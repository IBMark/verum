//! Line-based taint tracking from user-controlled sources (PHP superglobals,
//! Express request objects, Rust extractors) to dangerous sinks (SQL, HTML
//! output, command execution, filesystem paths).
//!
//! Two layers. Intra-procedural: taint state per function, sanitizers clear
//! taint on reassignment, direct source-to-sink on a line is Critical.
//! Inter-procedural: a fixpoint over function summaries - a function whose
//! `return` derives from a source taints its callers' assignments (re-scanned
//! until the tainted-return set stops growing, capped at 3 rounds), and a call
//! passing tainted data into a sink-bearing function is reported as a
//! cross-function flow at reduced confidence, with a structured [`TaintPath`].

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use regex::Regex;

use crate::scan::ScanContext;
use verum_nucleus::{
    matchable_path, Finding, FindingKind, Ir, Language, Severity, SymbolId, SymbolKind, TaintHop,
    TaintPath, TaintSink, TaintSource,
};

const PHP_SOURCES: &[&str] = &["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES"];
const JS_SOURCES: &[&str] = &["req.query", "req.params", "req.body"];
/// Rust: genuinely external input plus HTTP framework extractor markers.
/// Extractor bindings themselves (`Path(id): Path<...>`) are handled by
/// `RUST_EXTRACTOR_RE`, which taints the bound identifier.
///
/// `env::var`/`env::var_os` and `env::args` are deliberately NOT sources.
/// Environment variables are trusted build/deploy configuration, and in the
/// CLI-heavy Rust ecosystem a program's own argv is a path or subcommand it is
/// *meant* to act on - treating either as attacker input flagged every
/// `Command::new` reading `PATH` and every `File::open(arg)` as CRITICAL. Only
/// stdin, network reads, and HTTP request surfaces (extractors, query strings,
/// match info) remain, where the data genuinely crosses a trust boundary.
const RUST_SOURCES: &[&str] = &["io::stdin", "stdin()", ".query_string()", "req.match_info"];

const PHP_SANITIZERS: &[&str] = &[
    "intval(",
    "(int)",
    "(float)",
    "floatval(",
    "htmlspecialchars(",
    "htmlentities(",
    "escapeshellarg(",
    "escapeshellcmd(",
    "filter_var(",
    "addslashes(",
    "abs(",
];
const JS_SANITIZERS: &[&str] = &["parseInt(", "parseFloat(", "Number(", "encodeURIComponent("];
/// Rust: a typed parse is validation; canonicalize + escape helpers count too.
const RUST_SANITIZERS: &[&str] = &[
    ".parse::<",
    ".parse()",
    "canonicalize(",
    "sanitize",
    "escape(",
    "shell_escape",
];

// Raw-query entry points only. Parameterized ORM/driver methods (`->query(`,
// `.execute(`, `db.query(`) are almost always safe, and matched interprocedurally
// they reported "SQL injection" on essentially every controller that reaches the
// ORM - so they are deliberately excluded to avoid mass false positives.
const SQL_SINKS: &[&str] = &[
    "DB::raw(",
    "->raw(",
    "whereRaw(",
    "selectRaw(",
    "orderByRaw(",
    "havingRaw(",
    "mysql_query(",
    "mysqli_query(",
    "->unprepared(",
    // Rust: sqlx / diesel raw query entry points.
    "sqlx::query(",
    "sqlx::query_as(",
    "sql_query(",
];
const EXEC_SINKS: &[&str] = &[
    "eval(",
    "exec(",
    "shell_exec(",
    "system(",
    "passthru(",
    "popen(",
    "proc_open(",
    // Rust: process spawning.
    "Command::new(",
];
// PHP direct-output sinks. Express `res.send(`/`res.write(` were removed: they
// usually carry JSON, files, or generated content, so treating them as XSS sinks
// produced false positives (e.g. sending a generated schema as a file).
const HTML_SINKS: &[&str] = &["echo ", "echo(", "print ", "print("];
/// Filesystem path operations - tainted input here is `../` traversal.
const PATH_SINKS: &[&str] = &[
    "fs::read(",
    "fs::read_to_string(",
    "fs::write(",
    "fs::remove_file(",
    "fs::remove_dir_all(",
    "File::open(",
    "File::create(",
    "file_get_contents(",
    "file_put_contents(",
    "unlink(",
    "fs.readFile",
    "fs.writeFile",
    "fs.unlink",
];

/// Keywords and builtins that must not be treated as user-function callees.
const CALL_KEYWORDS: &[&str] = &[
    "if", "for", "foreach", "while", "switch", "return", "function", "catch", "match", "array",
    "isset", "empty", "unset", "echo", "print", "list", "fn", "new",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum SinkCat {
    Sql,
    Exec,
    Html,
    Path,
}

impl SinkCat {
    fn finding_kind(self) -> FindingKind {
        match self {
            SinkCat::Sql => FindingKind::SqlInjection,
            SinkCat::Exec => FindingKind::EvalUsage,
            SinkCat::Html => FindingKind::XssVulnerability,
            SinkCat::Path => FindingKind::PathTraversal,
        }
    }
    fn taint_sink(self) -> TaintSink {
        match self {
            SinkCat::Sql => TaintSink::SqlQuery,
            SinkCat::Exec => TaintSink::CommandExec,
            SinkCat::Html => TaintSink::HtmlOutput,
            SinkCat::Path => TaintSink::FileWrite,
        }
    }
    fn label(self) -> &'static str {
        match self {
            SinkCat::Sql => "SQL query",
            SinkCat::Exec => "command/code execution",
            SinkCat::Html => "HTML output",
            SinkCat::Path => "filesystem path operation",
        }
    }
}

struct Detection {
    cat: SinkCat,
    severity: Severity,
    confidence: f32,
    line: u32,
    desc: String,
    via: String,
}

/// Per-function facts gathered while scanning.
#[derive(Default)]
struct FnFact {
    returns_tainted: bool,
    sinks: Vec<(SinkCat, u32)>,
}

/// A call site passing tainted data into a user function.
struct TaintedArgCall {
    file: PathBuf,
    line: u32,
    callee: String,
    via: String,
    caller: Option<SymbolId>,
}

#[derive(Default)]
struct FileScan {
    detections: Vec<Detection>,
    tainted_arg_calls: Vec<TaintedArgCall>,
    /// (enclosing symbol, facts) - keyed later into the global map.
    facts: Vec<(SymbolId, FnFact)>,
}

/// Function spans of one file, for enclosing-symbol attribution.
struct SpanIndex {
    /// line number -> symbol of the smallest span containing it, precomputed
    /// so `enclosing` is O(1) instead of a scan over every span per query.
    by_line: Vec<Option<SymbolId>>,
}

impl SpanIndex {
    /// `line_count` is the file's length: the index is only ever queried for a
    /// line that exists, so a span reaching past the end encloses nothing and
    /// must not be allowed to size the table.
    fn build(ir: &Ir, ctx: &ScanContext, file: &Path, line_count: usize) -> Self {
        let mut spans: Vec<(SymbolId, u32, u32)> = ctx
            .symbols(file)
            .iter()
            .filter_map(|id| ir.symbols.get_key_value(id))
            .filter(|(_, s)| {
                matches!(
                    s.kind,
                    SymbolKind::Function | SymbolKind::Method | SymbolKind::StaticMethod
                )
            })
            .map(|(id, s)| (*id, s.line_start, s.line_end))
            .collect();
        spans.sort_by_key(|(_, start, end)| (*start, *end));

        // Fill line -> smallest enclosing span, walking spans in sorted order
        // and overwriting only on a STRICTLY smaller width: ties then keep the
        // earliest span, exactly reproducing the old min_by_key first-wins.
        let max_end = spans
            .iter()
            .map(|(_, _, end)| *end as usize)
            .max()
            .unwrap_or(0)
            .min(line_count);
        let mut by_line: Vec<Option<SymbolId>> = vec![None; max_end + 1];
        let mut width: Vec<u32> = vec![u32::MAX; max_end + 1];
        for (id, start, end) in &spans {
            // A symbol whose `line_end` precedes its `line_start` is malformed,
            // but it arrives from the IR rather than from this pass, so it gets
            // clamped rather than trusted - the plain subtraction underflowed.
            let w = end.saturating_sub(*start);
            for line in (*start as usize)..=(*end as usize).min(max_end) {
                if w < width[line] {
                    width[line] = w;
                    by_line[line] = Some(*id);
                }
            }
        }
        Self { by_line }
    }

    /// Smallest function span containing `line`.
    fn enclosing(&self, line: u32) -> Option<SymbolId> {
        self.by_line.get(line as usize).copied().flatten()
    }
}

pub fn analyse(ir: &Ir) -> Vec<Finding> {
    analyse_with_paths(ir).0
}

/// Full analysis: findings plus structured taint paths (used by `verum map`).
pub fn analyse_with_paths(ir: &Ir) -> (Vec<Finding>, Vec<TaintPath>) {
    analyse_with_context(ir, &ScanContext::index_only(ir))
}

/// As [`analyse_with_paths`], but taking each file's lines and symbols from a
/// context shared with the other line-scanning passes. Purely a performance
/// split: the context reproduces what this pass used to derive per file, so the
/// findings are identical either way.
pub fn analyse_with_context(ir: &Ir, ctx: &ScanContext) -> (Vec<Finding>, Vec<TaintPath>) {
    // Group 2 captures a compound-assignment operator (`.=`, `+=`) when
    // present; empty means plain `=`. `[^=]` still rejects `==`.
    let assign_re =
        Regex::new(r"^\s*(?:\$|let |const |var )?([A-Za-z_][A-Za-z0-9_]*)\s*([.+]?)=[^=]")
            .expect("valid regex");
    let call_re = Regex::new(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(").expect("valid regex");

    let mut files: Vec<(PathBuf, Language)> = ir
        .files
        .iter()
        .filter(|(_, info)| {
            matches!(
                info.language,
                Language::Php | Language::JavaScript | Language::TypeScript | Language::Rust
            )
        })
        .map(|(p, info)| (p.clone(), info.language.clone()))
        .collect();
    files.sort_by(|a, b| a.0.cmp(&b.0));

    // Per-file scan inputs, gathered once: lines and the function-span index.
    // The fixpoint below rescans from these rather than re-reading the file or
    // rebuilding the span index on every round.
    let mut contents: Vec<(PathBuf, ScanLang, Cow<'_, [String]>, SpanIndex)> = Vec::new();
    for (path, language) in &files {
        let path_str = matchable_path(path);
        if path_str.contains("vendor/")
            || path_str.contains("node_modules/")
            || path_str.contains("/target/")
        {
            continue;
        }
        // Rust build scripts, test harnesses, benches and examples are not
        // runtime attack surface - skip them as taint sink sites. Applied only
        // to Rust files; PHP/JS/TS taint behaviour is unchanged.
        if *language == Language::Rust && is_rust_non_runtime_path(path) {
            continue;
        }
        let Some(lines) = ctx.lines(path) else {
            continue;
        };
        let lang = match language {
            Language::Php => ScanLang::Php,
            Language::Rust => ScanLang::Rust,
            _ => ScanLang::Js,
        };
        let spans = SpanIndex::build(ir, ctx, path, lines.len());
        contents.push((path.clone(), lang, lines, spans));
    }

    // Fixpoint over tainted-return function names.
    let mut tainted_return_fns: HashSet<String> = HashSet::new();
    // One entry per `contents` entry, in the same order; the two are zipped
    // below rather than each carrying its own copy of the path.
    let mut scans: Vec<FileScan> = Vec::new();
    // Files whose scan panicked and was isolated; a BTreeSet so the resulting
    // diagnostics come out in path order regardless of which round tripped.
    let mut panicked: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();
    for round in 0..3 {
        scans.clear();
        let mut next_tainted: HashSet<String> = HashSet::new();
        for (path, lang, lines, spans) in &contents {
            // One hostile file must not panic the whole pass: scan under the
            // panic guard; a panicking file contributes an empty scan (and a
            // diagnostic finding below) while every other file proceeds.
            let scan = match verum_nucleus::panic_guard::catch(|| {
                scan_file(
                    path,
                    *lang,
                    lines,
                    spans,
                    &tainted_return_fns,
                    &assign_re,
                    &call_re,
                )
            }) {
                Some(scan) => scan,
                None => {
                    panicked.insert(path.clone());
                    FileScan::default()
                }
            };
            for (sym, fact) in &scan.facts {
                if fact.returns_tainted {
                    if let Some(s) = ir.symbols.get(sym) {
                        next_tainted.insert(s.name.clone());
                    }
                }
            }
            scans.push(scan);
        }
        let stable = next_tainted.is_subset(&tainted_return_fns);
        tainted_return_fns = next_tainted;
        if stable || round == 2 {
            break;
        }
    }

    // Global sink summaries: function name -> (symbol, sinks).
    let mut sink_fns: HashMap<String, (SymbolId, Vec<(SinkCat, u32)>)> = HashMap::new();
    {
        let mut ordered: Vec<(&SymbolId, &FnFact)> = scans
            .iter()
            .flat_map(|s| s.facts.iter().map(|(id, f)| (id, f)))
            .collect();
        ordered.sort_by_key(|(id, _)| id.0);
        for (id, fact) in ordered {
            if fact.sinks.is_empty() {
                continue;
            }
            if let Some(sym) = ir.symbols.get(id) {
                sink_fns
                    .entry(sym.name.clone())
                    .or_insert_with(|| (*id, fact.sinks.clone()));
            }
        }
    }

    let mut findings = Vec::new();
    let mut paths = Vec::new();

    // Direct (intra-procedural) detections.
    for ((path, _, _, spans), scan) in contents.iter().zip(&scans) {
        for d in &scan.detections {
            findings.push(Finding {
                id: format!(
                    "taint-{:?}-{}:{}",
                    d.cat.finding_kind(),
                    path.display(),
                    d.line
                ),
                kind: d.cat.finding_kind(),
                severity: d.severity.clone(),
                confidence: d.confidence,
                file: path.clone(),
                line_start: d.line,
                line_end: d.line,
                symbol: spans.enclosing(d.line),
                message: format!("Unsanitized user input reaches {} ({})", d.desc, d.via),
                suggestion: suggestion_for(d.cat),
                auto_fixable: false,
                related: Vec::new(),
            });
            paths.push(TaintPath {
                source: TaintSource::Unknown,
                hops: hop_for(ir, spans.enclosing(d.line), path, d.line),
                sink: d.cat.taint_sink(),
                sink_file: path.clone(),
                sink_line: d.line,
                sanitized: false,
                sanitizer: None,
            });
        }
    }

    // Cross-function flows: tainted argument into a sink-bearing function.
    // Callees are resolved by name, so a common method name (sort, set, count,
    // get, ...) can collide with an unrelated same-named function that happens to
    // contain a sink. Count definitions per name so ambiguous ones can be skipped.
    let mut name_counts: HashMap<&str, usize> = HashMap::new();
    for s in ir.symbols.values() {
        if matches!(
            s.kind,
            SymbolKind::Function | SymbolKind::Method | SymbolKind::StaticMethod
        ) {
            *name_counts.entry(s.name.as_str()).or_default() += 1;
        }
    }
    let mut seen_cross: HashSet<(PathBuf, u32, String)> = HashSet::new();
    for scan in &scans {
        for call in &scan.tainted_arg_calls {
            let Some((callee_id, sinks)) = sink_fns.get(&call.callee) else {
                continue;
            };
            // Ambiguous callee: several functions share this name, so we cannot
            // say the tainted call reaches this particular sink-bearing one.
            if name_counts.get(call.callee.as_str()).copied().unwrap_or(0) > 1 {
                continue;
            }
            // Same-line direct sinks are already reported above.
            if !seen_cross.insert((call.file.clone(), call.line, call.callee.clone())) {
                continue;
            }
            let Some(callee_sym) = ir.symbols.get(callee_id) else {
                continue;
            };
            let (cat, sink_line) = sinks[0];
            let mut related = vec![verum_nucleus::Location {
                file: callee_sym.file.clone(),
                line: callee_sym.line_start,
                description: format!("`{}` defined here", callee_sym.name),
            }];
            related.push(verum_nucleus::Location {
                file: callee_sym.file.clone(),
                line: sink_line,
                description: format!("{} sink inside `{}`", cat.label(), callee_sym.name),
            });
            findings.push(Finding {
                id: format!(
                    "taint-cross-{}-{}:{}",
                    call.callee,
                    call.file.display(),
                    call.line
                ),
                kind: cat.finding_kind(),
                severity: Severity::High,
                confidence: 0.60,
                file: call.file.clone(),
                line_start: call.line,
                line_end: call.line,
                symbol: call.caller,
                message: format!(
                    "Tainted data passed to `{}()`, which contains a {} sink ({})",
                    call.callee,
                    cat.label(),
                    call.via
                ),
                suggestion: format!(
                    "Sanitize the argument before calling `{}()`, or make `{}()` use \
                     parameter binding internally",
                    call.callee, call.callee
                ),
                auto_fixable: false,
                related,
            });

            let mut hops = hop_for(ir, call.caller, &call.file, call.line);
            hops.push(TaintHop {
                symbol: *callee_id,
                file: callee_sym.file.clone(),
                line: callee_sym.line_start,
                transforms: vec![format!("argument into {}()", callee_sym.name)],
            });
            paths.push(TaintPath {
                source: TaintSource::Unknown,
                hops,
                sink: cat.taint_sink(),
                sink_file: callee_sym.file.clone(),
                sink_line,
                sanitized: false,
                sanitizer: None,
            });
        }
    }

    // One diagnostic per isolated file, in path order (the set deduplicates
    // across fixpoint rounds).
    for path in &panicked {
        findings.push(Finding::parse_failure(
            path,
            "analysis panicked on this file",
        ));
    }

    (findings, paths)
}

/// True for Rust source that is developer-controlled rather than runtime
/// attack surface: build scripts (`build.rs`), test files (`*_test.rs`,
/// `*_tests.rs`, anything under `tests/`), benchmarks (`benches/`) and
/// examples (`examples/`). Input reaching a sink in these locations is not a
/// vulnerability, so they are excluded from taint sink reporting. Only ever
/// consulted for Rust-language files.
fn is_rust_non_runtime_path(path: &Path) -> bool {
    let s = matchable_path(path);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    name == "build.rs"
        || name.ends_with("_test.rs")
        || name.ends_with("_tests.rs")
        || s.contains("/tests/")
        || s.contains("/benches/")
        || s.contains("/examples/")
}

fn hop_for(ir: &Ir, sym: Option<SymbolId>, file: &Path, line: u32) -> Vec<TaintHop> {
    match sym.and_then(|id| ir.symbols.get(&id).map(|s| (id, s))) {
        Some((id, s)) => vec![TaintHop {
            symbol: id,
            file: s.file.clone(),
            line,
            transforms: vec![format!("in {}", s.name)],
        }],
        None => vec![TaintHop {
            symbol: SymbolId(0),
            file: file.to_path_buf(),
            line,
            transforms: vec!["file scope".to_string()],
        }],
    }
}

fn suggestion_for(cat: SinkCat) -> String {
    match cat {
        SinkCat::Sql => {
            "Use prepared statements / parameter binding instead of interpolating input".to_string()
        }
        SinkCat::Html => "Escape output with htmlspecialchars() or a templating engine".to_string(),
        SinkCat::Exec => {
            "Never pass user input to execution sinks; validate against an allowlist".to_string()
        }
        SinkCat::Path => "Canonicalize the path and verify it stays under the intended root \
             before touching the filesystem"
            .to_string(),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScanLang {
    Php,
    Js,
    Rust,
}

/// HTTP-framework extractor bindings that taint an identifier directly:
/// axum `Path(id): Path<u64>` / `Query(params)` / `Json(body)` in a handler
/// signature, actix `web::Path(id)`.
static RUST_EXTRACTOR_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
/// Reads that fill a caller-provided buffer: `sock.recv_from(&mut buf)`,
/// `stream.read_exact(&mut buf)` - the tainted value is the buffer.
static RUST_READ_INTO_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();

#[allow(clippy::too_many_arguments)]
fn scan_file(
    path: &Path,
    lang: ScanLang,
    lines: &[String],
    spans: &SpanIndex,
    tainted_return_fns: &HashSet<String>,
    assign_re: &Regex,
    call_re: &Regex,
) -> FileScan {
    let is_php = lang == ScanLang::Php;
    let (sources, sanitizers) = match lang {
        ScanLang::Php => (PHP_SOURCES, PHP_SANITIZERS),
        ScanLang::Js => (JS_SOURCES, JS_SANITIZERS),
        ScanLang::Rust => (RUST_SOURCES, RUST_SANITIZERS),
    };
    let rust_extractor = RUST_EXTRACTOR_RE.get_or_init(|| {
        Regex::new(r"(?:Path|Query|Json|Form)\(\s*(?:mut\s+)?([a-z_][a-z0-9_]*)\s*\)\s*:")
            .expect("valid regex")
    });
    let rust_read_into = RUST_READ_INTO_RE.get_or_init(|| {
        Regex::new(r"\.(?:recv|recv_from|read|read_exact|read_to_end|read_to_string|read_line)\(\s*&mut\s+([a-z_][a-z0-9_]*)")
            .expect("valid regex")
    });

    let mut tainted: HashSet<String> = HashSet::new();
    let mut detections: Vec<Detection> = Vec::new();
    let mut tainted_arg_calls: Vec<TaintedArgCall> = Vec::new();
    let mut facts: HashMap<SymbolId, FnFact> = HashMap::new();

    for (idx, line) in lines.iter().enumerate() {
        let line_num = (idx + 1) as u32;
        // Overlong lines are generated blobs, and the tainted-variable check
        // below rescans every tracked name against the line - skip them
        // (deterministic input-size guard, see `scan::MAX_SCAN_LINE_BYTES`).
        if line.len() > crate::scan::MAX_SCAN_LINE_BYTES {
            continue;
        }
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with('#') {
            continue;
        }

        // Taint state is per-function: reset at declarations.
        if trimmed.contains("function ")
            || trimmed.starts_with("def ")
            || (lang == ScanLang::Rust
                && (trimmed.starts_with("fn ")
                    || trimmed.starts_with("pub fn ")
                    || trimmed.contains("async fn ")))
        {
            tainted.clear();
        }

        let enclosing = spans.enclosing(line_num);

        if lang == ScanLang::Rust {
            for caps in rust_extractor.captures_iter(line) {
                track_tainted(&mut tainted, caps[1].to_string());
            }
            for caps in rust_read_into.captures_iter(line) {
                track_tainted(&mut tainted, caps[1].to_string());
            }
        }

        let has_sanitizer = sanitizers.iter().any(|s| line.contains(s));
        let direct_source = sources.iter().any(|s| line.contains(s));
        let tainted_var_used: Option<String> = tainted
            .iter()
            .find(|v| contains_var(line, v, is_php))
            .cloned();

        let sink_hit = |sinks: &[&str]| sinks.iter().any(|s| line.contains(s));
        // Rust SQL is parameterized by default: `sqlx::query("... $1 ...").bind(v)`
        // is safe regardless of what binds, and `.execute()`/`.fetch_*()` run a
        // prepared statement. The *only* injectable Rust SQL is a query whose
        // TEXT is built dynamically - `sqlx::query(&format!(...))`. So for Rust,
        // require a query call with `format!` in its argument; the PHP/JS raw
        // string sinks keep their existing behavior.
        let sql_sink = if lang == ScanLang::Rust {
            (line.contains("sqlx::query")
                || line.contains("sql_query")
                || line.contains("query_as"))
                && line.contains("format!")
        } else {
            sink_hit(SQL_SINKS)
        };
        let sink_cat = if sql_sink {
            Some(SinkCat::Sql)
        } else if sink_hit(EXEC_SINKS) {
            Some(SinkCat::Exec)
        } else if sink_hit(HTML_SINKS) && lang != ScanLang::Rust {
            // `print`/`echo` shapes are PHP/JS output; Rust println is not an
            // HTML sink.
            Some(SinkCat::Html)
        } else if sink_hit(PATH_SINKS) {
            Some(SinkCat::Path)
        } else {
            None
        };

        // Record sink presence per function regardless of taint - this is the
        // summary the inter-procedural layer consumes.
        if let (Some(cat), Some(sym)) = (sink_cat, enclosing) {
            facts.entry(sym).or_default().sinks.push((cat, line_num));
        }

        let flow_via = if direct_source {
            Some(("user input used directly".to_string(), 0.90))
        } else {
            tainted_var_used.as_ref().map(|v| {
                (
                    format!(
                        "via tainted variable `{}{}`",
                        if is_php { "$" } else { "" },
                        v
                    ),
                    0.80,
                )
            })
        };

        if let Some((via, conf)) = &flow_via {
            if let Some(cat) = sink_cat {
                if !has_sanitizer {
                    detections.push(Detection {
                        cat,
                        severity: if matches!(cat, SinkCat::Html | SinkCat::Path) {
                            Severity::High
                        } else {
                            Severity::Critical
                        },
                        confidence: if cat == SinkCat::Html {
                            conf - 0.05
                        } else {
                            *conf
                        },
                        line: line_num,
                        desc: cat.label().to_string(),
                        via: via.clone(),
                    });
                }
            } else if is_sql_concat(line, direct_source, tainted_var_used.as_deref(), is_php)
                && !has_sanitizer
            {
                detections.push(Detection {
                    cat: SinkCat::Sql,
                    severity: Severity::Critical,
                    confidence: conf - 0.05,
                    line: line_num,
                    desc: "SQL string concatenation".to_string(),
                    via: via.clone(),
                });
            }

            // Returning tainted data taints this function's callers.
            if (trimmed.starts_with("return ") || trimmed.starts_with("return$")) && !has_sanitizer
            {
                if let Some(sym) = enclosing {
                    facts.entry(sym).or_default().returns_tainted = true;
                }
            }

            // Tainted argument into a user-function call.
            if sink_cat.is_none() && !has_sanitizer {
                for caps in call_re.captures_iter(line) {
                    let callee = &caps[1];
                    if CALL_KEYWORDS.contains(&callee) {
                        continue;
                    }
                    // A declaration is not a call site: `fn get_file(Path(name)...)`
                    // must not read as passing tainted data into itself.
                    let before = line[..caps.get(1).unwrap().start()].trim_end();
                    if before.ends_with("fn")
                        || before.ends_with("function")
                        || before.ends_with("def")
                    {
                        continue;
                    }
                    let call_start = caps.get(0).unwrap().end();
                    let args = &line[call_start.min(line.len())..];
                    let arg_tainted = sources.iter().any(|s| args.contains(s))
                        || tainted_var_used
                            .as_deref()
                            .map(|v| contains_var(args, v, is_php))
                            .unwrap_or(false);
                    if arg_tainted {
                        tainted_arg_calls.push(TaintedArgCall {
                            file: path.to_path_buf(),
                            line: line_num,
                            callee: callee.to_string(),
                            via: via.clone(),
                            caller: enclosing,
                        });
                    }
                }
            }
        }

        // Assignment tracking runs after the sink checks so a line that both
        // uses and reassigns a variable is judged on its pre-assignment state.
        if let Some(caps) = assign_re.captures(line) {
            let var = caps[1].to_string();
            // Compound assignments (`$q .= ...`, `$n += ...`) append to the target:
            // a tainted RHS taints it, but a clean/sanitized RHS must never
            // clear taint the target already carries.
            let is_compound = !caps[2].is_empty();
            let after_eq = line.split_once('=').map(|(_, r)| r).unwrap_or("");
            let from_tainted_return = tainted_return_fns
                .iter()
                .any(|f| contains_at_word_start(after_eq, &format!("{}(", f)));
            if (direct_source || from_tainted_return) && !has_sanitizer {
                track_tainted(&mut tainted, var);
            } else if !is_compound
                && (has_sanitizer || (!direct_source && tainted_var_used.is_none()))
            {
                // Sanitized or clean plain reassignment clears taint.
                tainted.remove(&var);
            } else if tainted_var_used.is_some() && !has_sanitizer {
                // Propagation: $b = $a . "x" where $a is tainted.
                track_tainted(&mut tainted, var);
            }
        }
    }

    FileScan {
        detections,
        tainted_arg_calls,
        facts: facts.into_iter().collect(),
    }
}

/// Cap on tainted variable names tracked per file.
///
/// Every scanned line is checked against every tracked name, so tracked state
/// growing without bound on generated code (tens of thousands of variables
/// assigned from a source) turns the scan quadratic. Real code tracks a
/// handful of names per function. The cap is a fixed constant applied in
/// line order - first-seen names win - so it depends only on the input and
/// identical inputs always track the identical set.
const MAX_TRACKED_TAINTED_VARS: usize = 512;

/// Insert `var` into the tracked set unless the fixed cap is reached
/// (re-inserting an already-tracked name is always allowed).
fn track_tainted(tainted: &mut HashSet<String>, var: String) {
    if tainted.len() < MAX_TRACKED_TAINTED_VARS || tainted.contains(&var) {
        tainted.insert(var);
    }
}

/// True when `pattern` occurs in `text` at a word start.
fn contains_at_word_start(text: &str, pattern: &str) -> bool {
    let mut from = 0;
    while let Some(pos) = text[from..].find(pattern) {
        let abs = from + pos;
        let prev = text[..abs].chars().next_back();
        let is_word_char = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$';
        if prev.is_none_or(|c| !is_word_char(c)) {
            return true;
        }
        from = abs + pattern.len();
    }
    false
}

/// Whether `text` uses variable `var` (with `$` sigil for PHP) at a word boundary.
fn contains_var(text: &str, var: &str, is_php: bool) -> bool {
    let needle = if is_php {
        format!("${}", var)
    } else {
        var.to_string()
    };
    let mut from = 0;
    while let Some(pos) = text[from..].find(&needle) {
        let abs = from + pos;
        let end = abs + needle.len();
        let prev_ok = if is_php {
            true
        } else {
            text[..abs]
                .chars()
                .next_back()
                .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '.')
        };
        let next_ok = text[end..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_');
        if prev_ok && next_ok {
            return true;
        }
        from = end;
    }
    false
}

/// A quoted SQL keyword concatenated with tainted data:
/// `"SELECT * FROM users WHERE id = " . $id`
fn is_sql_concat(line: &str, direct_source: bool, tainted_var: Option<&str>, is_php: bool) -> bool {
    let upper = line.to_ascii_uppercase();
    let has_sql_keyword = ["SELECT ", "INSERT ", "UPDATE ", "DELETE FROM", "WHERE "]
        .iter()
        .any(|k| upper.contains(k));
    if !has_sql_keyword {
        return false;
    }
    let concat =
        line.contains(". $") || line.contains(".$") || line.contains("+ ") || line.contains("${");
    concat && (direct_source || tainted_var.is_some_and(|v| contains_var(line, v, is_php)))
}

/// Human-readable label for a taint sink kind.
pub fn sink_label(kind: &TaintSink) -> &'static str {
    match kind {
        TaintSink::SqlQuery => "SQL query",
        TaintSink::CommandExec | TaintSink::EvalExec => "command execution",
        TaintSink::HtmlOutput => "HTML output",
        TaintSink::HttpHeader => "HTTP header",
        TaintSink::FileInclude => "file include",
        TaintSink::FileWrite => "file write",
        TaintSink::ExternalRequest => "external request",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_var_at_word_boundary() {
        assert!(contains_var("echo $id;", "id", true));
        assert!(!contains_var("echo $identifier;", "id", true));
        assert!(contains_var("send(id)", "id", false));
        assert!(!contains_var("send(idx)", "id", false));
    }

    #[test]
    fn tainted_var_tracking_is_capped_and_deterministic() {
        let mut tainted = HashSet::new();
        for i in 0..(MAX_TRACKED_TAINTED_VARS + 100) {
            track_tainted(&mut tainted, format!("v{i}"));
        }
        assert_eq!(
            tainted.len(),
            MAX_TRACKED_TAINTED_VARS,
            "first-seen names win; growth stops at the fixed cap"
        );
        // Names admitted before the cap stay re-insertable at the cap.
        assert!(tainted.contains("v0"));
        track_tainted(&mut tainted, "v0".to_string());
        assert_eq!(tainted.len(), MAX_TRACKED_TAINTED_VARS);
        // A name first seen past the cap is not tracked.
        assert!(!tainted.contains(&format!("v{MAX_TRACKED_TAINTED_VARS}")));
    }

    #[test]
    fn detects_sql_concat() {
        assert!(is_sql_concat(
            r#"$r = DB::select("SELECT * FROM users WHERE id = " . $id);"#,
            false,
            Some("id"),
            true
        ));
        assert!(!is_sql_concat(
            r#"$r = "SELECT * FROM users";"#,
            false,
            None,
            true
        ));
    }
}
