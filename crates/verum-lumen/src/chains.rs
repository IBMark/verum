//! Daisychain analysis: multi-hop paths through the call graph from entry
//! points to dangerous sinks.
//!
//! Resolved call edges are kept as-is; unambiguous names are mapped back to
//! symbols to complete the graph. From each entry point (route controllers,
//! framework entry symbols) we walk looking for chains that reach a dangerous
//! sink (deletion, exec/eval, raw SQL, filesystem, SSRF) without an
//! auth/validation gate on the path, or that cross a trust boundary (a
//! client/public entry into admin/daemon code). Unsanitized taint paths are
//! lifted into the same chain view.
//!
//! Findings are `DangerousChain` and informational by design - a mapping aid,
//! not a score penalty - with severity reflecting how exploitable the chain
//! looks.

use std::collections::{HashMap, HashSet, VecDeque};

use verum_nucleus::{
    matchable_path, Finding, FindingKind, Ir, Language, Location, Severity, SymbolId, TaintSink,
    TaintSource,
};

/// Maximum hops to walk from an entry point before giving up.
const MAX_DEPTH: usize = 6;
/// Hard cap on emitted chain findings to keep output bounded.
const MAX_CHAINS: usize = 300;

/// Category of a dangerous sink reached at the end of a chain.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SinkKind {
    Deletion,
    Exec,
    Sql,
    FileSystem,
    Ssrf,
}

impl SinkKind {
    fn label(self) -> &'static str {
        match self {
            SinkKind::Deletion => "destructive operation",
            SinkKind::Exec => "command/code execution",
            SinkKind::Sql => "raw SQL",
            SinkKind::FileSystem => "filesystem access",
            SinkKind::Ssrf => "outbound request",
        }
    }

    /// Base severity when the chain is NOT gated by auth/validation.
    fn ungated_severity(self) -> Severity {
        match self {
            SinkKind::Exec => Severity::Critical,
            SinkKind::Sql | SinkKind::Deletion => Severity::High,
            SinkKind::FileSystem | SinkKind::Ssrf => Severity::Medium,
        }
    }
}

/// Trust tier of a symbol, derived from its path / fully-qualified name. Used to
/// detect privilege hops where a lower-trust entry reaches higher-trust code.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Tier {
    Public = 0,
    Client = 1,
    Application = 2,
    Admin = 3,
    Daemon = 4,
}

pub fn analyse(ir: &Ir) -> Vec<Finding> {
    let mut findings = Vec::new();

    let index = build_name_index(ir);
    let adjacency = build_adjacency(ir, &index);

    // Trust tiers depend only on the symbol's fq/file, so compute each once up
    // front instead of re-deriving (format! + lowercase) per BFS edge visit.
    let tiers: HashMap<SymbolId, Tier> = ir
        .symbols
        .iter()
        .map(|(id, sym)| {
            (
                *id,
                tier_of(&sym.fully_qualified, &matchable_path(&sym.file)),
            )
        })
        .collect();

    // Map a controller symbol -> route middleware, so a chain rooted at a route
    // inherits the route's auth gate (middleware like `auth`, `admin`, ...).
    let mut route_gate: HashMap<SymbolId, bool> = HashMap::new();
    for route in &ir.routes {
        if let Some(c) = route.controller {
            let gated = route.middleware.iter().any(|m| middleware_is_gate(m));
            route_gate
                .entry(c)
                .and_modify(|g| *g |= gated)
                .or_insert(gated);
        }
    }

    let mut entries: Vec<SymbolId> = ir.routes.iter().filter_map(|r| r.controller).collect();
    for id in &ir.entry_points {
        entries.push(*id);
    }
    for (id, sym) in &ir.symbols {
        if sym.is_entry_point {
            entries.push(*id);
        }
    }
    entries.sort_by_key(|s| s.0);
    entries.dedup();
    // Tests, migrations and file-level pseudo-symbols are not attack surface.
    entries.retain(|id| ir.symbols.get(id).is_some_and(is_real_entry));

    // Dedup chains by (entry, sink category, sink name).
    let mut seen: HashSet<(u64, u8, String)> = HashSet::new();

    for entry in entries {
        if findings.len() >= MAX_CHAINS {
            break;
        }
        walk_entry(
            ir,
            &adjacency,
            &tiers,
            entry,
            &route_gate,
            &mut seen,
            &mut findings,
        );
    }

    findings.extend(taint_chains(ir));

    findings.truncate(MAX_CHAINS);
    findings
}

/// BFS from a single entry point, emitting chains as sinks are encountered.
fn walk_entry(
    ir: &Ir,
    adjacency: &HashMap<SymbolId, Vec<Edge>>,
    tiers: &HashMap<SymbolId, Tier>,
    entry: SymbolId,
    route_gate: &HashMap<SymbolId, bool>,
    seen: &mut HashSet<(u64, u8, String)>,
    findings: &mut Vec<Finding>,
) {
    let entry_sym = match ir.symbols.get(&entry) {
        Some(s) => s,
        None => return,
    };
    let entry_tier = *tiers.get(&entry).unwrap_or(&Tier::Public);
    let entry_gated = *route_gate.get(&entry).unwrap_or(&false);

    // Each queue item carries the path of symbols and whether a gate was seen.
    struct State {
        node: SymbolId,
        path: Vec<SymbolId>,
        gated: bool,
        crossed_to: Option<Tier>,
    }

    let mut queue: VecDeque<State> = VecDeque::new();
    let mut visited: HashSet<u64> = HashSet::new();
    visited.insert(entry.0);
    queue.push_back(State {
        node: entry,
        path: vec![entry],
        gated: entry_gated,
        crossed_to: None,
    });

    while let Some(state) = queue.pop_front() {
        if findings.len() >= MAX_CHAINS {
            return;
        }
        let edges = match adjacency.get(&state.node) {
            Some(e) => e,
            None => continue,
        };

        for edge in edges {
            // Inspect the callee name for sinks / gates regardless of resolution.
            // Classification depends only on (name, lang), so it was computed once
            // per edge in build_adjacency instead of per BFS visit.
            if let Some(sink) = edge.sink {
                let key = (entry.0, sink as u8, edge.name.clone());
                if seen.insert(key) {
                    if let Some(f) = make_chain_finding(
                        ir,
                        entry_sym,
                        entry_tier,
                        &state.path,
                        edge,
                        sink,
                        state.gated,
                        state.crossed_to,
                    ) {
                        findings.push(f);
                    }
                }
                // Don't traverse into sinks; they're leaves for this purpose.
                continue;
            }

            let now_gated = state.gated || edge.is_gate;

            if let Some(callee) = edge.callee {
                if state.path.len() >= MAX_DEPTH || !visited.insert(callee.0) {
                    continue;
                }
                let mut path = state.path.clone();
                path.push(callee);

                let mut crossed = state.crossed_to;
                if let Some(&t) = tiers.get(&callee) {
                    if t > entry_tier {
                        crossed = Some(crossed.map_or(t, |c| c.max(t)));
                    }
                }

                queue.push_back(State {
                    node: callee,
                    path,
                    gated: now_gated,
                    crossed_to: crossed,
                });
            }
        }
    }
}

/// Build a finding for one discovered chain.
#[allow(clippy::too_many_arguments)]
fn make_chain_finding(
    ir: &Ir,
    entry_sym: &verum_nucleus::Symbol,
    entry_tier: Tier,
    path: &[SymbolId],
    sink_edge: &Edge,
    sink: SinkKind,
    gated: bool,
    crossed_to: Option<Tier>,
) -> Option<Finding> {
    // Render the chain as "Entry -> Mid -> ... -> sink()".
    let mut names: Vec<String> = path
        .iter()
        .filter_map(|id| ir.symbols.get(id))
        .map(|s| short(&s.name, &s.fully_qualified))
        .collect();
    names.push(format!("{}()", short(&sink_edge.name, &sink_edge.name)));
    let rendered = names.join(" -> ");

    let privilege_hop = crossed_to.is_some_and(|t| t > entry_tier);

    // Severity: ungated dangerous sinks are the headline; gated ones are surfaced
    // at low severity; a privilege hop bumps one level.
    let mut severity = if gated {
        Severity::Low
    } else {
        sink.ungated_severity()
    };
    if privilege_hop {
        severity = bump(severity);
    }

    let mut tags = Vec::new();
    if !gated {
        tags.push("no auth/validation gate".to_string());
    }
    if privilege_hop {
        tags.push("crosses trust boundary".to_string());
    }
    let tag_str = if tags.is_empty() {
        "gated".to_string()
    } else {
        tags.join(", ")
    };

    let related: Vec<Location> = path
        .iter()
        .filter_map(|id| ir.symbols.get(id))
        .map(|s| Location {
            file: s.file.clone(),
            line: s.line_start,
            description: short(&s.name, &s.fully_qualified),
        })
        .collect();

    Some(Finding {
        fingerprint: String::new(),
        id: format!("chain-{}-{}", entry_sym.id.0, sink_edge.name),
        kind: FindingKind::DangerousChain,
        severity,
        confidence: if gated { 0.4 } else { 0.65 },
        file: entry_sym.file.clone(),
        line_start: entry_sym.line_start,
        line_end: entry_sym.line_start,
        symbol: Some(entry_sym.id),
        message: format!("Daisychain to {} ({}): {}", sink.label(), tag_str, rendered),
        suggestion: if gated {
            "Reachable but gated - confirm the gate covers this path.".to_string()
        } else {
            "Add an authorization/validation gate between the entry point and this sink."
                .to_string()
        },
        auto_fixable: false,
        related,
    })
}

/// Lift unsanitized taint paths (user input -> sink) into chain findings.
fn taint_chains(ir: &Ir) -> Vec<Finding> {
    let mut out = Vec::new();
    for (i, tp) in ir.taint_paths.iter().enumerate() {
        if tp.sanitized {
            continue;
        }
        let mut hops: Vec<String> = vec![source_label(&tp.source)];
        for hop in &tp.hops {
            if let Some(sym) = ir.symbols.get(&hop.symbol) {
                hops.push(short(&sym.name, &sym.fully_qualified));
            }
        }
        hops.push(sink_label(&tp.sink).to_string());
        out.push(Finding {
            fingerprint: String::new(),
            id: format!("chain-taint-{}", i),
            kind: FindingKind::DangerousChain,
            severity: taint_sink_severity(&tp.sink),
            confidence: 0.7,
            file: tp.sink_file.clone(),
            line_start: tp.sink_line,
            line_end: tp.sink_line,
            symbol: None,
            message: format!("Tainted daisychain (unsanitized): {}", hops.join(" -> ")),
            suggestion: "Validate/sanitize the input before it reaches this sink.".to_string(),
            auto_fixable: false,
            related: tp
                .hops
                .iter()
                .map(|h| Location {
                    file: h.file.clone(),
                    line: h.line,
                    description: h.transforms.join(", "),
                })
                .collect(),
        });
    }
    out
}

struct Edge {
    callee: Option<SymbolId>,
    name: String,
    /// Sink classification of `name` in the call site's language, precomputed
    /// at build time. The sink must be classified by where it's actually called
    /// (`beamStore.delete` in a JS dashboard is a Map op), not by the entry
    /// point's language, since a chain can cross languages via name matching.
    sink: Option<SinkKind>,
    /// Whether `name` looks like an auth/validation gate, precomputed likewise.
    is_gate: bool,
}

/// Index symbols by normalized short name and by fully-qualified name.
fn build_name_index(ir: &Ir) -> HashMap<String, Vec<SymbolId>> {
    let mut index: HashMap<String, Vec<SymbolId>> = HashMap::new();
    for (id, sym) in &ir.symbols {
        index.entry(normalize(&sym.name)).or_default().push(*id);
        let fq = normalize(&sym.fully_qualified);
        if fq != normalize(&sym.name) {
            index.entry(fq).or_default().push(*id);
        }
    }
    index
}

fn build_adjacency(
    ir: &Ir,
    index: &HashMap<String, Vec<SymbolId>>,
) -> HashMap<SymbolId, Vec<Edge>> {
    let mut adj: HashMap<SymbolId, Vec<Edge>> = HashMap::new();
    for call in &ir.calls {
        use verum_nucleus::CallTarget::*;
        // Resolved edges keep their id and use the target's name for sink/gate
        // classification.
        let (callee, name) = match &call.callee {
            Resolved(id) => {
                let name = ir
                    .symbols
                    .get(id)
                    .map(|s| s.name.clone())
                    .unwrap_or_default();
                (Some(*id), name)
            }
            Unresolved(s) | Dynamic(s) | Magic(s) => (resolve(s, index), s.clone()),
        };
        if name.is_empty() {
            continue;
        }
        // Prefer the resolved callee's own language; else the call-site file's;
        // else the caller's (the call lives in the caller's file).
        let lang = callee
            .and_then(|id| ir.symbols.get(&id))
            .map(|s| s.language.clone())
            .or_else(|| ir.files.get(&call.file).map(|f| f.language.clone()))
            .or_else(|| ir.symbols.get(&call.caller).map(|s| s.language.clone()))
            .unwrap_or_default();
        // Sink/gate classification depends only on (name, lang); doing it here
        // once per edge keeps the BFS from re-lowercasing the same name on
        // every visit (this pair dominated the pass's profile).
        let sink = classify_sink(&name, &lang);
        let is_gate = name_is_gate(&name);
        adj.entry(call.caller).or_default().push(Edge {
            callee,
            name,
            sink,
            is_gate,
        });
    }
    adj
}

/// Resolve a callee name to a single symbol if it is unambiguous. Ambiguous
/// names stay unresolved for traversal - the name is still used for sink/gate
/// classification.
fn resolve(name: &str, index: &HashMap<String, Vec<SymbolId>>) -> Option<SymbolId> {
    let key = normalize(last_segment(name));
    match index.get(&key) {
        Some(ids) if ids.len() == 1 => Some(ids[0]),
        _ => None,
    }
}

fn last_segment(name: &str) -> &str {
    let n = name.rsplit(['\\', '/']).next().unwrap_or(name);
    let n = n.rsplit("::").next().unwrap_or(n);
    let n = n.rsplit("->").next().unwrap_or(n);
    n.rsplit('.').next().unwrap_or(n)
}

fn normalize(s: &str) -> String {
    s.trim_matches(|c| c == '\\' || c == '(' || c == ')')
        .to_ascii_lowercase()
}

/// A meaningful entry point: not test/migration/seed code, not a file-level
/// pseudo-symbol.
fn is_real_entry(s: &verum_nucleus::Symbol) -> bool {
    use verum_nucleus::SymbolKind::*;
    if !matches!(s.kind, Method | Function | StaticMethod | Class) {
        return false;
    }
    if is_test_path(&matchable_path(&s.file)) {
        return false;
    }
    let n = s.name.to_ascii_lowercase();
    n.len() > 2 && n != "php" && !n.starts_with("test")
}

fn is_test_path(p: &str) -> bool {
    let p = p.to_ascii_lowercase();
    p.contains("/tests/")
        || p.contains("/test/")
        || p.contains("/database/migrations/")
        || p.contains("/database/seeders/")
        || p.ends_with("test.php")
}

/// Public sink classification for `verum map`: the category label a callee
/// name falls into, if it is a dangerous sink.
pub fn sink_category(name: &str) -> Option<&'static str> {
    // Permissive default (full PHP catalog) - this is a labelling aid for
    // `verum map` and callers expect the widest recall.
    classify_sink(name, &Language::Php).map(|s| s.label())
}

/// Qualified receivers that are in-memory std containers - a `truncate`,
/// `clear` or `remove` on these is routine data structure work, never a
/// destructive storage operation. Receiver-type inference in atlas emits
/// method calls on typed locals/fields as `Type::method`, which is what these
/// prefixes match.
const BENIGN_RECEIVERS: &[&str] = &[
    "vec::",
    "string::",
    "vecdeque::",
    "hashmap::",
    "btreemap::",
    "hashset::",
    "btreeset::",
    "binaryheap::",
    "bytesmut::",
    "bytes::",
    "pathbuf::",
    "osstring::",
];

/// Deletion verbs that are destructive only in a storage context. When the
/// receiver is unknown (`x.truncate` - Rust dotted call the type inference
/// couldn't bind), require a storage-suggesting receiver token; `truncate` on
/// some local buffer must not read as data loss.
// `truncate` is intentionally absent: in Rust it's `OpenOptions::truncate`,
// `Vec/String::truncate`, or `File` truncation - never a DB destroy. PHP's
// `->truncate()` keeps its recall through the DEL name catalog.
const AMBIGUOUS_DEL: &[&str] = &["delete", "destroy", "purge", "purgeexpired"];

const STORAGE_HINTS: &[&str] = &[
    "file",
    "fs",
    "db",
    "sql",
    "conn",
    "client",
    "store",
    "repo",
    "bucket",
    "disk",
    "storage",
    "table",
    "model",
    "record",
    "cache",
    "session",
    "collection",
    "dao",
    "registry",
    "queue",
    "index",
    "cursor",
];

/// True when a dotted call's receiver carries a storage hint (`self.db.delete`,
/// `cursor.execute`). PHP arrow calls (`->`) are excluded - their idioms keep
/// their recall through the PHP name catalogs instead.
fn storage_receiver(n: &str) -> bool {
    n.contains('.')
        && !n.contains("->")
        && n.rsplit_once('.')
            .map(|(r, _)| STORAGE_HINTS.iter().any(|h| r.contains(h)))
            .unwrap_or(false)
}

/// Python-only sinks whose names are too generic to catalog bare. Every entry
/// is receiver-gated, in the same spirit as `AMBIGUOUS_DEL`: `execute` is a
/// SQL sink only on a storage-hinted receiver (`cursor.execute`,
/// `conn.executemany` - never `executor.execute` from a thread pool), the
/// HTTP verbs only when the receiver IS a client module (`requests.get` -
/// never `self.client.get`, which is as often gRPC or a fake), and the
/// `subprocess`/`os`/`shutil` families only on their module receiver.
/// Precision over recall throughout: a bare `run(` or `get(` is ubiquitous
/// and never classified. Returning `None` falls back to the shared
/// catalogs, which is harmless - none of these names appear there except
/// `delete` (whose `AMBIGUOUS_DEL` storage gating is exactly what a
/// non-client receiver should get) and `popen` (a genuine exec in any
/// catalog language).
fn classify_python_sink(n: &str) -> Option<SinkKind> {
    let seg = last_segment(n);
    let receiver = n.rsplit_once('.').map(|(r, _)| r).unwrap_or("");

    // DB-API cursor/connection execute. `executemany`/`executescript` are
    // rarer but no less generic (`executor.executemany` batches tasks), so
    // all three take the storage gate.
    if matches!(seg, "execute" | "executemany" | "executescript") && storage_receiver(n) {
        return Some(SinkKind::Sql);
    }
    // SQLAlchemy textual SQL - only the module-qualified spelling is precise
    // enough. Bare `text(` names everything from templating to tokenizers,
    // so the common from-import spelling is deliberately missed.
    if seg == "text" && receiver == "sqlalchemy" {
        return Some(SinkKind::Sql);
    }
    // The subprocess family. `run`/`call` are the most generic names in the
    // language, so the qualified name must say `subprocess`; the from-import
    // spellings of the names that exist nowhere else keep their recall bare.
    const SUBPROCESS_FAMILY: &[&str] = &[
        "run",
        "call",
        "check_call",
        "check_output",
        "popen",
        "getoutput",
    ];
    if SUBPROCESS_FAMILY.contains(&seg) {
        if n.contains("subprocess") {
            return Some(SinkKind::Exec);
        }
        if receiver.is_empty() && matches!(seg, "check_call" | "check_output" | "getoutput") {
            return Some(SinkKind::Exec);
        }
    }
    // `os.execv*`/`os.spawn*` replace or fork the process image. Gated on the
    // `os` receiver: a method named `execvp` on anything else is somebody's
    // wrapper, and flagging wrappers is the caller's walk to do.
    if receiver == "os" && (seg.starts_with("exec") || seg.starts_with("spawn")) {
        return Some(SinkKind::Exec);
    }
    // Outbound HTTP. `urlopen` exists only in urllib, so it carries alone;
    // the client-library verbs fire only when the receiver IS the module.
    if seg == "urlopen" {
        return Some(SinkKind::Ssrf);
    }
    if matches!(seg, "get" | "post" | "put" | "patch" | "delete" | "request")
        && matches!(receiver, "requests" | "httpx" | "aiohttp")
    {
        return Some(SinkKind::Ssrf);
    }
    // Filesystem deletion, module-gated: `items.remove(x)` is a list op.
    if receiver == "os" && matches!(seg, "remove" | "unlink" | "removedirs") {
        return Some(SinkKind::Deletion);
    }
    if receiver == "shutil" && seg == "rmtree" {
        return Some(SinkKind::Deletion);
    }
    None
}

fn classify_sink(name: &str, lang: &Language) -> Option<SinkKind> {
    let n = name.to_ascii_lowercase();
    if BENIGN_RECEIVERS.iter().any(|p| n.starts_with(p)) {
        return None;
    }
    // Matching is on the EXACT final identifier segment to avoid substring
    // false positives (e.g. `system` inside `filesystemAdapter`, or `assert`
    // inside PHPUnit's `assertArrayHasKey`).
    const DEL: &[&str] = &[
        "delete",
        "destroy",
        "forcedelete",
        "truncate",
        "droptable",
        "dropdatabase",
        "unlink",
        "rmdir",
        "deletedirectory",
        "deleteprefix",
        "purge",
        "purgeexpired",
    ];
    const EXEC: &[&str] = &[
        "exec",
        "shell_exec",
        "system",
        "passthru",
        "proc_open",
        "popen",
        "eval",
        "pcntl_exec",
    ];
    const SQL: &[&str] = &[
        "whereraw",
        "selectraw",
        "orderbyraw",
        "havingraw",
        "unprepared",
        "statement",
        "rawquery",
    ];
    const FS: &[&str] = &[
        "file_get_contents",
        "file_put_contents",
        "fopen",
        "fwrite",
        "readfile",
        "include",
        "require",
        "require_once",
        "include_once",
    ];
    const SSRF: &[&str] = &["curl_exec", "curl_multi_exec"];
    let seg = last_segment(&n);
    let hit = |list: &[&str]| list.contains(&seg);

    // Deletion needs care in Rust/Go: `delete`/`destroy`/`DELETE` are HTTP
    // methods and routing DSL (axum `delete(handler)` registers a route), and
    // `truncate` is `Vec::truncate` - none destructive. Split by ambiguity:
    //  - HARD_DEL: no HTTP method, router, or collection op shares these names,
    //    so they're destructive in any language.
    //  - AMBIGUOUS_DEL: destructive only with a storage-hinted receiver
    //    (`self.db.delete()`), except in PHP where `$model->delete()` is
    //    idiomatic and the DEL name catalog below keeps recall.
    const HARD_DEL: &[&str] = &[
        "forcedelete",
        "droptable",
        "dropdatabase",
        "unlink",
        "rmdir",
        "deletedirectory",
        "deleteprefix",
        "deletemany",
        "deleteone",
    ];
    if HARD_DEL.contains(&seg) {
        return Some(SinkKind::Deletion);
    }
    // Python's dangerous callables hide behind the most generic names in the
    // language (`execute`, `run`, `get`), so they are classified by receiver,
    // never by name alone. Checked before AMBIGUOUS_DEL so `requests.delete`
    // reads as the outbound HTTP call it is, not as a deletion verb.
    if matches!(lang, Language::Python) {
        if let Some(kind) = classify_python_sink(&n) {
            return Some(kind);
        }
    }
    if AMBIGUOUS_DEL.contains(&seg) {
        // Storage-hinted receiver ⇒ an ORM delete (`self.db.delete()`). NOT for
        // JS/TS: there `.delete(key)` is `Map`/`Set`/`WeakMap` removal, and a
        // collection named `beamStore`/`sessionCache` matches a storage hint by
        // coincidence - a Map delete is not a destructive DB op.
        if !matches!(lang, Language::JavaScript | Language::TypeScript) && storage_receiver(&n) {
            return Some(SinkKind::Deletion);
        }
        if !matches!(lang, Language::Php) {
            return None;
        }
    }

    // EXEC/SQL/FS/SSRF (and the PHP-side DEL) are bare identifier names lifted
    // from PHP/JS/Python runtimes (`passthru`, `whereRaw`, `file_get_contents`).
    // In Rust/Go the same tokens are ordinary method names, so the name
    // catalogs only apply to the languages where they're genuine builtins.
    let name_catalogs = matches!(
        lang,
        Language::Php | Language::JavaScript | Language::TypeScript | Language::Python
    );
    if name_catalogs && hit(DEL) {
        Some(SinkKind::Deletion)
    } else if name_catalogs && hit(EXEC) {
        Some(SinkKind::Exec)
    } else if name_catalogs && hit(SQL) {
        Some(SinkKind::Sql)
    } else if name_catalogs && hit(FS) {
        Some(SinkKind::FileSystem)
    } else if name_catalogs && hit(SSRF) {
        Some(SinkKind::Ssrf)
    } else {
        None
    }
}

fn name_is_gate(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    const GATES: &[&str] = &[
        "authorize",
        "validate",
        "validated",
        "->can",
        "cannot",
        "gate::",
        "policy",
        "permission",
        "checkpermission",
        "abort_unless",
        "abort_if",
        "denyaccess",
        "requireclientapikey",
        "requirepolymartapikey",
        "authenticate",
        "middleware",
    ];
    GATES.iter().any(|k| n.contains(k))
}

fn middleware_is_gate(m: &str) -> bool {
    let n = m.to_ascii_lowercase();
    const TOKENS: &[&str] = &[
        "auth",
        "admin",
        "permission",
        "can:",
        "ability",
        "verified",
        "client-api",
        "application-api",
        "daemon",
        "polymart-api",
        "two-factor",
        "twofactor",
        "requiretwofactor",
    ];
    TOKENS.iter().any(|t| n.contains(t))
}

fn tier_of(fq: &str, file: &str) -> Tier {
    let s = format!("{} {}", fq, file).to_ascii_lowercase();
    if s.contains("daemon") || s.contains("api-remote") || s.contains("/remote") {
        Tier::Daemon
    } else if s.contains("admin") {
        Tier::Admin
    } else if s.contains("application") {
        Tier::Application
    } else if s.contains("client") {
        Tier::Client
    } else {
        Tier::Public
    }
}

fn bump(s: Severity) -> Severity {
    match s {
        Severity::Low => Severity::Medium,
        Severity::Medium => Severity::High,
        Severity::High | Severity::Critical => Severity::Critical,
        Severity::Info => Severity::Low,
    }
}

fn short(name: &str, fq: &str) -> String {
    let base = if name.is_empty() { fq } else { name };
    last_segment(base).to_string()
}

fn source_label(s: &TaintSource) -> String {
    use TaintSource::*;
    match s {
        GetParam(p) => format!("$_GET[{}]", p),
        PostParam(p) => format!("$_POST[{}]", p),
        RequestParam(p) => format!("request({})", p),
        CookieParam(p) => format!("$_COOKIE[{}]", p),
        ServerVar(p) => format!("$_SERVER[{}]", p),
        EnvVar(p) => format!("env({})", p),
        FileUpload => "file upload".to_string(),
        Unknown => "user input".to_string(),
    }
}

fn sink_label(s: &TaintSink) -> &'static str {
    match s {
        TaintSink::SqlQuery => "SQL query",
        TaintSink::CommandExec => "command exec",
        TaintSink::EvalExec => "eval",
        TaintSink::FileInclude => "file include",
        TaintSink::HtmlOutput => "HTML output",
        TaintSink::HttpHeader => "HTTP header",
        TaintSink::FileWrite => "file write",
        TaintSink::ExternalRequest => "external request",
    }
}

fn taint_sink_severity(s: &TaintSink) -> Severity {
    match s {
        TaintSink::SqlQuery
        | TaintSink::CommandExec
        | TaintSink::EvalExec
        | TaintSink::FileInclude => Severity::High,
        TaintSink::FileWrite | TaintSink::ExternalRequest => Severity::Medium,
        TaintSink::HtmlOutput | TaintSink::HttpHeader => Severity::Medium,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_dangerous_sinks() {
        let php = &Language::Php;
        assert!(matches!(
            classify_sink("delete", php),
            Some(SinkKind::Deletion)
        ));
        assert!(matches!(
            classify_sink("forceDelete", php),
            Some(SinkKind::Deletion)
        ));
        assert!(matches!(
            classify_sink("shell_exec", php),
            Some(SinkKind::Exec)
        ));
        assert!(matches!(
            classify_sink("whereRaw", php),
            Some(SinkKind::Sql)
        ));
        assert!(matches!(
            classify_sink("file_get_contents", php),
            Some(SinkKind::FileSystem)
        ));
        assert!(classify_sink("formatBytes", php).is_none());
    }

    #[test]
    fn benign_receivers_are_not_sinks() {
        // Dotted-receiver deletion is a Rust concept (PHP method calls use `->`),
        // so those cases are classified as Rust; PHP keeps `->`/bare-verb recall.
        let rust = &Language::Rust;
        let php = &Language::Php;
        // Typed std-container receivers (from atlas type inference).
        assert!(classify_sink("Vec::truncate", rust).is_none());
        assert!(classify_sink("String::truncate", rust).is_none());
        assert!(classify_sink("HashMap::remove", rust).is_none());
        // Unknown Rust dotted receiver + ambiguous verb: not storage.
        assert!(classify_sink("rec.truncate", rust).is_none());
        assert!(classify_sink("self.pending.delete", rust).is_none());
        // Bare deletion verbs in Rust are HTTP methods / routing DSL, not sinks.
        assert!(classify_sink("delete", rust).is_none());
        assert!(classify_sink("DELETE", rust).is_none());
        assert!(classify_sink("destroy", rust).is_none());
        // Storage-suggesting receivers still count - recall floor for real
        // deletions across the storage-hint vocabulary.
        assert!(matches!(
            classify_sink("self.db.delete", rust),
            Some(SinkKind::Deletion)
        ));
        assert!(matches!(
            classify_sink("self.records.delete", rust),
            Some(SinkKind::Deletion)
        ));
        assert!(matches!(
            classify_sink("cache.delete", rust),
            Some(SinkKind::Deletion)
        ));
        assert!(matches!(
            classify_sink("self.session.destroy", rust),
            Some(SinkKind::Deletion)
        ));
        // `truncate` in Rust is OpenOptions/Vec/File, never a DB destroy.
        assert!(classify_sink("file.truncate", rust).is_none());
        assert!(classify_sink("buf.truncate", rust).is_none());
        // Unambiguous destructive verbs count regardless of receiver/language.
        assert!(matches!(
            classify_sink("x.unlink", rust),
            Some(SinkKind::Deletion)
        ));
        assert!(matches!(
            classify_sink("conn.dropTable", rust),
            Some(SinkKind::Deletion)
        ));
        // PHP arrow calls keep their Laravel model semantics.
        assert!(matches!(
            classify_sink("$user->delete", php),
            Some(SinkKind::Deletion)
        ));
        // Bare verbs (PHP query builders) keep their recall.
        assert!(matches!(
            classify_sink("truncate", php),
            Some(SinkKind::Deletion)
        ));
    }

    /// The exec/sql/fs/ssrf name catalogs are PHP/JS/Python builtins and must not
    /// fire on Rust/Go, where the same tokens are ordinary method names.
    #[test]
    fn exec_catalog_is_language_gated() {
        // Regression: ripgrep has a Rust builder method literally named `passthru`.
        assert!(classify_sink("passthru", &Language::Rust).is_none());
        assert!(classify_sink("passthru", &Language::Go).is_none());
        assert!(classify_sink("passthru", &Language::Unknown).is_none());
        // Same for the other PHP-shaped bare-name catalogs on Rust.
        assert!(classify_sink("shell_exec", &Language::Rust).is_none());
        assert!(classify_sink("whereRaw", &Language::Rust).is_none());
        assert!(classify_sink("file_get_contents", &Language::Rust).is_none());
        assert!(classify_sink("curl_exec", &Language::Rust).is_none());
        // PHP/JS/TS/Python keep full recall.
        assert!(matches!(
            classify_sink("passthru", &Language::Php),
            Some(SinkKind::Exec)
        ));
        assert!(matches!(
            classify_sink("passthru", &Language::JavaScript),
            Some(SinkKind::Exec)
        ));
        assert!(matches!(
            classify_sink("passthru", &Language::TypeScript),
            Some(SinkKind::Exec)
        ));
        assert!(matches!(
            classify_sink("passthru", &Language::Python),
            Some(SinkKind::Exec)
        ));
        // Deletion path stays language-agnostic (Rust fs deletion via storage hint).
        assert!(matches!(
            classify_sink("self.db.delete", &Language::Rust),
            Some(SinkKind::Deletion)
        ));
    }

    /// Python DB-API `execute` fires only behind a storage-hinted receiver -
    /// a thread pool's `executor.execute` shares the name and must not flag.
    #[test]
    fn python_execute_is_receiver_gated() {
        let py = &Language::Python;
        assert!(matches!(
            classify_sink("cursor.execute", py),
            Some(SinkKind::Sql)
        ));
        assert!(matches!(
            classify_sink("self.db.execute", py),
            Some(SinkKind::Sql)
        ));
        assert!(matches!(
            classify_sink("conn.executemany", py),
            Some(SinkKind::Sql)
        ));
        assert!(matches!(
            classify_sink("connection.executescript", py),
            Some(SinkKind::Sql)
        ));
        assert!(matches!(
            classify_sink("session.execute", py),
            Some(SinkKind::Sql)
        ));
        // The generic spellings stay silent: bare from-import, thread pools.
        assert!(classify_sink("execute", py).is_none());
        assert!(classify_sink("executor.execute", py).is_none());
        assert!(classify_sink("self.executor.executemany", py).is_none());
        // And the gate is Python-only - a Rust method named `execute` is not
        // a DB-API cursor even behind a hinted receiver name.
        assert!(classify_sink("cursor.execute", &Language::Rust).is_none());
        // SQLAlchemy `text` only in its module-qualified spelling.
        assert!(matches!(
            classify_sink("sqlalchemy.text", py),
            Some(SinkKind::Sql)
        ));
        assert!(classify_sink("text", py).is_none());
        assert!(classify_sink("self.text", py).is_none());
    }

    /// The subprocess family: `run`/`call` need `subprocess` in the qualified
    /// name; the names that exist nowhere else keep their from-import recall.
    #[test]
    fn python_subprocess_family_is_module_gated() {
        let py = &Language::Python;
        assert!(matches!(
            classify_sink("subprocess.run", py),
            Some(SinkKind::Exec)
        ));
        assert!(matches!(
            classify_sink("subprocess.call", py),
            Some(SinkKind::Exec)
        ));
        assert!(matches!(
            classify_sink("subprocess.check_output", py),
            Some(SinkKind::Exec)
        ));
        assert!(matches!(
            classify_sink("subprocess.Popen", py),
            Some(SinkKind::Exec)
        ));
        // From-import spellings of the subprocess-only names.
        assert!(matches!(
            classify_sink("check_output", py),
            Some(SinkKind::Exec)
        ));
        assert!(matches!(
            classify_sink("check_call", py),
            Some(SinkKind::Exec)
        ));
        assert!(matches!(
            classify_sink("getoutput", py),
            Some(SinkKind::Exec)
        ));
        // Bare `run`/`call` are everywhere and must never flag.
        assert!(classify_sink("run", py).is_none());
        assert!(classify_sink("call", py).is_none());
        assert!(classify_sink("app.run", py).is_none());
        assert!(classify_sink("loop.run", py).is_none());
        // os.exec*/os.spawn* replace the process image; wrappers do not.
        assert!(matches!(
            classify_sink("os.execvp", py),
            Some(SinkKind::Exec)
        ));
        assert!(matches!(
            classify_sink("os.spawnl", py),
            Some(SinkKind::Exec)
        ));
        assert!(classify_sink("runner.execvp", py).is_none());
        // Rust/Go methods named `run` stay out regardless.
        assert!(classify_sink("subprocess.run", &Language::Rust).is_none());
    }

    /// HTTP verbs fire only when the receiver IS a client module - a `get` on
    /// anything else (`self.client.get`, `settings.get`) is a lookup.
    #[test]
    fn python_http_verbs_need_a_client_module_receiver() {
        let py = &Language::Python;
        assert!(matches!(
            classify_sink("requests.get", py),
            Some(SinkKind::Ssrf)
        ));
        assert!(matches!(
            classify_sink("requests.post", py),
            Some(SinkKind::Ssrf)
        ));
        assert!(matches!(
            classify_sink("httpx.request", py),
            Some(SinkKind::Ssrf)
        ));
        assert!(matches!(
            classify_sink("aiohttp.request", py),
            Some(SinkKind::Ssrf)
        ));
        // `requests.delete` is an outbound call, never a deletion verb.
        assert!(matches!(
            classify_sink("requests.delete", py),
            Some(SinkKind::Ssrf)
        ));
        // urlopen exists only in urllib - it carries without a receiver.
        assert!(matches!(classify_sink("urlopen", py), Some(SinkKind::Ssrf)));
        assert!(matches!(
            classify_sink("urllib.request.urlopen", py),
            Some(SinkKind::Ssrf)
        ));
        // Everything the gate exists for.
        assert!(classify_sink("get", py).is_none());
        assert!(classify_sink("self.client.get", py).is_none());
        assert!(classify_sink("settings.get", py).is_none());
        assert!(classify_sink("headers.get", py).is_none());
        assert!(classify_sink("requests.get", &Language::Rust).is_none());
    }

    /// Filesystem deletion is module-gated: `items.remove(x)` is a list op.
    #[test]
    fn python_fs_deletion_is_module_gated() {
        let py = &Language::Python;
        assert!(matches!(
            classify_sink("os.remove", py),
            Some(SinkKind::Deletion)
        ));
        assert!(matches!(
            classify_sink("shutil.rmtree", py),
            Some(SinkKind::Deletion)
        ));
        // `unlink` is unambiguous in any language via HARD_DEL.
        assert!(matches!(
            classify_sink("os.unlink", py),
            Some(SinkKind::Deletion)
        ));
        assert!(classify_sink("remove", py).is_none());
        assert!(classify_sink("items.remove", py).is_none());
        assert!(classify_sink("rmtree", py).is_none());
        // The Python receiver gate must not disturb the shared AMBIGUOUS_DEL
        // storage logic: an ORM delete still counts, a plain attr does not.
        assert!(matches!(
            classify_sink("session.delete", py),
            Some(SinkKind::Deletion)
        ));
        assert!(classify_sink("self.pending.delete", py).is_none());
    }

    fn test_symbol(
        id: u64,
        name: &str,
        lang: Language,
        entry: bool,
        file: &str,
    ) -> verum_nucleus::Symbol {
        verum_nucleus::Symbol {
            id: SymbolId(id),
            name: name.to_string(),
            fully_qualified: name.to_string(),
            kind: verum_nucleus::SymbolKind::Function,
            visibility: verum_nucleus::Visibility::Public,
            file: std::path::PathBuf::from(file),
            line_start: 1,
            line_end: 5,
            col_start: 0,
            col_end: 0,
            language: lang,
            parent: None,
            hash: 0,
            normalized_hash: 0,
            flow_hash: 0,
            param_count: 0,
            is_entry_point: entry,
            doc_comment: None,
        }
    }

    fn test_call(
        caller: u64,
        callee: verum_nucleus::CallTarget,
        file: &str,
    ) -> verum_nucleus::Call {
        verum_nucleus::Call {
            caller: SymbolId(caller),
            callee,
            file: std::path::PathBuf::from(file),
            line: 2,
            col: 0,
        }
    }

    /// A Rust entry point calling a symbol named `passthru` must NOT produce an
    /// Exec chain finding - this is the reported false positive.
    #[test]
    fn rust_passthru_chain_is_not_flagged() {
        let mut ir = Ir::default();
        ir.symbols.insert(
            SymbolId(1),
            test_symbol(1, "main", Language::Rust, true, "src/main.rs"),
        );
        ir.symbols.insert(
            SymbolId(2),
            test_symbol(2, "passthru", Language::Rust, false, "src/search.rs"),
        );
        ir.calls.push(test_call(
            1,
            verum_nucleus::CallTarget::Resolved(SymbolId(2)),
            "src/main.rs",
        ));

        let findings = analyse(&ir);
        let msgs: Vec<&String> = findings.iter().map(|f| &f.message).collect();
        assert!(
            !findings
                .iter()
                .any(|f| f.message.contains("command/code execution")),
            "Rust passthru must not be flagged as exec: {:?}",
            msgs
        );
    }

    /// A PHP entry point reaching `passthru(` must still be flagged (recall guard).
    #[test]
    fn php_passthru_chain_is_still_flagged() {
        let mut ir = Ir::default();
        ir.symbols.insert(
            SymbolId(1),
            test_symbol(
                1,
                "handleRequest",
                Language::Php,
                true,
                "app/Http/Controller.php",
            ),
        );
        ir.calls.push(test_call(
            1,
            verum_nucleus::CallTarget::Unresolved("passthru".to_string()),
            "app/Http/Controller.php",
        ));

        let findings = analyse(&ir);
        let msgs: Vec<&String> = findings.iter().map(|f| &f.message).collect();
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("command/code execution")),
            "PHP passthru must still be flagged: {:?}",
            msgs
        );
    }

    #[test]
    fn recognizes_gates() {
        assert!(name_is_gate("authorize"));
        assert!(name_is_gate("Gate::allows"));
        assert!(middleware_is_gate("auth:sanctum"));
        assert!(middleware_is_gate("admin"));
        assert!(!middleware_is_gate("throttle:api"));
        assert!(!name_is_gate("formatBytes"));
    }

    #[test]
    fn trust_tiers_order() {
        assert!(tier_of("App\\Http\\Controllers\\Admin\\X", "admin.php") > Tier::Public);
        assert!(tier_of("App\\Daemon\\Y", "api-remote.php") > Tier::Admin);
    }

    #[test]
    fn last_segment_strips_qualifiers() {
        assert_eq!(last_segment("App\\Foo::bar"), "bar");
        assert_eq!(last_segment("$this->handle"), "handle");
        assert_eq!(last_segment("DB::raw"), "raw");
    }
}
