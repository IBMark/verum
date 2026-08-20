pub mod composer;
pub mod dockerfile;
pub mod endpoints;
pub mod go_lang;
pub mod html;
pub mod java;
pub mod java_web;
pub mod javascript;
pub mod kubernetes;
pub mod laravel;
pub mod php;
pub mod python;
pub mod resolver;
pub mod rust_lang;
pub mod terraform;

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Result;
use rayon::prelude::*;

use verum_nucleus::{FileId, FileInfo, Framework, Ir, Language, SymbolId};

/// Deterministic string hash (FNV-1a) for symbol/file ids and source hashes.
/// ahash - even `AHasher::default()` - is seeded per process, so ids and
/// hashes built with it change on every run; two invocations of `verum` on
/// the same tree could never be compared. FNV-1a is stable across runs,
/// platforms, and builds.
pub fn stable_hash(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Strip comments from source text before normalization so that comment
/// wording never affects `normalized_hash` - two functions that differ only in
/// comments must hash identically. String literals are preserved verbatim
/// (a `//` inside `"http://..."` is not a comment).
///
/// `slash`: strip `//` and `/* */` (PHP/JS/TS/Rust/Go). Disabled for Python,
/// where `//` is floor division. `hash`: strip `#` line comments (PHP/Python).
/// `single_quote`: treat `'` as a string delimiter - off for Rust, where a
/// `'a` lifetime would open a phantom string and swallow real code from the
/// normalized hash.
pub(crate) fn strip_comments(source: &str, slash: bool, hash: bool, single_quote: bool) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        // Rust mode: consume a char literal ('x', '\n', '\u{2026}') as a unit
        // so a quote inside it can't open a phantom string. Anything that
        // doesn't close like a char literal is a lifetime - plain text.
        if !single_quote && c == '\'' {
            let lit_end = if i + 1 < chars.len() && chars[i + 1] == '\\' {
                (i + 2..(i + 12).min(chars.len())).find(|&j| chars[j] == '\'')
            } else if i + 2 < chars.len() && chars[i + 2] == '\'' && chars[i + 1] != '\'' {
                Some(i + 2)
            } else {
                None
            };
            if let Some(end) = lit_end {
                for ch in &chars[i..=end] {
                    out.push(*ch);
                }
                i = end + 1;
            } else {
                out.push(c);
                i += 1;
            }
            continue;
        }
        if c == '"' || (single_quote && c == '\'') || c == '`' {
            let quote = c;
            out.push(c);
            i += 1;
            while i < chars.len() {
                let ch = chars[i];
                out.push(ch);
                i += 1;
                if ch == '\\' && i < chars.len() {
                    out.push(chars[i]);
                    i += 1;
                } else if ch == quote {
                    break;
                }
            }
            continue;
        }
        if slash && c == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if slash && c == '/' && i + 1 < chars.len() && chars[i + 1] == '*' {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i = (i + 2).min(chars.len());
            continue;
        }
        if hash && c == '#' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Per-thread, per-language reuse of `tree_sitter::Parser` instances.
///
/// Constructing a `Parser` and loading a grammar for every file is pure
/// overhead in the rayon parse loop - each worker thread only ever needs one
/// parser per language. A parser given no old tree is stateless between
/// `parse` calls, so reuse cannot change the resulting tree.
pub(crate) mod parser_pool {
    use std::cell::RefCell;

    use tree_sitter::{Language, Parser, Tree};

    thread_local! {
        // Keyed by a static language name. At most a handful of entries, so a
        // linear scan over a Vec beats hashing.
        static PARSERS: RefCell<Vec<(&'static str, Parser)>> = const { RefCell::new(Vec::new()) };
    }

    /// Parse `source` with this thread's cached parser for `key`, creating
    /// (and caching) one via `language` on first use per thread.
    pub(crate) fn parse(
        key: &'static str,
        language: impl FnOnce() -> Language,
        source: &str,
    ) -> Option<Tree> {
        PARSERS.with(|cell| {
            let mut pool = cell.borrow_mut();
            if let Some((_, parser)) = pool.iter_mut().find(|(k, _)| *k == key) {
                return parser.parse(source, None);
            }
            let mut parser = Parser::new();
            parser.set_language(&language()).ok()?;
            let tree = parser.parse(source, None);
            pool.push((key, parser));
            tree
        })
    }
}

/// Configuration for the Atlas code mapper.
#[derive(Debug, Clone)]
pub struct AtlasConfig {
    pub root: PathBuf,
    pub language: Language,
    pub exclude_patterns: Vec<String>,
    pub cache_path: Option<PathBuf>,
    pub delta_mode: bool,
}

impl Default for AtlasConfig {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
            language: Language::Php,
            exclude_patterns: Vec::new(),
            cache_path: None,
            delta_mode: false,
        }
    }
}

/// Atlas maps a codebase into the Verum IR.
pub struct Atlas {
    pub config: AtlasConfig,
}

/// Per-phase timing when VERUM_PROFILE is set in the environment, mirroring
/// the pass timing in verum-lumen. Timing is observation only - it never
/// influences what gets mapped.
fn profile_phase(profile: bool, name: &str, since: Instant) -> Instant {
    if profile {
        eprintln!("  atlas {:<18} {:>6.2}s", name, since.elapsed().as_secs_f64());
    }
    Instant::now()
}

impl Atlas {
    pub fn new(config: AtlasConfig) -> Self {
        Self { config }
    }

    /// Build the IR from the configured root directory.
    pub fn build(&self) -> Result<Ir> {
        let start = Instant::now();
        let profile = std::env::var("VERUM_PROFILE").is_ok();
        let mut mark = Instant::now();

        let (files, infra_files) = self.collect_all();
        tracing::info!("Collected {} files", files.len());
        mark = profile_phase(profile, "walk", mark);

        let partial_irs: Vec<Ir> = files
            .par_iter()
            .filter_map(|path| match self.parse_file(path) {
                Ok(ir) => Some(ir),
                Err(e) => {
                    tracing::warn!("Failed to parse {}: {}", path.display(), e);
                    None
                }
            })
            .collect();
        mark = profile_phase(profile, "parse", mark);

        let mut ir = partial_irs.into_iter().fold(Ir::new(), |mut acc, partial| {
            acc.merge(partial);
            acc
        });
        mark = profile_phase(profile, "merge", mark);

        if !infra_files.is_empty() {
            tracing::info!("Collected {} infrastructure files", infra_files.len());
            let infra_irs: Vec<Ir> = infra_files
                .par_iter()
                .filter_map(|path| match self.parse_infra_file(path) {
                    Ok(partial) => Some(partial),
                    Err(e) => {
                        tracing::warn!("Failed to parse infra file {}: {}", path.display(), e);
                        None
                    }
                })
                .collect();
            for partial in infra_irs {
                ir.merge(partial);
            }
        }

        let framework = composer::detect_framework(&self.config.root);
        ir.framework = framework;

        // Extract Laravel routes BEFORE the resolver pass so route-file call
        // edges (controller references, provider bindings) get resolved too.
        if ir.framework == Framework::Laravel {
            laravel::extract_routes(&self.config.root, &mut ir);
        }
        mark = profile_phase(profile, "infra+framework", mark);

        resolver::resolve(&mut ir);
        mark = profile_phase(profile, "resolve", mark);

        java_web::extract_routes(&mut ir);

        // Promote wrapper calls (`request('/x')` through a project fetch/axios
        // wrapper) to real HTTP calls before linking.
        endpoints::promote_wrapper_calls(&mut ir);

        // Stitch client HTTP calls to the routes that serve them, so the call
        // graph spans the frontend/backend language boundary.
        endpoints::link(&mut ir);

        detect_entry_points(&mut ir);
        profile_phase(profile, "link+entrypoints", mark);

        let elapsed = start.elapsed();
        ir.metadata.build_time_ms = elapsed.as_millis() as u64;
        ir.metadata.total_symbols = ir.symbols.len();
        ir.metadata.language = self.config.language.clone();
        ir.metadata.verum_version = env!("CARGO_PKG_VERSION").to_string();

        Ok(ir)
    }

    /// Collect source and infrastructure files (K8s YAML, Dockerfiles,
    /// Terraform) in one walk over the tree.
    ///
    /// The walk respects the repository's own `.gitignore` and
    /// `.git/info/exclude` - a gitignored `venv/` or scratch directory is not
    /// shipped code, and mapping it both costs time and floods findings.
    /// Machine-dependent rules (the user's global gitignore, ignore files
    /// above the root) are deliberately NOT applied: the same tree must map
    /// identically on every machine. Both result lists are sorted, so the
    /// downstream merge order never depends on directory readdir order.
    fn collect_all(&self) -> (Vec<PathBuf>, Vec<PathBuf>) {
        let mut files = Vec::new();
        let mut infra_files = Vec::new();

        let walker = ignore::WalkBuilder::new(&self.config.root)
            .follow_links(false)
            // Keep dotfiles visible (`.eslintrc.js`, CI YAML under `.github/`
            // were always mapped); only `.git` itself is pruned below.
            .hidden(false)
            .git_ignore(true)
            .git_exclude(true)
            // Machine state must not change findings.
            .git_global(false)
            .parents(false)
            // `.ignore` files are tool-specific; only git's rules apply.
            .ignore(false)
            .require_git(true)
            .filter_entry(|e| e.file_name() != ".git")
            .build();

        for entry in walker.filter_map(|e| e.ok()) {
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            let path_str = path.to_string_lossy();
            if path_str.contains("vendor/") || path_str.contains("node_modules/") {
                continue;
            }
            if is_build_output(&path_str) {
                continue;
            }

            let excluded = self
                .config
                .exclude_patterns
                .iter()
                .any(|pat| path_str.contains(pat.as_str()));
            if excluded {
                continue;
            }

            // Size cap, checked on metadata BEFORE any read: hand-written
            // source is essentially never this large, so anything bigger is
            // generated output or data that would cost parse time for zero
            // signal.
            if entry
                .metadata()
                .map(|m| m.len() > MAX_SOURCE_FILE_BYTES)
                .unwrap_or(false)
            {
                continue;
            }

            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if file_name == "Dockerfile"
                || file_name.ends_with(".dockerfile")
                || file_name.starts_with("Dockerfile.")
            {
                infra_files.push(path.to_path_buf());
                continue;
            }

            let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
                continue;
            };

            match ext {
                "yaml" | "yml" => {
                    // Only files that look like K8s manifests.
                    if let Ok(content) = std::fs::read_to_string(path) {
                        if content.contains("apiVersion:") && content.contains("kind:") {
                            infra_files.push(path.to_path_buf());
                        }
                    }
                    continue;
                }
                "tf" => {
                    infra_files.push(path.to_path_buf());
                    continue;
                }
                _ => {}
            }

            if language_for_extension(ext).is_none() {
                continue;
            }

            // Blade templates carry a `.php` extension but are not standalone PHP
            // source. Parsing them as PHP yields garbage symbols and false-positive
            // security findings, so skip them from the source scan.
            if is_blade_template(path) {
                continue;
            }

            // Skip minified / generated bundles. These slip past exclude_paths when a
            // build directory isn't excluded and otherwise flood dead-code findings
            // with mangled single-letter identifiers.
            if is_minified_or_generated(path) {
                continue;
            }

            // A NUL byte in the head of the file marks it as binary data
            // wearing a source extension; parsing it yields garbage symbols.
            if looks_binary(path) {
                continue;
            }

            files.push(path.to_path_buf());
        }

        files.sort();
        infra_files.sort();
        (files, infra_files)
    }

    fn parse_infra_file(&self, path: &Path) -> Result<Ir> {
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        if file_name == "Dockerfile"
            || file_name.ends_with(".dockerfile")
            || file_name.starts_with("Dockerfile.")
        {
            return dockerfile::parse_file(path);
        }

        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            match ext {
                "yaml" | "yml" => return kubernetes::parse_file(path),
                "tf" => return terraform::parse_file(path),
                _ => {}
            }
        }

        anyhow::bail!("Unknown infrastructure file type: {}", path.display())
    }

    /// Parse a single file into a partial IR, detecting language from extension.
    fn parse_file(&self, path: &Path) -> Result<Ir> {
        let ext = path.extension().and_then(|e| e.to_str());

        // HTML shares the JavaScript language tag (its inline scripts are JS),
        // so it must be routed by extension before the language match.
        if matches!(ext, Some("html") | Some("htm")) {
            return html::parse_file(path);
        }

        let lang = ext
            .and_then(language_for_extension)
            .unwrap_or_else(|| self.config.language.clone());

        match &lang {
            Language::Php => php::parse_file(path),
            Language::Python => python::parse_file(path),
            Language::Rust => rust_lang::parse_file(path),
            Language::Go => go_lang::parse_file(path),
            Language::Java => java::parse_file(path),
            Language::JavaScript => javascript::parse_file(path, false),
            Language::TypeScript => javascript::parse_file(path, true),
            _ => {
                // Stub for other languages: just register the file
                let mut ir = Ir::new();
                let source = std::fs::read_to_string(path)?;
                let line_count = source.lines().count() as u32;
                let size_bytes = std::fs::metadata(path)?.len();

                let file_id = FileId(crate::stable_hash(path.to_string_lossy().as_ref()));
                ir.files.insert(
                    path.to_path_buf(),
                    FileInfo {
                        id: file_id,
                        path: path.to_path_buf(),
                        language: lang,
                        line_count,
                        size_bytes,
                        last_modified: 0,
                        hash: 0,
                        symbols: Vec::new(),
                    },
                );
                ir.metadata.total_files += 1;
                ir.metadata.total_lines += line_count as u64;

                Ok(ir)
            }
        }
    }
}

/// Files larger than this are skipped before reading (see
/// [`Atlas::collect_all`]). 5 MiB: no hand-written source file reaches this;
/// generated bundles, test corpora and data files do.
const MAX_SOURCE_FILE_BYTES: u64 = 5 * 1024 * 1024;

/// True when the first 8 KiB contain a NUL byte - the standard cheap test for
/// binary content (git uses the same heuristic). Read errors are not treated
/// as binary; the parser will surface them.
fn looks_binary(path: &Path) -> bool {
    use std::io::Read;
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut buf = [0u8; 8192];
    let mut head = file.take(buf.len() as u64);
    let Ok(n) = head.read(&mut buf) else {
        return false;
    };
    buf[..n].contains(&0)
}

/// Returns true for Blade template files (`*.blade.php`).
///
/// `Path::extension` only sees the trailing `php`, so the full file name must be
/// inspected to distinguish a Blade view from a plain PHP source file.
fn is_blade_template(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.ends_with(".blade.php"))
        .unwrap_or(false)
}

/// Heuristic detection of minified or generated assets that should not be
/// analyzed as hand-written source.
///
/// Catches `*.min.js` / `*.min.css` by name, and otherwise samples the file: a
/// very long maximum line length (typical of bundlers) with few newlines marks
/// the file as generated.
fn is_minified_or_generated(path: &Path) -> bool {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if name.ends_with(".min.js") || name.ends_with(".min.css") {
            return true;
        }
    }

    // Only sample text assets we'd otherwise parse.
    let is_scannable = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| matches!(e, "js" | "jsx" | "ts" | "tsx" | "css"))
        .unwrap_or(false);
    if !is_scannable {
        return false;
    }

    // Sample up to 64 KiB; bundlers emit one enormous line.
    if let Ok(file) = std::fs::File::open(path) {
        use std::io::Read;
        let mut buf = vec![0u8; 64 * 1024];
        if let Ok(n) = file.take(64 * 1024).read(&mut buf[..]) {
            let sample = String::from_utf8_lossy(&buf[..n]);
            let longest_line = sample.lines().map(|l| l.len()).max().unwrap_or(0);
            if longest_line > 5000 {
                return true;
            }
        }
    }

    false
}

/// Compiled/generated output directories - a SvelteKit/Next/webpack `build/`
/// or `dist/` holds bundled, minified output, not hand-written source, and
/// analyzing it floods dead-code/duplicate/naming findings with mangled names.
fn is_build_output(path_str: &str) -> bool {
    const DIRS: &[&str] = &[
        "/build/",
        "/dist/",
        "/.svelte-kit/",
        "/.next/",
        "/.nuxt/",
        "/.output/",
        "/out/",
        "/coverage/",
        "/.turbo/",
    ];
    DIRS.iter().any(|d| path_str.contains(d))
}

fn language_for_extension(ext: &str) -> Option<Language> {
    match ext {
        "php" => Some(Language::Php),
        "rs" => Some(Language::Rust),
        "js" | "jsx" => Some(Language::JavaScript),
        "ts" | "tsx" => Some(Language::TypeScript),
        "py" => Some(Language::Python),
        "go" => Some(Language::Go),
        "java" => Some(Language::Java),
        "html" | "htm" => Some(Language::JavaScript),
        _ => None,
    }
}

/// Mark route-mapped controllers, framework-magic Laravel classes, and React
/// page components as entry points.
fn detect_entry_points(ir: &mut Ir) {
    let mut entry_point_ids: Vec<SymbolId> = Vec::new();

    // Route-mapped controllers are entry points
    for route in &ir.routes {
        if let Some(controller_id) = &route.controller {
            entry_point_ids.push(*controller_id);
        }
    }

    let is_laravel = ir.framework == Framework::Laravel;

    for (id, sym) in &ir.symbols {
        let path_str = sym.file.to_string_lossy();

        if path_str.contains("Controller")
            && matches!(
                sym.kind,
                verum_nucleus::SymbolKind::Class | verum_nucleus::SymbolKind::Method
            )
        {
            entry_point_ids.push(*id);
            continue;
        }

        if is_laravel {
            if path_str.contains("/Providers/")
                && matches!(
                    sym.kind,
                    verum_nucleus::SymbolKind::Class | verum_nucleus::SymbolKind::Method
                )
            {
                entry_point_ids.push(*id);
                continue;
            }
            if path_str.contains("/Middleware/")
                && matches!(
                    sym.kind,
                    verum_nucleus::SymbolKind::Class | verum_nucleus::SymbolKind::Method
                )
            {
                entry_point_ids.push(*id);
                continue;
            }
            if path_str.contains("/Console/")
                && matches!(
                    sym.kind,
                    verum_nucleus::SymbolKind::Class | verum_nucleus::SymbolKind::Method
                )
            {
                entry_point_ids.push(*id);
                continue;
            }
            if (path_str.contains("/Listeners/") || path_str.contains("/Events/"))
                && matches!(
                    sym.kind,
                    verum_nucleus::SymbolKind::Class | verum_nucleus::SymbolKind::Method
                )
            {
                entry_point_ids.push(*id);
                continue;
            }
            if path_str.contains("/Jobs/")
                && matches!(
                    sym.kind,
                    verum_nucleus::SymbolKind::Class | verum_nucleus::SymbolKind::Method
                )
            {
                entry_point_ids.push(*id);
                continue;
            }
            if path_str.contains("/Notifications/")
                && matches!(
                    sym.kind,
                    verum_nucleus::SymbolKind::Class | verum_nucleus::SymbolKind::Method
                )
            {
                entry_point_ids.push(*id);
                continue;
            }
            // Models (accessors, mutators, scopes are called magically)
            if path_str.contains("/Models/")
                && matches!(
                    sym.kind,
                    verum_nucleus::SymbolKind::Class | verum_nucleus::SymbolKind::Method
                )
            {
                entry_point_ids.push(*id);
                continue;
            }
            // Transformers (Fractal includes)
            if path_str.contains("/Transformers/")
                && matches!(
                    sym.kind,
                    verum_nucleus::SymbolKind::Class | verum_nucleus::SymbolKind::Method
                )
            {
                entry_point_ids.push(*id);
                continue;
            }
            if path_str.contains("/Observers/")
                && matches!(
                    sym.kind,
                    verum_nucleus::SymbolKind::Class | verum_nucleus::SymbolKind::Method
                )
            {
                entry_point_ids.push(*id);
                continue;
            }
            if path_str.contains("/Policies/")
                && matches!(
                    sym.kind,
                    verum_nucleus::SymbolKind::Class | verum_nucleus::SymbolKind::Method
                )
            {
                entry_point_ids.push(*id);
                continue;
            }
            if path_str.contains("/Rules/")
                && matches!(
                    sym.kind,
                    verum_nucleus::SymbolKind::Class | verum_nucleus::SymbolKind::Method
                )
            {
                entry_point_ids.push(*id);
                continue;
            }
        }

        // React: exported components under routers/ or pages/
        if matches!(
            sym.language,
            verum_nucleus::Language::TypeScript | verum_nucleus::Language::JavaScript
        ) && matches!(sym.visibility, verum_nucleus::Visibility::Public)
            && (path_str.contains("/routers/") || path_str.contains("/pages/"))
        {
            entry_point_ids.push(*id);
        }
    }

    for id in &entry_point_ids {
        if let Some(sym) = ir.symbols.get_mut(id) {
            sym.is_entry_point = true;
        }
    }

    ir.entry_points.extend(entry_point_ids);
}
