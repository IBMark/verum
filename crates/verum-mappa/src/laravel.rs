use std::path::Path;

use verum_nucleus::{
    Call, CallTarget, FileId, FileInfo, HttpMethod, Ir, Language, Route, Symbol, SymbolId,
    SymbolKind, Visibility,
};

/// Deterministic pseudo-symbol id in a distinct namespace. Hashing the tagged
/// path avoids colliding with parser-allocated ids, which are
/// `hash(path) + n` - an offset of the same base hash would silently
/// overwrite the n-th real symbol of the same file on `HashMap::insert`.
fn pseudo_id(tag: &str, path: &Path) -> SymbolId {
    SymbolId(crate::stable_hash(&format!("{}::{}", tag, path.display())))
}

/// Extract Laravel routes, dynamic dispatch patterns, and template references.
pub fn extract_routes(root: &Path, ir: &mut Ir) {
    let route_files = [
        root.join("routes/web.php"),
        root.join("routes/api.php"),
        root.join("routes/admin.php"),
        root.join("routes/auth.php"),
    ];

    for route_file in &route_files {
        if route_file.exists() {
            if let Ok(content) = std::fs::read_to_string(route_file) {
                parse_route_file(&content, route_file, ir);
            }
        }
    }

    scan_service_providers(root, ir);

    scan_config_files(root, ir);

    scan_blade_templates(root, ir);
}

/// Scan service provider files for ->bind(), ->singleton(), morph maps,
/// $listen/$observers arrays - all of which reference classes dynamically.
fn scan_service_providers(root: &Path, ir: &mut Ir) {
    let providers_dir = root.join("app/Providers");
    if !providers_dir.exists() {
        return;
    }

    // Regex for ::class references - covers bindings, morph maps, listeners, observers
    let class_ref_re = regex::Regex::new(r#"([A-Z][A-Za-z0-9_\\]+)::class"#).expect("valid regex");

    for entry in walkdir::WalkDir::new(&providers_dir)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() || !path.to_string_lossy().ends_with(".php") {
            continue;
        }

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let provider_id = {
            let id = pseudo_id("provider", path);

            ir.symbols.insert(
                id,
                Symbol {
                    id,
                    name: format!(
                        "provider::{}",
                        path.file_stem().unwrap_or_default().to_string_lossy()
                    ),
                    fully_qualified: format!("provider::{}", path.display()),
                    kind: SymbolKind::Function,
                    visibility: Visibility::Public,
                    file: path.to_path_buf(),
                    line_start: 1,
                    line_end: content.lines().count() as u32,
                    col_start: 0,
                    col_end: 0,
                    language: Language::Php,
                    parent: None,
                    hash: 0,
                    normalized_hash: 0,
                    flow_hash: 0,
                    param_count: 0,
                    is_entry_point: true,
                    doc_comment: None,
                },
            );
            id
        };

        for caps in class_ref_re.captures_iter(&content) {
            if let Some(class_name) = caps.get(1) {
                let name = class_name.as_str().to_string();
                let short = name.rsplit('\\').next().unwrap_or(&name).to_string();

                ir.calls.push(Call {
                    caller: provider_id,
                    callee: CallTarget::Unresolved(name),
                    file: path.to_path_buf(),
                    line: 0,
                    col: 0,
                });
                ir.calls.push(Call {
                    caller: provider_id,
                    callee: CallTarget::Unresolved(short),
                    file: path.to_path_buf(),
                    line: 0,
                    col: 0,
                });
            }
        }
    }
}

/// Scan config files for ::class references that load classes dynamically.
fn scan_config_files(root: &Path, ir: &mut Ir) {
    let config_dir = root.join("config");
    if !config_dir.exists() {
        return;
    }

    let class_ref_re = regex::Regex::new(r#"([A-Z][A-Za-z0-9_\\]+)::class"#).expect("valid regex");

    for entry in walkdir::WalkDir::new(&config_dir)
        .follow_links(false)
        .max_depth(2)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() || !path.to_string_lossy().ends_with(".php") {
            continue;
        }

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let config_id = {
            let id = pseudo_id("config", path);

            ir.symbols.insert(
                id,
                Symbol {
                    id,
                    name: format!(
                        "config::{}",
                        path.file_stem().unwrap_or_default().to_string_lossy()
                    ),
                    fully_qualified: format!("config::{}", path.display()),
                    kind: SymbolKind::Function,
                    visibility: Visibility::Public,
                    file: path.to_path_buf(),
                    line_start: 1,
                    line_end: content.lines().count() as u32,
                    col_start: 0,
                    col_end: 0,
                    language: Language::Php,
                    parent: None,
                    hash: 0,
                    normalized_hash: 0,
                    flow_hash: 0,
                    param_count: 0,
                    is_entry_point: true,
                    doc_comment: None,
                },
            );
            id
        };

        for caps in class_ref_re.captures_iter(&content) {
            if let Some(class_name) = caps.get(1) {
                let name = class_name.as_str().to_string();
                let short = name.rsplit('\\').next().unwrap_or(&name).to_string();

                ir.calls.push(Call {
                    caller: config_id,
                    callee: CallTarget::Unresolved(name),
                    file: path.to_path_buf(),
                    line: 0,
                    col: 0,
                });
                ir.calls.push(Call {
                    caller: config_id,
                    callee: CallTarget::Unresolved(short),
                    file: path.to_path_buf(),
                    line: 0,
                    col: 0,
                });
            }
        }
    }
}

fn parse_route_file(content: &str, file: &Path, ir: &mut Ir) {
    // Match patterns like Route::get('/path', [Controller::class, 'method'])
    // or Route::get('/path', 'Controller@method')
    // or Route::get('/path', function() { ... })
    let route_pattern =
        regex::Regex::new(r#"Route::(get|post|put|patch|delete|any)\s*\(\s*['"]([^'"]+)['"]"#)
            .expect("valid regex");

    // Route::match(['get','post'], '/path', ...) - a verb list plus a path.
    let match_pattern =
        regex::Regex::new(r#"Route::match\s*\(\s*\[([^\]]*)\]\s*,\s*['"]([^'"]+)['"]"#)
            .expect("valid regex");

    // Inline ->middleware('a') or ->middleware(['a','b']) on a single route.
    let inline_mw_pattern =
        regex::Regex::new(r#"->middleware\s*\(\s*(\[?[^\])]*)\]?\s*\)"#).expect("valid regex");

    let resource_pattern = regex::Regex::new(
        r#"Route::(resource|apiResource)\s*\(\s*['"]([^'"]+)['"]\s*,\s*([A-Za-z\\]+)"#,
    )
    .expect("valid regex");

    // Match controller references: [Controller::class, 'method'] or 'Controller@method'
    let controller_ref =
        regex::Regex::new(r#"([A-Za-z\\]+)::class\s*,\s*['"](\w+)['"]\s*\]"#).expect("valid regex");
    let controller_at_ref =
        regex::Regex::new(r#"['"]([A-Za-z\\]+)@(\w+)['"]"#).expect("valid regex");

    // Lookup tables over the already-merged IR: class short name -> ids, and
    // (parent class id, method name) -> method id. Built deterministically.
    let mut class_by_name: std::collections::HashMap<String, Vec<SymbolId>> =
        std::collections::HashMap::new();
    let mut method_by_parent: std::collections::HashMap<(SymbolId, String), SymbolId> =
        std::collections::HashMap::new();
    {
        let mut ordered: Vec<(&SymbolId, &Symbol)> = ir.symbols.iter().collect();
        ordered.sort_by(|a, b| {
            (&a.1.file, a.1.line_start, &a.1.name).cmp(&(&b.1.file, b.1.line_start, &b.1.name))
        });
        for (id, sym) in ordered {
            match sym.kind {
                SymbolKind::Class => {
                    class_by_name.entry(sym.name.clone()).or_default().push(*id);
                }
                SymbolKind::Method | SymbolKind::StaticMethod => {
                    if let Some(parent) = sym.parent {
                        method_by_parent
                            .entry((parent, sym.name.clone()))
                            .or_insert(*id);
                    }
                }
                _ => {}
            }
        }
    }

    // Resolve "Controller::class, 'method'" (or Controller@method) to the
    // method symbol, falling back to the class symbol.
    let resolve_controller = |controller: &str, method: &str| -> Option<SymbolId> {
        let short = controller.rsplit('\\').next().unwrap_or(controller);
        let classes = class_by_name.get(short)?;
        if classes.len() != 1 {
            return None; // ambiguous class name - don't guess
        }
        let class_id = classes[0];
        method_by_parent
            .get(&(class_id, method.to_string()))
            .copied()
            .or(Some(class_id))
    };

    // Group frames: prefix + middleware that apply to every route nested inside
    // Route::prefix('x')->group(fn(){..}) or Route::group(['prefix'=>'x'], ..).
    let frames = find_group_frames(content);

    // --- Route emission (position-based so group prefixes apply) ---

    // Standard verbs: Route::get/post/put/patch/delete/any('/path', handler).
    for caps in route_pattern.captures_iter(content) {
        let whole = caps.get(0).unwrap();
        let method = http_method(caps.get(1).map(|m| m.as_str()).unwrap_or(""));
        let raw_path = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let (prefix, mut middleware) = enclosing_context(&frames, whole.start());
        let path = combine_path(&prefix, raw_path);

        let window = statement_window(content, whole.start());
        middleware.extend(inline_middleware(&inline_mw_pattern, window));
        let controller = resolve_from_window(
            window,
            &controller_ref,
            &controller_at_ref,
            &resolve_controller,
        );

        ir.routes.push(Route {
            method,
            path,
            controller,
            middleware,
            file: file.to_path_buf(),
            line: line_of(content, whole.start()),
        });
    }

    // Route::match(['get','post'], '/path', handler) - one route per verb.
    for caps in match_pattern.captures_iter(content) {
        let whole = caps.get(0).unwrap();
        let verbs = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let raw_path = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let (prefix, mut middleware) = enclosing_context(&frames, whole.start());
        let path = combine_path(&prefix, raw_path);
        let line = line_of(content, whole.start());

        let window = statement_window(content, whole.start());
        middleware.extend(inline_middleware(&inline_mw_pattern, window));
        let controller = resolve_from_window(
            window,
            &controller_ref,
            &controller_at_ref,
            &resolve_controller,
        );

        for verb in verbs.split(',') {
            let verb = verb.trim().trim_matches('\'').trim_matches('"');
            if verb.is_empty() {
                continue;
            }
            ir.routes.push(Route {
                method: http_method(&verb.to_lowercase()),
                path: path.clone(),
                controller,
                middleware: middleware.clone(),
                file: file.to_path_buf(),
                line,
            });
        }
    }

    // Route::resource / Route::apiResource - expand to CRUD routes.
    for caps in resource_pattern.captures_iter(content) {
        let whole = caps.get(0).unwrap();
        let is_api = caps.get(1).map(|m| m.as_str()).unwrap_or("") == "apiResource";
        let name = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let controller = caps.get(3).map(|m| m.as_str()).unwrap_or("");
        let (prefix, mut middleware) = enclosing_context(&frames, whole.start());
        let line = line_of(content, whole.start());

        let window = statement_window(content, whole.start());
        middleware.extend(inline_middleware(&inline_mw_pattern, window));

        let base = name.trim_matches('/').to_string();
        let member = format!("{}/{{{}}}", base, singularize(&base));
        // (verb, sub-path, controller method, excluded from apiResource)
        let actions: [(HttpMethod, String, &str, bool); 7] = [
            (HttpMethod::Get, base.clone(), "index", false),
            (HttpMethod::Get, format!("{}/create", base), "create", true),
            (HttpMethod::Post, base.clone(), "store", false),
            (HttpMethod::Get, member.clone(), "show", false),
            (HttpMethod::Get, format!("{}/edit", member), "edit", true),
            (HttpMethod::Put, member.clone(), "update", false),
            (HttpMethod::Delete, member.clone(), "destroy", false),
        ];

        for (verb, sub, method_name, web_only) in &actions {
            if is_api && *web_only {
                continue;
            }
            ir.routes.push(Route {
                method: verb.clone(),
                path: combine_path(&prefix, sub),
                controller: resolve_controller(controller, method_name),
                middleware: middleware.clone(),
                file: file.to_path_buf(),
                line,
            });
        }
    }

    // --- Call-graph edges (controller references) from a pseudo route symbol ---
    // Kept line-based; covers multi-line route definitions and resource classes.
    let route_file_sym = pseudo_id("routes", file);
    let mut route_file_sym_inserted = false;

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = (line_idx + 1) as u32;
        let ctrl = controller_ref
            .captures(line)
            .or_else(|| controller_at_ref.captures(line))
            .map(|caps| {
                (
                    caps.get(1)
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default(),
                    caps.get(2)
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default(),
                )
            });

        // Register controller references as call-graph edges from a pseudo
        // route-file symbol (covers multi-line route definitions too).
        let mut referenced: Vec<String> = Vec::new();
        if let Some((controller, method)) = &ctrl {
            if !controller.is_empty() {
                referenced.push(controller.clone());
                if let Some(short) = controller.rsplit('\\').next() {
                    referenced.push(short.to_string());
                }
                if !method.is_empty() {
                    referenced.push(format!("{}::{}", controller, method));
                    referenced.push(method.clone());
                }
            }
        }
        if let Some(caps) = resource_pattern.captures(line) {
            if let Some(controller) = caps.get(3) {
                referenced.push(controller.as_str().to_string());
                if let Some(short) = controller.as_str().rsplit('\\').next() {
                    referenced.push(short.to_string());
                }
            }
        }

        if !referenced.is_empty() {
            if !route_file_sym_inserted {
                route_file_sym_inserted = true;
                ir.symbols.entry(route_file_sym).or_insert_with(|| Symbol {
                    id: route_file_sym,
                    name: format!(
                        "routes::{}",
                        file.file_stem().unwrap_or_default().to_string_lossy()
                    ),
                    fully_qualified: format!("routes::{}", file.display()),
                    kind: SymbolKind::Function,
                    visibility: Visibility::Public,
                    file: file.to_path_buf(),
                    line_start: 1,
                    line_end: content.lines().count() as u32,
                    col_start: 0,
                    col_end: 0,
                    language: Language::Php,
                    parent: None,
                    hash: 0,
                    normalized_hash: 0,
                    flow_hash: 0,
                    param_count: 0,
                    is_entry_point: true,
                    doc_comment: None,
                });
            }
            for name in referenced {
                ir.calls.push(Call {
                    caller: route_file_sym,
                    callee: CallTarget::Unresolved(name),
                    file: file.to_path_buf(),
                    line: line_num,
                    col: 0,
                });
            }
        }
    }
}

/// A `->group()` body span with the prefix + middleware it contributes to
/// every route nested inside it. `start`/`end` are byte offsets of the closure
/// body (just inside the braces).
struct GroupFrame {
    start: usize,
    end: usize,
    prefix: String,
    middleware: Vec<String>,
}

fn http_method(verb: &str) -> HttpMethod {
    match verb {
        "post" => HttpMethod::Post,
        "put" => HttpMethod::Put,
        "patch" => HttpMethod::Patch,
        "delete" => HttpMethod::Delete,
        "any" => HttpMethod::Any,
        _ => HttpMethod::Get,
    }
}

/// 1-based line number of a byte offset.
fn line_of(content: &str, byte: usize) -> u32 {
    (content[..byte.min(content.len())]
        .bytes()
        .filter(|&b| b == b'\n')
        .count()
        + 1) as u32
}

/// Naive English singularisation for resource route parameters. The linker
/// reduces `{param}` to `*`, so this only affects the human-readable path.
fn singularize(name: &str) -> String {
    let last = name.rsplit(['/', '.']).next().unwrap_or(name);
    if let Some(stem) = last.strip_suffix("ies") {
        format!("{}y", stem)
    } else if last.ends_with("ss") {
        last.to_string()
    } else if let Some(stem) = last.strip_suffix('s') {
        stem.to_string()
    } else {
        last.to_string()
    }
}

/// Join a group prefix with a route path into a single normalised `/a/b/c`.
fn combine_path(prefix: &str, path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in prefix.split('/').chain(path.split('/')) {
        let t = seg.trim();
        if !t.is_empty() {
            parts.push(t);
        }
    }
    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

/// Text of the statement starting at `start`, up to (and including) the first
/// `;`. Used to scope controller/inline-middleware lookups to one route.
fn statement_window(content: &str, start: usize) -> &str {
    let rest = &content[start..];
    match rest.find(';') {
        Some(i) => &rest[..=i],
        None => rest,
    }
}

/// Parse tokens out of a `->middleware('a')` / `->middleware(['a','b'])` call.
fn inline_middleware(pattern: &regex::Regex, window: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(caps) = pattern.captures(window) {
        let raw = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        for tok in raw
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split(',')
        {
            let tok = tok.trim().trim_matches('\'').trim_matches('"');
            if !tok.is_empty() {
                out.push(tok.to_string());
            }
        }
    }
    out
}

/// Resolve the controller handler referenced within a single route statement.
fn resolve_from_window<F: Fn(&str, &str) -> Option<SymbolId>>(
    window: &str,
    controller_ref: &regex::Regex,
    controller_at_ref: &regex::Regex,
    resolve: &F,
) -> Option<SymbolId> {
    controller_ref
        .captures(window)
        .or_else(|| controller_at_ref.captures(window))
        .and_then(|caps| {
            let c = caps.get(1)?.as_str();
            let m = caps.get(2)?.as_str();
            resolve(c, m)
        })
}

/// Combine the prefix + middleware of every group frame enclosing `pos`,
/// outermost first.
fn enclosing_context(frames: &[GroupFrame], pos: usize) -> (String, Vec<String>) {
    let mut enclosing: Vec<&GroupFrame> = frames
        .iter()
        .filter(|f| f.start <= pos && pos < f.end)
        .collect();
    // Outermost (smallest start / widest span) first - deterministic.
    enclosing.sort_by_key(|f| f.start);

    let mut prefix_parts: Vec<&str> = Vec::new();
    let mut middleware: Vec<String> = Vec::new();
    for f in enclosing {
        let p = f.prefix.trim_matches('/');
        if !p.is_empty() {
            prefix_parts.push(p);
        }
        middleware.extend(f.middleware.iter().cloned());
    }
    (prefix_parts.join("/"), middleware)
}

/// Locate every `->group(...)`/`Route::group(...)` and record the byte span of
/// its closure body plus the prefix/middleware declared for it.
fn find_group_frames(content: &str) -> Vec<GroupFrame> {
    let group_re = regex::Regex::new(r"(?:->|::)group\s*\(").expect("valid regex");
    let prefix_chain_re =
        regex::Regex::new(r#"(?:->|::)prefix\s*\(\s*['"]([^'"]+)['"]"#).expect("valid regex");
    let mw_chain_re = regex::Regex::new(r#"(?:->|::)middleware\s*\(\s*(\[?[^\])]*)\]?\s*\)"#)
        .expect("valid regex");
    let prefix_arr_re =
        regex::Regex::new(r#"['"]prefix['"]\s*=>\s*['"]([^'"]+)['"]"#).expect("valid regex");
    let mw_arr_re = regex::Regex::new(r#"['"]middleware['"]\s*=>\s*(\[[^\]]*\]|['"][^'"]+['"])"#)
        .expect("valid regex");

    let mut frames = Vec::new();
    for m in group_re.find_iter(content) {
        // Chain preceding `->group(` - from the statement's `Route::` to here.
        let chain_start = content[..m.start()].rfind("Route::").unwrap_or(0);
        let chain = &content[chain_start..m.start()];

        let mut prefix = prefix_chain_re
            .captures(chain)
            .and_then(|c| c.get(1))
            .map(|s| s.as_str().to_string())
            .unwrap_or_default();
        let mut middleware = mw_chain_re
            .captures(chain)
            .map(|c| parse_token_list(c.get(1).map(|m| m.as_str()).unwrap_or("")))
            .unwrap_or_default();

        // Array-config form: Route::group(['prefix'=>.., 'middleware'=>..], fn).
        if let Some((astart, aend)) = find_array_span(content, m.end()) {
            let arr = &content[astart..aend];
            if prefix.is_empty() {
                if let Some(c) = prefix_arr_re.captures(arr) {
                    prefix = c.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                }
            }
            if middleware.is_empty() {
                if let Some(c) = mw_arr_re.captures(arr) {
                    middleware = parse_token_list(c.get(1).map(|m| m.as_str()).unwrap_or(""));
                }
            }
        }

        if let Some((start, end)) = find_body_span(content, m.end()) {
            frames.push(GroupFrame {
                start,
                end,
                prefix,
                middleware,
            });
        }
    }
    frames
}

fn parse_token_list(raw: &str) -> Vec<String> {
    raw.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .filter_map(|t| {
            let t = t.trim().trim_matches('\'').trim_matches('"');
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        })
        .collect()
}

/// Given a byte offset just after `group(`, find the closure body - the first
/// top-level `{` (ignoring `[...]` config and quoted strings) and its match.
/// Returns byte offsets just inside the braces.
fn find_body_span(content: &str, from: usize) -> Option<(usize, usize)> {
    let bytes = content.as_bytes();
    let n = bytes.len();

    // Locate the opening brace of the closure body.
    let mut i = from;
    let mut bracket = 0i32;
    let mut quote: Option<u8> = None;
    let mut open = None;
    while i < n {
        let c = bytes[i];
        if let Some(q) = quote {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match c {
            b'\'' | b'"' => quote = Some(c),
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b'{' if bracket == 0 => {
                open = Some(i);
                break;
            }
            _ => {}
        }
        i += 1;
    }
    let open = open?;

    // Brace-match to the closing `}`.
    let mut depth = 0i32;
    let mut j = open;
    let mut quote: Option<u8> = None;
    while j < n {
        let c = bytes[j];
        if let Some(q) = quote {
            if c == b'\\' {
                j += 2;
                continue;
            }
            if c == q {
                quote = None;
            }
            j += 1;
            continue;
        }
        match c {
            b'\'' | b'"' => quote = Some(c),
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((open + 1, j));
                }
            }
            _ => {}
        }
        j += 1;
    }
    None
}

/// Find the first top-level `[...]` starting at/after `from`, returning byte
/// offsets just inside the brackets. Bails at the first `{` (closure body) so
/// only a config array in argument position is considered.
fn find_array_span(content: &str, from: usize) -> Option<(usize, usize)> {
    let bytes = content.as_bytes();
    let n = bytes.len();
    let mut i = from;
    let mut quote: Option<u8> = None;
    let mut open = None;
    while i < n {
        let c = bytes[i];
        if let Some(q) = quote {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match c {
            b'\'' | b'"' => quote = Some(c),
            b'[' => {
                open = Some(i);
                break;
            }
            b'{' => return None,
            _ => {}
        }
        i += 1;
    }
    let open = open?;

    let mut depth = 0i32;
    let mut j = open;
    let mut quote: Option<u8> = None;
    while j < n {
        let c = bytes[j];
        if let Some(q) = quote {
            if c == b'\\' {
                j += 2;
                continue;
            }
            if c == q {
                quote = None;
            }
            j += 1;
            continue;
        }
        match c {
            b'\'' | b'"' => quote = Some(c),
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some((open + 1, j));
                }
            }
            _ => {}
        }
        j += 1;
    }
    None
}

/// Scan Blade templates for references to other views, components, and PHP classes.
///
/// Looks for: @extends, @include, @component, @livewire, @each, and
/// PHP class references like Foo::class or new Foo()
fn scan_blade_templates(root: &Path, ir: &mut Ir) {
    let views_dir = root.join("resources/views");
    if !views_dir.exists() {
        return;
    }

    let extends_re =
        regex::Regex::new(r#"@extends\s*\(\s*['"]([^'"]+)['"]\s*\)"#).expect("valid regex");
    let include_re =
        regex::Regex::new(r#"@include\s*\(\s*['"]([^'"]+)['"]\s*"#).expect("valid regex");
    let component_re =
        regex::Regex::new(r#"@component\s*\(\s*['"]([^'"]+)['"]\s*"#).expect("valid regex");
    let livewire_re =
        regex::Regex::new(r#"@livewire\s*\(\s*['"]([^'"]+)['"]\s*"#).expect("valid regex");
    let each_re = regex::Regex::new(r#"@each\s*\(\s*['"]([^'"]+)['"]\s*"#).expect("valid regex");
    let class_ref_re = regex::Regex::new(r#"([A-Z][A-Za-z0-9_\\]+)::class"#).expect("valid regex");
    let new_ref_re = regex::Regex::new(r#"new\s+([A-Z][A-Za-z0-9_\\]+)"#).expect("valid regex");
    let _route_ref_re =
        regex::Regex::new(r#"route\s*\(\s*['"]([^'"]+)['"]\s*"#).expect("valid regex");

    for entry in walkdir::WalkDir::new(&views_dir)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let path_str = path.to_string_lossy();
        if !path_str.ends_with(".blade.php") {
            continue;
        }

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let line_count = content.lines().count() as u32;
        let size_bytes = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

        let file_id = FileId(crate::stable_hash(path.to_string_lossy().as_ref()));

        ir.files.insert(
            path.to_path_buf(),
            FileInfo {
                id: file_id,
                path: path.to_path_buf(),
                language: Language::Php,
                line_count,
                size_bytes,
                last_modified: 0,
                hash: 0,
                symbols: Vec::new(),
            },
        );

        ir.metadata.total_files += 1;
        ir.metadata.total_lines += line_count as u64;

        let blade_sym_id = pseudo_id("blade", path);
        let blade_name = path
            .strip_prefix(&views_dir)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('/', ".")
            .replace(".blade.php", "");

        ir.symbols.insert(
            blade_sym_id,
            Symbol {
                id: blade_sym_id,
                name: blade_name.clone(),
                fully_qualified: format!("blade::{}", blade_name),
                kind: SymbolKind::Function,
                visibility: Visibility::Public,
                file: path.to_path_buf(),
                line_start: 1,
                line_end: line_count,
                col_start: 0,
                col_end: 0,
                language: Language::Php,
                parent: None,
                hash: 0,
                normalized_hash: 0,
                flow_hash: 0,
                param_count: 0,
                is_entry_point: true, // Blade templates are always entry points
                doc_comment: None,
            },
        );

        for (line_idx, line) in content.lines().enumerate() {
            let line_num = (line_idx + 1) as u32;

            // @extends, @include, @component, @each - register the view name
            for re in &[&extends_re, &include_re, &component_re, &each_re] {
                for caps in re.captures_iter(line) {
                    if let Some(view_name) = caps.get(1) {
                        let view = view_name.as_str().to_string();
                        // Record both the dotted view name and its last segment.
                        ir.calls.push(Call {
                            caller: blade_sym_id,
                            callee: CallTarget::Unresolved(view.clone()),
                            file: path.to_path_buf(),
                            line: line_num,
                            col: 0,
                        });
                        if let Some(last) = view.rsplit('.').next() {
                            ir.calls.push(Call {
                                caller: blade_sym_id,
                                callee: CallTarget::Unresolved(last.to_string()),
                                file: path.to_path_buf(),
                                line: line_num,
                                col: 0,
                            });
                        }
                    }
                }
            }

            for caps in livewire_re.captures_iter(line) {
                if let Some(component) = caps.get(1) {
                    ir.calls.push(Call {
                        caller: blade_sym_id,
                        callee: CallTarget::Unresolved(component.as_str().to_string()),
                        file: path.to_path_buf(),
                        line: line_num,
                        col: 0,
                    });
                }
            }

            for caps in class_ref_re.captures_iter(line) {
                if let Some(class_name) = caps.get(1) {
                    let name = class_name.as_str().to_string();
                    let short = name.rsplit('\\').next().unwrap_or(&name).to_string();
                    ir.calls.push(Call {
                        caller: blade_sym_id,
                        callee: CallTarget::Unresolved(name),
                        file: path.to_path_buf(),
                        line: line_num,
                        col: 0,
                    });
                    ir.calls.push(Call {
                        caller: blade_sym_id,
                        callee: CallTarget::Unresolved(short),
                        file: path.to_path_buf(),
                        line: line_num,
                        col: 0,
                    });
                }
            }

            for caps in new_ref_re.captures_iter(line) {
                if let Some(class_name) = caps.get(1) {
                    let name = class_name.as_str().to_string();
                    let short = name.rsplit('\\').next().unwrap_or(&name).to_string();
                    ir.calls.push(Call {
                        caller: blade_sym_id,
                        callee: CallTarget::Unresolved(name),
                        file: path.to_path_buf(),
                        line: line_num,
                        col: 0,
                    });
                    ir.calls.push(Call {
                        caller: blade_sym_id,
                        callee: CallTarget::Unresolved(short),
                        file: path.to_path_buf(),
                        line: line_num,
                        col: 0,
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use verum_nucleus::Ir;

    fn mk_symbol(id: SymbolId, name: &str, kind: SymbolKind, parent: Option<SymbolId>) -> Symbol {
        Symbol {
            id,
            name: name.to_string(),
            fully_qualified: name.to_string(),
            kind,
            visibility: Visibility::Public,
            file: PathBuf::from("app/Http/Controllers/Controller.php"),
            line_start: 1,
            line_end: 1,
            col_start: 0,
            col_end: 0,
            language: Language::Php,
            parent,
            hash: 0,
            normalized_hash: 0,
            flow_hash: 0,
            param_count: 0,
            is_entry_point: false,
            doc_comment: None,
        }
    }

    /// Insert a controller class plus the given method symbols so that
    /// `resolve_controller` can bind route handlers to real SymbolIds.
    fn add_controller(ir: &mut Ir, next: &mut u64, class: &str, methods: &[&str]) -> SymbolId {
        let cid = SymbolId(*next);
        *next += 1;
        ir.symbols
            .insert(cid, mk_symbol(cid, class, SymbolKind::Class, None));
        for m in methods {
            let mid = SymbolId(*next);
            *next += 1;
            ir.symbols
                .insert(mid, mk_symbol(mid, m, SymbolKind::Method, Some(cid)));
        }
        cid
    }

    fn is_method(m: &HttpMethod, want: &HttpMethod) -> bool {
        std::mem::discriminant(m) == std::mem::discriminant(want)
    }

    #[test]
    fn prefixed_group_route_is_prefixed() {
        let mut ir = Ir::new();
        let mut next = 1u64;
        let cid = add_controller(&mut ir, &mut next, "UserController", &["index"]);
        let content = "<?php\nRoute::prefix('api')->group(function () {\n    Route::get('/users', [UserController::class, 'index']);\n});\n";
        parse_route_file(content, Path::new("routes/api.php"), &mut ir);

        let route = ir
            .routes
            .iter()
            .find(|r| r.path == "/api/users")
            .expect("prefixed route /api/users");
        assert!(is_method(&route.method, &HttpMethod::Get));
        assert!(route.controller.is_some(), "controller should resolve");
        // The resolved handler is a method whose parent is the controller class.
        let handler = ir.symbols.get(&route.controller.unwrap()).unwrap();
        assert_eq!(handler.parent, Some(cid));
        assert_eq!(handler.name, "index");
    }

    #[test]
    fn nested_array_group_applies_prefix_and_middleware() {
        let mut ir = Ir::new();
        let mut next = 1u64;
        add_controller(&mut ir, &mut next, "StatsController", &["show"]);
        let content = "<?php\nRoute::group(['prefix' => 'admin', 'middleware' => ['auth']], function () {\n    Route::prefix('v1')->group(function () {\n        Route::get('/stats', [StatsController::class, 'show']);\n    });\n});\n";
        parse_route_file(content, Path::new("routes/web.php"), &mut ir);

        let route = ir
            .routes
            .iter()
            .find(|r| r.path == "/admin/v1/stats")
            .expect("nested prefixed route /admin/v1/stats");
        assert!(route.controller.is_some());
        assert!(
            route.middleware.iter().any(|m| m == "auth"),
            "group middleware should apply, got {:?}",
            route.middleware
        );
    }

    #[test]
    fn resource_expands_to_seven_routes() {
        let mut ir = Ir::new();
        let mut next = 1u64;
        add_controller(
            &mut ir,
            &mut next,
            "UserController",
            &[
                "index", "create", "store", "show", "edit", "update", "destroy",
            ],
        );
        let content = "<?php\nRoute::resource('users', UserController::class);\n";
        parse_route_file(content, Path::new("routes/web.php"), &mut ir);

        assert_eq!(ir.routes.len(), 7, "resource yields 7 CRUD routes");
        let has = |method: HttpMethod, path: &str| {
            ir.routes
                .iter()
                .any(|r| is_method(&r.method, &method) && r.path == path && r.controller.is_some())
        };
        assert!(has(HttpMethod::Get, "/users"), "index");
        assert!(has(HttpMethod::Get, "/users/create"), "create");
        assert!(has(HttpMethod::Post, "/users"), "store");
        assert!(has(HttpMethod::Get, "/users/{user}"), "show");
        assert!(has(HttpMethod::Get, "/users/{user}/edit"), "edit");
        assert!(has(HttpMethod::Put, "/users/{user}"), "update");
        assert!(has(HttpMethod::Delete, "/users/{user}"), "destroy");
    }

    #[test]
    fn api_resource_expands_to_five_routes() {
        let mut ir = Ir::new();
        let mut next = 1u64;
        add_controller(
            &mut ir,
            &mut next,
            "UserController",
            &["index", "store", "show", "update", "destroy"],
        );
        let content = "<?php\nRoute::apiResource('users', UserController::class);\n";
        parse_route_file(content, Path::new("routes/api.php"), &mut ir);

        assert_eq!(
            ir.routes.len(),
            5,
            "apiResource yields 5 routes (no create/edit)"
        );
        assert!(
            !ir.routes
                .iter()
                .any(|r| r.path.contains("create") || r.path.ends_with("/edit")),
            "apiResource must not include create/edit"
        );
    }

    #[test]
    fn match_and_any_verbs() {
        let mut ir = Ir::new();
        let mut next = 1u64;
        add_controller(&mut ir, &mut next, "FormController", &["handle"]);
        add_controller(&mut ir, &mut next, "HookController", &["handle"]);
        let content = "<?php\nRoute::match(['get', 'post'], '/submit', [FormController::class, 'handle']);\nRoute::any('/webhook', [HookController::class, 'handle']);\n";
        parse_route_file(content, Path::new("routes/api.php"), &mut ir);

        let has = |method: HttpMethod, path: &str| {
            ir.routes
                .iter()
                .any(|r| is_method(&r.method, &method) && r.path == path)
        };
        assert!(has(HttpMethod::Get, "/submit"), "match GET /submit");
        assert!(has(HttpMethod::Post, "/submit"), "match POST /submit");
        assert!(has(HttpMethod::Any, "/webhook"), "any /webhook");
    }

    #[test]
    fn chained_modifiers_do_not_break_path() {
        let mut ir = Ir::new();
        let mut next = 1u64;
        add_controller(&mut ir, &mut next, "DashController", &["index"]);
        let content = "<?php\nRoute::get('/dash', [DashController::class, 'index'])->name('dash')->middleware('auth');\n";
        parse_route_file(content, Path::new("routes/web.php"), &mut ir);

        let route = ir
            .routes
            .iter()
            .find(|r| r.path == "/dash")
            .expect("route /dash");
        assert!(
            route.controller.is_some(),
            "controller resolves despite ->name()/->middleware()"
        );
        assert!(
            route.middleware.iter().any(|m| m == "auth"),
            "inline middleware captured"
        );
    }
}
