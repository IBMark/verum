//! Spring / JAX-RS route extraction for Java. Reads method annotations
//! (`@GetMapping("/x")`, `@RequestMapping`, JAX-RS `@Path`+`@GET`) and adds
//! `Route`s so the cross-language linker can connect frontend calls to Java
//! handlers. Runs as a post-pass over already-parsed Java symbols.
//!
//! ## Where annotations come from
//!
//! The Java frontend (`java.rs`) is expected to stash each symbol's annotation
//! text in its `doc_comment` field (e.g. `Some("@GetMapping(\"/users/{id}\")")`).
//! That work may land after this pass, so `extract_routes` is tolerant: when a
//! symbol's `doc_comment` carries no `@`-annotation, it falls back to re-reading
//! the source file and scanning the lines directly above the declaration for
//! annotations - the same shape of source read that `laravel.rs` performs on
//! route files. Both paths feed the identical annotation parser below.

use std::collections::HashMap;
use std::path::PathBuf;

use verum_nucleus::{HttpMethod, Ir, Language, Route, Symbol, SymbolId, SymbolKind};

/// Extract Spring/JAX-RS routes from Java symbols into `ir.routes`.
///
/// Post-pass over the already-merged IR: for every Java method carrying a route
/// annotation, emit a `Route` whose `controller` is that method's `SymbolId`,
/// resolving the class-level base-path prefix (`@RequestMapping` / `@Path`) via
/// the method's parent class symbol.
pub fn extract_routes(ir: &mut Ir) {
    // Deterministic iteration: sort Java method symbols by (file, line, name).
    let mut methods: Vec<(SymbolId, SymbolId)> = Vec::new(); // (method_id, parent_class_id)
    {
        let mut ordered: Vec<(&SymbolId, &Symbol)> = ir
            .symbols
            .iter()
            .filter(|(_, s)| {
                s.language == Language::Java
                    && matches!(s.kind, SymbolKind::Method | SymbolKind::StaticMethod)
            })
            .collect();
        ordered.sort_by(|a, b| {
            (&a.1.file, a.1.line_start, &a.1.name).cmp(&(&b.1.file, b.1.line_start, &b.1.name))
        });
        for (id, sym) in ordered {
            if let Some(parent) = sym.parent {
                methods.push((*id, parent));
            }
        }
    }

    // Cache per-file source line reads so the fallback scan reads each file once.
    let mut file_cache: HashMap<PathBuf, Option<Vec<String>>> = HashMap::new();
    // Cache resolved class base paths so a controller file is scanned once.
    let mut base_cache: HashMap<SymbolId, String> = HashMap::new();

    let mut new_routes: Vec<Route> = Vec::new();

    for (method_id, parent_id) in methods {
        let sym = match ir.symbols.get(&method_id) {
            Some(s) => s,
            None => continue,
        };
        let anns = annotation_text(sym, &mut file_cache);
        let (method, sub_path) = match parse_method_route(&anns) {
            Some(r) => r,
            None => continue,
        };

        // Resolve class-level base prefix from the parent class annotations.
        let base = if let Some(b) = base_cache.get(&parent_id) {
            b.clone()
        } else {
            let b = ir
                .symbols
                .get(&parent_id)
                .map(|p| class_base_path(p, &mut file_cache))
                .unwrap_or_default();
            base_cache.insert(parent_id, b.clone());
            b
        };

        let path = join_paths(&base, &sub_path);
        let (file, line) = {
            let s = ir.symbols.get(&method_id).unwrap();
            (s.file.clone(), s.line_start)
        };

        new_routes.push(Route {
            method,
            path,
            controller: Some(method_id),
            middleware: Vec::new(),
            file,
            line,
        });
    }

    ir.routes.extend(new_routes);
}

/// Resolve the annotation text for a symbol: prefer the parser-provided
/// `doc_comment` (the fast path), fall back to scanning the source lines above
/// the declaration, for when `java.rs` hasn't populated `doc_comment` yet.
fn annotation_text(sym: &Symbol, file_cache: &mut HashMap<PathBuf, Option<Vec<String>>>) -> String {
    if let Some(dc) = &sym.doc_comment {
        if dc.contains('@') {
            return dc.clone();
        }
    }
    scan_annotations_above(sym, file_cache)
}

/// Read the source file (cached) and gather the contiguous block of annotation
/// lines around `sym.line_start`. Tree-sitter reports a declaration's start at
/// its first modifier, so `line_start` may point *at* the first annotation
/// (Spring/JAX-RS) or at the declaration keyword when annotations sit above it.
/// This scans both directions:
///   * upward from the declaration, collecting annotation-context lines, until a
///     blank line or a statement/block boundary (`;`, `{`, `}`) that is not
///     itself an annotation - so a preceding member's tail is never swept in;
///   * downward from the declaration, extending across further `@`-annotation
///     lines and unclosed annotation parentheses, until the signature line - so
///     a multi-annotation block like `@GET` + `@Path("/x")` is captured whole.
fn scan_annotations_above(
    sym: &Symbol,
    file_cache: &mut HashMap<PathBuf, Option<Vec<String>>>,
) -> String {
    let lines = file_cache.entry(sym.file.clone()).or_insert_with(|| {
        std::fs::read_to_string(&sym.file)
            .ok()
            .map(|c| c.lines().map(|l| l.to_string()).collect())
    });
    let lines = match lines {
        Some(l) => l,
        None => return String::new(),
    };

    // line_start is 1-indexed; the declaration sits at index line_start - 1.
    let decl_idx = (sym.line_start as usize).saturating_sub(1);
    if decl_idx >= lines.len() {
        return String::new();
    }

    // Upward scan: find the first line of the annotation block above decl_idx.
    let mut start = decl_idx;
    let mut i = decl_idx;
    while i > 0 {
        i -= 1;
        let trimmed = lines[i].trim();
        if trimmed.is_empty() {
            break;
        }
        let is_annotation_line = trimmed.starts_with('@');
        let ends_boundary =
            trimmed.ends_with(';') || trimmed.ends_with('{') || trimmed.ends_with('}');
        if ends_boundary && !is_annotation_line {
            break;
        }
        start = i;
    }

    // Downward scan: extend across additional annotation lines and unclosed
    // annotation parentheses, stopping at the signature line.
    let mut depth: i32 = 0; // cumulative across multi-line annotations
    let mut j = decl_idx;
    let end = loop {
        for c in lines[j].chars() {
            match c {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
        }
        if j + 1 >= lines.len() {
            break j;
        }
        let next = lines[j + 1].trim();
        if depth > 0 || next.starts_with('@') {
            j += 1;
            continue;
        }
        break j;
    };

    lines[start..=end].join("\n")
}

/// Determine the class-level base path from a class symbol's annotations:
/// Spring `@RequestMapping(...)` or JAX-RS `@Path(...)`. `@RestController` /
/// `@Controller` alone contribute no prefix.
fn class_base_path(sym: &Symbol, file_cache: &mut HashMap<PathBuf, Option<Vec<String>>>) -> String {
    let anns = annotation_text(sym, file_cache);
    if let Some(args) = annotation_args(&anns, "RequestMapping") {
        if let Some(p) = extract_path_arg(&args) {
            return p;
        }
    }
    if let Some(args) = annotation_args(&anns, "Path") {
        if let Some(p) = extract_path_arg(&args) {
            return p;
        }
    }
    String::new()
}

/// Parse a method's annotations into `(HttpMethod, sub_path)` if it maps a
/// route. Handles Spring `@GetMapping`/`@PostMapping`/... and `@RequestMapping`,
/// then JAX-RS verb annotations (`@GET`/`@POST`/...) paired with `@Path`.
fn parse_method_route(anns: &str) -> Option<(HttpMethod, String)> {
    // Spring shorthand mappings.
    const SPRING: &[(&str, HttpMethod)] = &[
        ("GetMapping", HttpMethod::Get),
        ("PostMapping", HttpMethod::Post),
        ("PutMapping", HttpMethod::Put),
        ("PatchMapping", HttpMethod::Patch),
        ("DeleteMapping", HttpMethod::Delete),
    ];
    for (name, method) in SPRING {
        if let Some(args) = annotation_args(anns, name) {
            let path = extract_path_arg(&args).unwrap_or_default();
            return Some((method.clone(), path));
        }
    }

    // Spring @RequestMapping(value=..., method=RequestMethod.X).
    if let Some(args) = annotation_args(anns, "RequestMapping") {
        let path = extract_path_arg(&args).unwrap_or_default();
        let method = extract_request_method(&args).unwrap_or(HttpMethod::Any);
        return Some((method, path));
    }

    // JAX-RS: verb annotation + optional @Path("/sub").
    const JAXRS: &[(&str, HttpMethod)] = &[
        ("GET", HttpMethod::Get),
        ("POST", HttpMethod::Post),
        ("PUT", HttpMethod::Put),
        ("PATCH", HttpMethod::Patch),
        ("DELETE", HttpMethod::Delete),
    ];
    for (name, method) in JAXRS {
        if has_bare_annotation(anns, name) {
            let path = annotation_args(anns, "Path")
                .and_then(|a| extract_path_arg(&a))
                .unwrap_or_default();
            return Some((method.clone(), path));
        }
    }

    None
}

/// Find `@Name(...)` and return the argument string inside the parentheses
/// (balanced), or `Some("")` when the annotation appears with no parentheses.
/// Returns `None` when the annotation is absent. Enforces a word boundary so
/// `@GetMapping` is not matched by a request for `@Get`.
fn annotation_args(anns: &str, name: &str) -> Option<String> {
    let bytes = anns.as_bytes();
    let needle = format!("@{}", name);
    let mut search_from = 0;
    while let Some(rel) = anns[search_from..].find(&needle) {
        let at = search_from + rel;
        let after = at + needle.len();
        search_from = after;
        // Word-boundary check: the char after the name must not be alphanumeric
        // or `_` (so `@Get` does not match inside `@GetMapping`).
        if let Some(&c) = bytes.get(after) {
            if (c as char).is_ascii_alphanumeric() || c == b'_' {
                continue;
            }
        }
        // Skip whitespace to find an opening paren, if any.
        let mut j = after;
        while j < bytes.len() && (bytes[j] as char).is_whitespace() {
            j += 1;
        }
        if j < bytes.len() && bytes[j] == b'(' {
            // Capture until the matching close paren (respecting nesting).
            let mut depth = 0i32;
            let start = j + 1;
            let mut k = j;
            while k < bytes.len() {
                match bytes[k] {
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(anns[start..k].to_string());
                        }
                    }
                    _ => {}
                }
                k += 1;
            }
            // Unbalanced - return the remainder.
            return Some(anns[start..].to_string());
        }
        // Annotation present but no parentheses.
        return Some(String::new());
    }
    None
}

/// True when `@Name` appears as a bare marker annotation (word-bounded),
/// regardless of following parentheses. Used for JAX-RS verb markers.
fn has_bare_annotation(anns: &str, name: &str) -> bool {
    annotation_args(anns, name).is_some()
}

/// Extract the path string from annotation args: prefer explicit `value = "..."`
/// or `path = "..."`, otherwise the first bare string literal.
fn extract_path_arg(args: &str) -> Option<String> {
    for key in ["value", "path"] {
        if let Some(v) = named_string(args, key) {
            return Some(v);
        }
    }
    first_string_literal(args)
}

/// Find `key = "value"` (or `key = {"value", ...}`) and return the first literal.
fn named_string(args: &str, key: &str) -> Option<String> {
    let bytes = args.as_bytes();
    let mut from = 0;
    while let Some(rel) = args[from..].find(key) {
        let at = from + rel;
        from = at + key.len();
        // Word boundary before the key.
        if at > 0 {
            let prev = bytes[at - 1] as char;
            if prev.is_ascii_alphanumeric() || prev == '_' {
                continue;
            }
        }
        // Expect optional whitespace then '='.
        let mut j = at + key.len();
        while j < bytes.len() && (bytes[j] as char).is_whitespace() {
            j += 1;
        }
        if j < bytes.len() && bytes[j] == b'=' {
            return first_string_literal(&args[j + 1..]);
        }
    }
    None
}

/// Return the first `"..."` string literal in `s`.
fn first_string_literal(s: &str) -> Option<String> {
    let start = s.find('"')? + 1;
    let rest = &s[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Parse `method = RequestMethod.GET` (or an array form; first verb wins).
fn extract_request_method(args: &str) -> Option<HttpMethod> {
    let idx = args.find("RequestMethod.")?;
    let after = &args[idx + "RequestMethod.".len()..];
    let verb: String = after
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect();
    match verb.as_str() {
        "GET" => Some(HttpMethod::Get),
        "POST" => Some(HttpMethod::Post),
        "PUT" => Some(HttpMethod::Put),
        "PATCH" => Some(HttpMethod::Patch),
        "DELETE" => Some(HttpMethod::Delete),
        _ => Some(HttpMethod::Any),
    }
}

/// Join a class base path and a method sub path into a single normalized route
/// path: ensure exactly one leading slash and collapse duplicate slashes.
fn join_paths(base: &str, sub: &str) -> String {
    let mut combined = String::new();
    combined.push('/');
    combined.push_str(base.trim_matches('/'));
    let sub_trimmed = sub.trim_matches('/');
    if !sub_trimmed.is_empty() {
        if !combined.ends_with('/') {
            combined.push('/');
        }
        combined.push_str(sub_trimmed);
    }
    collapse_slashes(&combined)
}

/// Collapse runs of `/` into a single `/`, preserving a single leading slash.
fn collapse_slashes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_slash = false;
    for c in s.chars() {
        if c == '/' {
            if !prev_slash {
                out.push('/');
            }
            prev_slash = true;
        } else {
            out.push(c);
            prev_slash = false;
        }
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_spring_get_mapping() {
        let (m, p) = parse_method_route(r#"@GetMapping("/users/{id}")"#).unwrap();
        assert!(matches!(m, HttpMethod::Get));
        assert_eq!(p, "/users/{id}");
    }

    #[test]
    fn parses_request_mapping_with_method_and_value() {
        let anns = r#"@RequestMapping(value = "/orders", method = RequestMethod.POST)"#;
        let (m, p) = parse_method_route(anns).unwrap();
        assert!(matches!(m, HttpMethod::Post));
        assert_eq!(p, "/orders");
    }

    #[test]
    fn request_mapping_without_method_is_any() {
        let (m, p) = parse_method_route(r#"@RequestMapping("/x")"#).unwrap();
        assert!(matches!(m, HttpMethod::Any));
        assert_eq!(p, "/x");
    }

    #[test]
    fn parses_jaxrs_verb_plus_path() {
        let anns = "@GET\n@Path(\"/sub\")";
        let (m, p) = parse_method_route(anns).unwrap();
        assert!(matches!(m, HttpMethod::Get));
        assert_eq!(p, "/sub");
    }

    #[test]
    fn get_mapping_not_matched_as_bare_get() {
        // `@GetMapping` must not be mistaken for a JAX-RS `@GET`.
        assert!(!has_bare_annotation("@GetMapping(\"/x\")", "GET"));
        assert!(has_bare_annotation("@GET\n@Path(\"/x\")", "GET"));
    }

    #[test]
    fn joins_and_normalizes_paths() {
        assert_eq!(join_paths("/api", "/users/{id}"), "/api/users/{id}");
        assert_eq!(join_paths("api/", "/x"), "/api/x");
        assert_eq!(join_paths("/api/", "//x//"), "/api/x");
        assert_eq!(join_paths("", "/x"), "/x");
        assert_eq!(join_paths("/base", ""), "/base");
        assert_eq!(join_paths("", ""), "/");
    }

    #[test]
    fn source_scan_fallback_reads_multiline_and_multi_annotation() {
        use verum_nucleus::{Symbol, SymbolKind, Visibility};

        // Write a temp Java file whose method carries JAX-RS annotations on
        // separate lines and a class with a base @Path - the layout tree-sitter
        // reports with line_start pointing *at* the first annotation.
        let mut path = std::env::temp_dir();
        path.push(format!(
            "verum_java_web_fallback_{}.java",
            std::process::id()
        ));
        let src = "package com.example;\n\
                   \n\
                   @Path(\"/products\")\n\
                   public class ProductResource {\n\
                   \n\
                   @GET\n\
                   @Path(\"/{sku}\")\n\
                   public Product get(String sku) {\n\
                   return repo.find(sku);\n\
                   }\n\
                   }\n";
        std::fs::write(&path, src).unwrap();

        let mk = |name: &str, kind: SymbolKind, line: u32| Symbol {
            id: SymbolId(0),
            name: name.to_string(),
            fully_qualified: name.to_string(),
            kind,
            visibility: Visibility::Public,
            file: path.clone(),
            line_start: line,
            line_end: line,
            col_start: 0,
            col_end: 0,
            language: Language::Java,
            parent: None,
            hash: 0,
            normalized_hash: 0,
            flow_hash: 0,
            param_count: 0,
            is_entry_point: false,
            doc_comment: None, // force the fallback
        };

        let mut cache = HashMap::new();
        // Method symbol: line_start at the `@GET` line (index 6, 1-based).
        let method_sym = mk("get", SymbolKind::Method, 6);
        let anns = annotation_text(&method_sym, &mut cache);
        let (m, sub) = parse_method_route(&anns).expect("route from fallback");
        assert!(matches!(m, HttpMethod::Get));
        assert_eq!(sub, "/{sku}");

        // Class symbol: line_start at the `@Path("/products")` line (line 3).
        let class_sym = mk("ProductResource", SymbolKind::Class, 3);
        let base = class_base_path(&class_sym, &mut cache);
        assert_eq!(base, "/products");
        assert_eq!(join_paths(&base, &sub), "/products/{sku}");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn extract_path_prefers_named_value() {
        assert_eq!(
            extract_path_arg(r#"value = "/a", method = RequestMethod.GET"#).unwrap(),
            "/a"
        );
        assert_eq!(extract_path_arg(r#""/b""#).unwrap(), "/b");
        assert_eq!(extract_path_arg(r#"path = "/c""#).unwrap(), "/c");
    }
}
