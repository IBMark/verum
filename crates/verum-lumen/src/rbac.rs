use verum_nucleus::{Finding, FindingKind, Ir, Severity};

/// Middleware names that count as auth: Laravel's `auth` guard, Spatie
/// permission/role middleware, and the RawPower-Panel custom aliases.
const AUTH_MIDDLEWARE: &[&str] = &[
    "auth",
    "auth.basic",
    "auth.session",
    "admin",
    "client-api",
    "application-api",
    "daemon",
    "permission",
    "role",
    "can:",
    "verified",
    "signed",
];

/// Matches exactly or as a parameterised form (`auth:sanctum`, `can:edit`) -
/// a bare prefix match would let `administrator` or `authority` count as auth.
fn is_auth_middleware(name: &str) -> bool {
    let lower = name.to_lowercase();
    AUTH_MIDDLEWARE.iter().any(|&m| {
        if let Some(stripped) = m.strip_suffix(':') {
            lower.starts_with(m) || lower == stripped
        } else {
            lower == m || lower.starts_with(&format!("{}:", m))
        }
    })
}

/// Flag routes with no visible auth middleware. Auth-file routes (login,
/// register) are expected to be public, and group-level middleware is resolved
/// via a content scan so routes inside `Route::group(['middleware' => [...]])` or
/// `Route::middleware([...])->group(` don't false-positive.
pub fn analyse(ir: &Ir) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Per route file: line ranges covered by group-level auth middleware.
    let mut file_group_ranges: std::collections::HashMap<std::path::PathBuf, Vec<(u32, u32)>> =
        std::collections::HashMap::new();

    let mut files_with_any_group_auth: std::collections::HashSet<std::path::PathBuf> =
        std::collections::HashSet::new();

    for route in &ir.routes {
        if file_group_ranges.contains_key(&route.file) {
            continue;
        }
        let content = match std::fs::read_to_string(&route.file) {
            Ok(c) => c,
            Err(_) => {
                file_group_ranges.insert(route.file.clone(), Vec::new());
                continue;
            }
        };

        let ranges = extract_group_auth_ranges(&content);
        if !ranges.is_empty() {
            files_with_any_group_auth.insert(route.file.clone());
        }
        file_group_ranges.insert(route.file.clone(), ranges);
    }

    for route in &ir.routes {
        if route.path.is_empty() {
            continue;
        }

        // Middleware extraction is only reliable for Laravel/PHP routes. For
        // Rust/Go/Java/Python frameworks we extract the route but not its
        // middleware/guards, so an empty middleware list is "unknown", not "no
        // auth" - flagging those would report MissingAuthMiddleware on every
        // non-PHP route (a false positive on the whole backend).
        let is_php_route = route
            .controller
            .and_then(|id| ir.symbols.get(&id))
            .map(|s| matches!(s.language, verum_nucleus::Language::Php))
            .unwrap_or_else(|| route.file.extension().and_then(|e| e.to_str()) == Some("php"));
        if !is_php_route {
            continue;
        }

        let has_route_auth = route.middleware.iter().any(|m| is_auth_middleware(m));
        if has_route_auth {
            continue;
        }

        // auth.php holds login/register/reset routes, which are public by design.
        let file_name = route
            .file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if file_name == "auth.php" || file_name == "admin.php" {
            continue;
        }

        // Health / monitoring endpoints are meant to be open.
        let path_lower = route.path.to_lowercase();
        if path_lower.contains("health")
            || path_lower.contains("status")
            || path_lower.contains("ping")
        {
            continue;
        }

        let covered_by_group = if let Some(ranges) = file_group_ranges.get(&route.file) {
            ranges
                .iter()
                .any(|(start, end)| route.line >= *start && route.line <= *end)
        } else {
            false
        };

        if covered_by_group {
            continue;
        }

        findings.push(Finding {
            fingerprint: String::new(),
            id: format!("rbac-noauth-{}-{}", route.method_str(), route.path),
            kind: FindingKind::MissingAuthMiddleware,
            severity: Severity::High,
            confidence: 0.90,
            file: route.file.clone(),
            line_start: route.line,
            line_end: route.line,
            symbol: route.controller,
            message: format!(
                "Route {} {} has no visible auth middleware",
                route.method_str(),
                route.path
            ),
            suggestion: "Verify this route has auth middleware (may be applied at group level)"
                .to_string(),
            auto_fixable: false,
            related: Vec::new(),
        });
    }

    findings
}

/// Find `Route::group(` / `Route::middleware(...)->group(` calls carrying auth
/// middleware and return the line ranges their closures cover.
///
/// Deliberately simple: match the middleware name near the group opener, then
/// brace-count to the closure's closing `}`. Handles both
/// `Route::group(['middleware' => ['auth']], function () { ... })` and
/// `Route::middleware(['auth'])->group(function () { ... })`.
fn extract_group_auth_ranges(content: &str) -> Vec<(u32, u32)> {
    let mut ranges: Vec<(u32, u32)> = Vec::new();

    let lines: Vec<&str> = content.lines().collect();
    let _total_lines = lines.len() as u32;

    let mut i = 0usize;
    while i < lines.len() {
        let line = lines[i];
        let _line_num = (i + 1) as u32;

        let is_group_line = line.contains("Route::group(") || line.contains("->group(");
        if !is_group_line {
            i += 1;
            continue;
        }

        // The options array is often spread over a few lines, so look for a
        // quoted middleware name in a small window from the opener.
        let window_end = (i + 6).min(lines.len());
        let window: String = lines[i..window_end].join("\n");

        // Extract every quoted literal in the window and run it through the
        // same matcher the per-route path uses, so parameterised forms
        // (`'auth:sanctum'`, `'can:edit'`) are recognised as auth groups.
        let has_auth = quoted_tokens(&window)
            .iter()
            .any(|token| is_auth_middleware(token));

        if !has_auth {
            i += 1;
            continue;
        }

        // Walk forward to the closure. The closure's `{` is the first one
        // outside the options array, so track `[`/`]` depth to know when
        // we've left the array.

        let mut bracket_depth: i32 = 0; // [ ] depth (options array)
        let mut brace_depth: i32 = 0; // { } depth (closure body)
        let mut closure_started = false;
        let mut group_start_line: u32 = 0;
        let mut group_end_line: u32 = 0;

        let mut j = i;
        'scan: while j < lines.len() {
            let scan_line = lines[j];
            let scan_line_num = (j + 1) as u32;

            for ch in scan_line.chars() {
                match ch {
                    '[' => bracket_depth += 1,
                    ']' => bracket_depth -= 1,
                    '{' if bracket_depth <= 0 => {
                        brace_depth += 1;
                        if brace_depth == 1 && !closure_started {
                            closure_started = true;
                            group_start_line = scan_line_num;
                        }
                    }
                    '}' if closure_started => {
                        brace_depth -= 1;
                        if brace_depth == 0 {
                            group_end_line = scan_line_num;
                            break 'scan;
                        }
                    }
                    _ => {}
                }
            }
            j += 1;
        }

        if closure_started && group_end_line > group_start_line {
            ranges.push((group_start_line, group_end_line));
            // Skip past this group's interior; the outer range already covers
            // any nested groups.
            i = j + 1;
        } else {
            i += 1;
        }
    }

    ranges
}

/// All `'...'` / `"..."` string literals in `text` (no escape handling - route
/// middleware names never contain quotes).
fn quoted_tokens(text: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\'' || c == b'"' {
            if let Some(end) = text[i + 1..].find(c as char) {
                tokens.push(&text[i + 1..i + 1 + end]);
                i = i + 1 + end + 1;
                continue;
            }
        }
        i += 1;
    }
    tokens
}

trait MethodStr {
    fn method_str(&self) -> &'static str;
}

impl MethodStr for verum_nucleus::Route {
    fn method_str(&self) -> &'static str {
        match &self.method {
            verum_nucleus::HttpMethod::Get => "GET",
            verum_nucleus::HttpMethod::Post => "POST",
            verum_nucleus::HttpMethod::Put => "PUT",
            verum_nucleus::HttpMethod::Patch => "PATCH",
            verum_nucleus::HttpMethod::Delete => "DELETE",
            verum_nucleus::HttpMethod::Any => "ANY",
        }
    }
}
