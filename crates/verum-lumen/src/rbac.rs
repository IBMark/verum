use verum_nucleus::{Finding, FindingKind, Ir, Language, Route, Severity, SymbolKind};

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

/// Python guard names that count as auth, compared lowercase: Flask-Login /
/// Flask-JWT-Extended / Flask-Security decorators, Django auth decorators, DRF
/// permission classes, and the canonical FastAPI auth dependencies.
/// `jwt_optional` is included on purpose - optional auth is a deliberate
/// access decision, not an omission.
const PYTHON_AUTH_GUARDS: &[&str] = &[
    "login_required",
    "auth_required",
    "auth_token_required",
    "jwt_required",
    "fresh_jwt_required",
    "jwt_optional",
    "roles_required",
    "roles_accepted",
    "permission_required",
    "permissions_required",
    "staff_member_required",
    "user_passes_test",
    "isauthenticated",
    "isadminuser",
    "isauthenticatedorreadonly",
    "djangomodelpermissions",
    "djangoobjectpermissions",
    "get_current_user",
    "get_current_active_user",
    "oauth2_scheme",
];

/// FastAPI guards are plain functions named by their author (`require_auth`,
/// `verify_jwt`, `check_login`), so no exact list can cover them. Match on
/// full word components only: `auth` the component matches `require_auth` but
/// never `author` or `authority`. A false "is auth" here can only silence a
/// finding or count as project-level auth evidence, so the component set stays
/// deliberately small.
fn has_auth_component(lower: &str) -> bool {
    lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|part| {
            matches!(
                part,
                "auth" | "jwt" | "login" | "authenticated" | "authorized"
            ) || part.starts_with("oauth")
        })
}

/// Matches exactly or as a parameterised form (`auth:sanctum`, `can:edit`) -
/// a bare prefix match would let `administrator` or `authority` count as auth.
/// Python guard names match by the exact list or by auth word component.
fn is_auth_middleware(name: &str) -> bool {
    let lower = name.to_lowercase();
    let laravel = AUTH_MIDDLEWARE.iter().any(|&m| {
        if let Some(stripped) = m.strip_suffix(':') {
            lower.starts_with(m) || lower == stripped
        } else {
            lower == m || lower.starts_with(&format!("{}:", m))
        }
    });
    laravel || PYTHON_AUTH_GUARDS.contains(&lower.as_str()) || has_auth_component(&lower)
}

/// Whether a route belongs to a language: resolved via the controller symbol
/// when present, else via the route file's extension - route files can
/// declare routes for controllers that live elsewhere.
fn route_is_lang(route: &Route, ir: &Ir, lang: Language, ext: &str) -> bool {
    route
        .controller
        .and_then(|id| ir.symbols.get(&id))
        .map(|s| s.language == lang)
        .unwrap_or_else(|| route.file.extension().and_then(|e| e.to_str()) == Some(ext))
}

/// Python endpoints that are public by design - the auth/session lifecycle
/// itself, generated API docs, and metrics scrapes. Path-substring based, so
/// it errs toward silence (`/tokens` management APIs are skipped too) - a
/// miss here is cheaper than flagging every login form.
const PYTHON_PUBLIC_PATH_MARKERS: &[&str] = &[
    "login", "logout", "register", "signup", "sign-up", "signin", "sign-in", "token", "oauth",
    "password", "webhook", "callback", "docs", "openapi", "metrics", "favicon",
];

/// App-level middleware hooks in a Python route file: auth applied in
/// `@app.before_request` or any middleware registration covers every route
/// while staying invisible to per-route guard extraction, so a file that
/// wires either keeps its routes out of the finding set. The bare
/// "middleware" substring is intentionally broad - it only ever suppresses.
fn python_app_level_hooks(content: &str) -> bool {
    content.contains("before_request") || content.contains("middleware")
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

    // Per Python route file: whether app-level middleware hooks are wired.
    let mut python_file_app_hooks: std::collections::HashMap<std::path::PathBuf, bool> =
        std::collections::HashMap::new();

    for route in &ir.routes {
        if route_is_lang(route, ir, Language::Python, "py") {
            if !python_file_app_hooks.contains_key(&route.file) {
                let has_hooks = std::fs::read_to_string(&route.file)
                    .map(|c| python_app_level_hooks(&c))
                    .unwrap_or(false);
                python_file_app_hooks.insert(route.file.clone(), has_hooks);
            }
            continue;
        }
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

    // A Python route with empty middleware means "no guard declared where we
    // can see it", which is only evidence in a project that declares route
    // guards at all. A project with zero auth anywhere may sit behind a
    // gateway or service mesh that terminates auth before the app - staying
    // silent there is the deliberate trade, false positives cost more than
    // misses.
    let python_project_uses_auth = ir.routes.iter().any(|r| {
        route_is_lang(r, ir, Language::Python, "py")
            && r.middleware.iter().any(|m| is_auth_middleware(m))
    });

    for route in &ir.routes {
        if route.path.is_empty() {
            continue;
        }

        if route.middleware.iter().any(|m| is_auth_middleware(m)) {
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

        // Middleware extraction is reliable for Laravel/PHP routes and for
        // Python routes declared as a decorator on their own handler. For
        // everything else - Rust/Go/Java frameworks, Django urls.py entries,
        // DRF registrations, aiohttp tables, Tornado handler lists - we
        // extract the route but the guards may live in another file, so an
        // empty middleware list there is "unknown", not "no auth"; flagging
        // it would report MissingAuthMiddleware on the whole backend.
        let is_php_route = route
            .controller
            .and_then(|id| ir.symbols.get(&id))
            .map(|s| matches!(s.language, Language::Php))
            .unwrap_or_else(|| route.file.extension().and_then(|e| e.to_str()) == Some("php"));

        let confidence = if is_php_route {
            // auth.php holds login/register/reset routes, public by design.
            let file_name = route
                .file
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            if file_name == "auth.php" || file_name == "admin.php" {
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
            0.90
        } else if route_is_lang(route, ir, Language::Python, "py") {
            if !python_project_uses_auth {
                continue;
            }
            if PYTHON_PUBLIC_PATH_MARKERS
                .iter()
                .any(|m| path_lower.contains(m))
            {
                continue;
            }
            // An explicitly-public declaration (DRF's AllowAny) is a
            // decision, not an omission.
            if route
                .middleware
                .iter()
                .any(|m| m.eq_ignore_ascii_case("allowany"))
            {
                continue;
            }
            // Only decorator-declared routes (Flask/FastAPI/Sanic) have
            // their full guard stack visible: the route and its handler
            // share a definition site, so route.line equals the handler's
            // first line. Any other shape keeps its "unknown" status.
            let decorator_declared = route
                .controller
                .and_then(|id| ir.symbols.get(&id))
                .is_some_and(|s| {
                    matches!(s.kind, SymbolKind::Function | SymbolKind::Method)
                        && route.line == s.line_start
                });
            if !decorator_declared {
                continue;
            }
            // App-level hooks (`before_request`, middleware registration) in
            // the same file may auth-gate every route; extraction cannot see
            // inside them, so the whole file stays quiet.
            if python_file_app_hooks
                .get(&route.file)
                .copied()
                .unwrap_or(false)
            {
                continue;
            }
            // Lower than the PHP path: ASGI/WSGI middleware wired in another
            // module can still be guarding this route.
            0.80
        } else {
            continue;
        };

        findings.push(Finding {
            fingerprint: String::new(),
            id: format!("rbac-noauth-{}-{}", route.method_str(), route.path),
            kind: FindingKind::MissingAuthMiddleware,
            severity: Severity::High,
            confidence,
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
