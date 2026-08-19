//! Cross-language seam-linking: connect a client HTTP call
//! (`fetch('/api/users')`) to the route handler that serves it, so the call
//! graph spans the frontend/backend language boundary. This is what turns
//! *multi-language* analysis (each language in its own silo) into
//! *cross-language* analysis (one graph across the seam).

use verum_nucleus::{Call, CallTarget, HttpCall, HttpMethod, Ir, Route};

/// A path reduced to a comparable pattern: each dynamic segment (`{id}`, `:id`,
/// `${id}`, a bare number) becomes `*`, so `/users/{id}` and `/users/42` match.
///
/// Normalisation performed here (all deterministic):
/// - a leading `?query` / `#fragment` is stripped before segmentation, so
///   `/api/users?page=2` compares equal to `/api/users`;
/// - surrounding slashes are trimmed, so `/api/users/` == `/api/users`;
/// - comparison is otherwise case-sensitive on each path segment.
pub fn path_pattern(path: &str) -> String {
    // Drop any query string or fragment: match on the path only.
    let path = path.split(['?', '#']).next().unwrap_or(path);
    path.trim_matches('/')
        .split('/')
        .map(|seg| {
            let dynamic = seg.starts_with('{')
                || seg.starts_with(':')
                || seg.starts_with("${")
                || seg.contains("${")
                || (!seg.is_empty() && seg.chars().all(|c| c.is_ascii_digit()));
            if dynamic {
                "*"
            } else {
                seg
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

pub fn method_key(m: &HttpMethod) -> &'static str {
    match m {
        HttpMethod::Get => "get",
        HttpMethod::Post => "post",
        HttpMethod::Put => "put",
        HttpMethod::Patch => "patch",
        HttpMethod::Delete => "delete",
        HttpMethod::Any => "any",
    }
}

/// Does a client verb match a route verb? A route (or call) declared `any`
/// matches any concrete verb - this keeps `link()` consistent with the MCP
/// `endpoints_view`, which expands `Any` the same way.
fn method_matches(call_method: &str, route_method: &str) -> bool {
    route_method == call_method || route_method == "any" || call_method == "any"
}

/// Is `seg` an API version segment such as `v1`, `v2`, `v10`?
fn is_version_seg(seg: &str) -> bool {
    seg.len() >= 2 && seg.starts_with('v') && seg[1..].chars().all(|c| c.is_ascii_digit())
}

/// Strip a leading `api` prefix (and an optional `vN` version segment that
/// follows it) from an already-normalised pattern. Returns the remaining
/// segments; if no such prefix is present the pattern is returned unchanged.
///
/// `api/v1/users` -> `users`, `api/users` -> `users`, `orders` -> `orders`.
/// Used only for the *secondary*, lower-confidence match: many frontends
/// hardcode `/api/...` (or `/api/vN/...`) while the backend registers the route
/// without the group prefix.
fn deprefix(pattern: &str) -> &str {
    match pattern.strip_prefix("api/") {
        Some(rest) => match rest.split_once('/') {
            // `api/v1/...` - drop the version segment too.
            Some((first, tail)) if is_version_seg(first) => tail,
            // `api/users` - just the `api` prefix.
            Some(_) => rest,
            // `api/v1` with nothing after - remainder is empty.
            None if is_version_seg(rest) => "",
            None => rest,
        },
        None => pattern,
    }
}

/// How a client call was matched to a route. Exact matches are trustworthy;
/// prefix-tolerant matches are a best-effort fallback and are only ever used
/// when no exact match exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchKind {
    Exact,
    PrefixTolerant,
}

/// Find the route (by index) that serves `call`, if any.
///
/// Two passes, in order, so behaviour is deterministic and false links are
/// avoided:
///  1. **Exact** - verb-compatible and identical normalised path pattern.
///  2. **Prefix-tolerant** (only if no exact match) - verb-compatible and the
///     patterns are identical *after* stripping a leading `api`/`api/vN` prefix
///     from either side. The remaining segments must match exactly and be
///     non-empty, so `/api/users` never links to `/orders`.
fn match_route(call: &HttpCall, routes: &[Route]) -> Option<(usize, MatchKind)> {
    let call_pat = path_pattern(&call.path);
    let call_method = method_key(&call.method);

    // Pass 1: exact.
    if let Some(i) = routes.iter().position(|r| {
        method_matches(call_method, method_key(&r.method)) && path_pattern(&r.path) == call_pat
    }) {
        return Some((i, MatchKind::Exact));
    }

    // Pass 2: prefix-tolerant secondary match.
    let call_dep = deprefix(&call_pat);
    if call_dep.is_empty() {
        return None;
    }
    routes
        .iter()
        .position(|r| {
            if !method_matches(call_method, method_key(&r.method)) {
                return false;
            }
            let route_pat = path_pattern(&r.path);
            let route_dep = deprefix(&route_pat);
            !route_dep.is_empty() && route_dep == call_dep
        })
        .map(|i| (i, MatchKind::PrefixTolerant))
}

/// Promote candidate calls made through a project's own HTTP wrapper. A
/// `request('/x')` call is recorded as a candidate keyed by callee name; if that
/// name is confirmed elsewhere to wrap `fetch`/`axios`, the candidate becomes a
/// real `http_call`. This is what makes client-side linking work on real
/// frontends, which centralize requests behind an `api`/`request` client rather
/// than calling `fetch` at every site.
pub fn promote_wrapper_calls(ir: &mut Ir) {
    if ir.http_call_candidates.is_empty() || ir.http_wrappers.is_empty() {
        return;
    }
    let wrappers: std::collections::HashSet<&str> =
        ir.http_wrappers.iter().map(|s| s.as_str()).collect();
    let promoted: Vec<HttpCall> = ir
        .http_call_candidates
        .iter()
        .filter(|(via, _)| wrappers.contains(via.as_str()))
        .map(|(_, call)| call.clone())
        .collect();
    ir.http_calls.extend(promoted);
}

/// Add a resolved call edge from each client HTTP call to the controller of the
/// route it targets, so downstream graph/taint/impact traversal crosses the
/// language boundary. A route with `method = Any` matches any verb, trailing
/// slashes and query strings are ignored, and an `/api`/`/api/vN` prefix
/// difference is tolerated as a secondary (lower-confidence) match.
pub fn link(ir: &mut Ir) {
    if ir.http_calls.is_empty() || ir.routes.is_empty() {
        return;
    }

    let mut new_edges: Vec<Call> = Vec::new();
    for call in &ir.http_calls {
        if let Some((idx, _kind)) = match_route(call, &ir.routes) {
            if let Some(controller) = ir.routes[idx].controller {
                new_edges.push(Call {
                    caller: call.caller,
                    callee: CallTarget::Resolved(controller),
                    file: call.file.clone(),
                    line: call.line,
                    col: 0,
                });
            }
        }
    }
    ir.calls.extend(new_edges);
}

/// Reconcile client HTTP calls against declared routes, without mutating the IR.
///
/// Returns `(matched, orphan_calls, orphan_routes)`:
/// - `matched`     - number of client calls that resolve to some route;
/// - `orphan_calls`  - client calls hitting a path no route serves (a frontend
///   call to a route that doesn't exist);
/// - `orphan_routes` - routes that no client call reaches (dead endpoints).
///
/// Uses the same two-pass matcher as [`link`], so results agree with the edges
/// `link` would add. Output ordering is stable: orphans follow their source
/// order in `ir.http_calls` / `ir.routes`.
pub fn reconcile(ir: &Ir) -> (usize, Vec<&HttpCall>, Vec<&Route>) {
    let mut matched = 0usize;
    let mut orphan_calls: Vec<&HttpCall> = Vec::new();
    let mut route_hit = vec![false; ir.routes.len()];

    for call in &ir.http_calls {
        match match_route(call, &ir.routes) {
            Some((idx, _kind)) => {
                matched += 1;
                route_hit[idx] = true;
            }
            None => orphan_calls.push(call),
        }
    }

    let orphan_routes: Vec<&Route> = ir
        .routes
        .iter()
        .enumerate()
        .filter(|(i, _)| !route_hit[*i])
        .map(|(_, r)| r)
        .collect();

    (matched, orphan_calls, orphan_routes)
}

/// A resolved cross-language seam: a client HTTP call matched to a backend route.
pub struct Seam<'a> {
    pub call: &'a HttpCall,
    pub route: &'a Route,
}

/// Like [`reconcile`] but also returns the matched client-call ↔ route pairs, so
/// callers can display the actual cross-language seams (not just counts). Uses
/// the same two-pass matcher as [`link`], so the seams shown agree with the
/// edges `link` adds to the call graph.
pub fn reconcile_seams(ir: &Ir) -> (Vec<Seam<'_>>, Vec<&HttpCall>, Vec<&Route>) {
    let mut seams: Vec<Seam<'_>> = Vec::new();
    let mut orphan_calls: Vec<&HttpCall> = Vec::new();
    let mut route_hit = vec![false; ir.routes.len()];

    for call in &ir.http_calls {
        match match_route(call, &ir.routes) {
            Some((idx, _kind)) => {
                route_hit[idx] = true;
                seams.push(Seam {
                    call,
                    route: &ir.routes[idx],
                });
            }
            None => orphan_calls.push(call),
        }
    }

    let orphan_routes: Vec<&Route> = ir
        .routes
        .iter()
        .enumerate()
        .filter(|(i, _)| !route_hit[*i])
        .map(|(_, r)| r)
        .collect();

    (seams, orphan_calls, orphan_routes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use verum_nucleus::{HttpCall, HttpMethod, Ir, Route, SymbolId};

    fn route(method: HttpMethod, path: &str) -> Route {
        Route {
            method,
            path: path.to_string(),
            controller: Some(SymbolId(1)),
            middleware: Vec::new(),
            file: PathBuf::from("routes.php"),
            line: 1,
        }
    }

    fn call(method: HttpMethod, path: &str) -> HttpCall {
        HttpCall {
            method,
            path: path.to_string(),
            caller: SymbolId(2),
            file: PathBuf::from("client.ts"),
            line: 1,
        }
    }

    fn ir_with(routes: Vec<Route>, calls: Vec<HttpCall>) -> Ir {
        Ir {
            routes,
            http_calls: calls,
            ..Default::default()
        }
    }

    #[test]
    fn trailing_slash_matches() {
        let mut ir = ir_with(
            vec![route(HttpMethod::Get, "/api/users")],
            vec![call(HttpMethod::Get, "/api/users/")],
        );
        let (matched, orphan_calls, orphan_routes) = reconcile(&ir);
        assert_eq!(matched, 1, "trailing slash should still match");
        assert!(orphan_calls.is_empty());
        assert!(orphan_routes.is_empty());

        link(&mut ir);
        assert_eq!(ir.calls.len(), 1, "link should add one cross-language edge");
    }

    #[test]
    fn template_dollar_matches_brace() {
        // Client uses a JS template literal `${id}`; route uses `{id}`.
        let ir = ir_with(
            vec![route(HttpMethod::Get, "/api/users/{id}/posts")],
            vec![call(HttpMethod::Get, "/api/users/${id}/posts")],
        );
        let (matched, orphan_calls, _) = reconcile(&ir);
        assert_eq!(matched, 1, "${{id}} template should match {{id}} route");
        assert!(orphan_calls.is_empty());
    }

    #[test]
    fn any_route_matches_get_call() {
        let mut ir = ir_with(
            vec![route(HttpMethod::Any, "/api/things")],
            vec![call(HttpMethod::Get, "/api/things")],
        );
        let (matched, _, orphan_routes) = reconcile(&ir);
        assert_eq!(matched, 1, "Any route should match a GET call");
        assert!(orphan_routes.is_empty());

        link(&mut ir);
        assert_eq!(ir.calls.len(), 1);
    }

    #[test]
    fn version_prefix_secondary_links() {
        // Frontend hardcodes /api/v1/...; backend registers the route bare.
        let mut ir = ir_with(
            vec![route(HttpMethod::Get, "/users")],
            vec![call(HttpMethod::Get, "/api/v1/users")],
        );
        let (matched, orphan_calls, orphan_routes) = reconcile(&ir);
        assert_eq!(matched, 1, "version-prefix difference should still link");
        assert!(orphan_calls.is_empty());
        assert!(orphan_routes.is_empty());

        link(&mut ir);
        assert_eq!(ir.calls.len(), 1);
    }

    #[test]
    fn no_false_link_across_paths() {
        // Different resources must never link, even after prefix stripping.
        let mut ir = ir_with(
            vec![route(HttpMethod::Get, "/orders")],
            vec![call(HttpMethod::Get, "/api/users")],
        );
        let (matched, orphan_calls, orphan_routes) = reconcile(&ir);
        assert_eq!(matched, 0, "/api/users must not link to /orders");
        assert_eq!(orphan_calls.len(), 1);
        assert_eq!(orphan_routes.len(), 1);

        link(&mut ir);
        assert!(
            ir.calls.is_empty(),
            "no cross-language edge should be added"
        );
    }

    #[test]
    fn method_mismatch_is_orphan() {
        // Verb must be compatible: a POST call must not hit a GET route.
        let ir = ir_with(
            vec![route(HttpMethod::Get, "/api/users")],
            vec![call(HttpMethod::Post, "/api/users")],
        );
        let (matched, orphan_calls, orphan_routes) = reconcile(&ir);
        assert_eq!(matched, 0);
        assert_eq!(orphan_calls.len(), 1);
        assert_eq!(orphan_routes.len(), 1);
    }
}
