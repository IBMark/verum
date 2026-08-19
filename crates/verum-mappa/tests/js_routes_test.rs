//! Node/NestJS backend route extraction and hardened client HTTP-call
//! extraction in the JS/TS frontend (`javascript.rs`).

use std::path::Path;
use verum_nucleus::{HttpMethod, Ir};

fn parse(src: &str, ts: bool) -> Ir {
    let name = if ts { "t.ts" } else { "t.js" };
    verum_mappa::javascript::parse_source(src, Path::new(name), ts, None)
        .expect("should parse JS/TS source")
}

#[test]
fn express_app_get_is_a_route_with_resolved_handler() {
    let ir = parse(
        "function handler(){} const app = express(); app.get('/api/x', handler);",
        false,
    );
    let r = ir
        .routes
        .iter()
        .find(|r| r.path == "/api/x")
        .expect("app.get should register route /api/x");
    assert!(matches!(r.method, HttpMethod::Get));
    let cid = r
        .controller
        .expect("handler identifier resolved to a symbol");
    assert_eq!(ir.symbols.get(&cid).unwrap().name, "handler");
    // A server-side route must not also be recorded as a client HTTP call.
    assert!(ir.http_calls.is_empty(), "route must not be a client call");
}

#[test]
fn express_router_chain_and_use_prefix() {
    let ir = parse(
        "const router = express.Router(); router.route('/z').get(fn); app.use('/prefix', mw);",
        false,
    );
    assert!(
        ir.routes
            .iter()
            .any(|r| r.path == "/z" && matches!(r.method, HttpMethod::Get)),
        "router.route('/z').get(...) should register /z"
    );
    assert!(
        ir.routes
            .iter()
            .any(|r| r.path == "/prefix" && matches!(r.method, HttpMethod::Any)),
        "app.use('/prefix', ...) should register /prefix as Any"
    );
}

#[test]
fn map_get_is_not_a_route() {
    let ir = parse("const m = new Map(); m.get('key'); cache.get('x');", false);
    assert!(
        ir.routes.is_empty(),
        "map.get / cache.get must not be treated as routes"
    );
}

#[test]
fn nest_controller_and_method_decorators() {
    let src = "@Controller('/api') class UsersController { \
               @Get('/x') findAll() { return []; } \
               @Post() create() {} }";
    let ir = parse(src, true);

    let r = ir
        .routes
        .iter()
        .find(|r| r.path == "/api/x")
        .expect("@Get('/x') under @Controller('/api') should be /api/x");
    assert!(matches!(r.method, HttpMethod::Get));
    let cid = r.controller.expect("controller is the decorated method");
    assert_eq!(ir.symbols.get(&cid).unwrap().name, "findAll");

    assert!(
        ir.routes
            .iter()
            .any(|r| r.path == "/api" && matches!(r.method, HttpMethod::Post)),
        "@Post() with no path should inherit the controller base /api"
    );
}

#[test]
fn axios_config_object_form() {
    let ir = parse("axios({ url: '/y', method: 'post' });", false);
    let h = ir
        .http_calls
        .iter()
        .find(|h| h.path == "/y")
        .expect("axios({url}) should record an http_call");
    assert!(
        matches!(h.method, HttpMethod::Post),
        "method should come from the config object"
    );
}

#[test]
fn data_hooks_and_template_literals() {
    let ir = parse(
        "useSWR('/api/swr'); const id = 1; fetch(`/api/users/${id}`);",
        false,
    );
    assert!(
        ir.http_calls.iter().any(|h| h.path == "/api/swr"),
        "useSWR('/api/swr') should record an http_call"
    );
    assert!(
        ir.http_calls
            .iter()
            .any(|h| h.path.starts_with("/api/users/")),
        "template-literal fetch URL should keep its literal prefix"
    );
}

#[test]
fn client_api_get_is_not_reclassified_as_a_route() {
    // Regression guard: `api.get('/x')` is a client call, never a server route.
    let ir = parse("api.get('/users');", false);
    assert!(
        ir.http_calls.iter().any(|h| h.path == "/users"),
        "api.get should stay a client http_call"
    );
    assert!(ir.routes.is_empty(), "api.get must not become a route");
}
