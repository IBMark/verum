use std::io::Write;

use verum_nucleus::HttpMethod;

/// Write `source` to a uniquely-named temp `.go` file and parse it.
fn parse_go(name: &str, source: &str) -> verum_nucleus::Ir {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "verum_go_endpoints_{}_{}.go",
        name,
        std::process::id()
    ));
    {
        let mut f = std::fs::File::create(&path).expect("create temp file");
        f.write_all(source.as_bytes()).expect("write temp file");
    }
    let ir = verum_mappa::go_lang::parse_file(&path).expect("parse go");
    let _ = std::fs::remove_file(&path);
    ir
}

#[test]
fn gin_verb_registers_route() {
    let source = r#"
package main

func RegisterRoutes(r *gin.Engine) {
    r.GET("/api/x", handleX)
}

func handleX(c *gin.Context) {}
"#;

    let ir = parse_go("gin_verb", source);

    let route = ir
        .routes
        .iter()
        .find(|r| r.path == "/api/x")
        .expect("gin r.GET should register /api/x route");
    assert!(
        matches!(route.method, HttpMethod::Get),
        "route method should be GET, got {:?}",
        route.method
    );
    // Controller resolves to the handleX handler symbol.
    let controller = route.controller.expect("route should have a controller");
    let handler = ir.symbols.get(&controller).expect("controller symbol");
    assert_eq!(handler.name, "handleX");
}

#[test]
fn nethttp_handlefunc_registers_any_route() {
    let source = r#"
package main

func main() {
    http.HandleFunc("/y", handleY)
}

func handleY(w http.ResponseWriter, req *http.Request) {}
"#;

    let ir = parse_go("nethttp_handle", source);

    let route = ir
        .routes
        .iter()
        .find(|r| r.path == "/y")
        .expect("http.HandleFunc should register /y route");
    assert!(
        matches!(route.method, HttpMethod::Any),
        "net/http route method should be Any, got {:?}",
        route.method
    );
}

#[test]
fn nethttp_client_get_is_http_call() {
    let source = r#"
package main

func fetchThing() {
    http.Get("http://h/api/x")
}
"#;

    let ir = parse_go("nethttp_client", source);

    let call = ir
        .http_calls
        .iter()
        .find(|c| c.path == "/api/x")
        .expect("http.Get should record an http_call for /api/x");
    assert!(
        matches!(call.method, HttpMethod::Get),
        "http.Get method should be GET, got {:?}",
        call.method
    );
    // And it must NOT be misclassified as a route.
    assert!(
        !ir.routes.iter().any(|r| r.path == "/api/x"),
        "client http.Get must not be recorded as a route"
    );
    // caller resolves to the enclosing function.
    let caller = ir.symbols.get(&call.caller).expect("caller symbol");
    assert_eq!(caller.name, "fetchThing");
}

#[test]
fn chi_lowercase_verb_with_router_receiver_is_route() {
    let source = r#"
package main

func routes(r chi.Router) {
    r.Get("/things", listThings)
    r.Post("/things", createThing)
}

func listThings(w http.ResponseWriter, req *http.Request) {}
func createThing(w http.ResponseWriter, req *http.Request) {}
"#;

    let ir = parse_go("chi_router", source);

    let get = ir
        .routes
        .iter()
        .find(|r| r.path == "/things" && matches!(r.method, HttpMethod::Get))
        .expect("chi r.Get should register /things GET route");
    assert!(get.controller.is_some(), "chi route should resolve handler");

    assert!(
        ir.routes
            .iter()
            .any(|r| r.path == "/things" && matches!(r.method, HttpMethod::Post)),
        "chi r.Post should register /things POST route"
    );
}

#[test]
fn gin_group_prefix_is_applied() {
    let source = r#"
package main

func setup(r *gin.Engine) {
    api := r.Group("/api")
    api.GET("/users", listUsers)
}

func listUsers(c *gin.Context) {}
"#;

    let ir = parse_go("gin_group", source);

    assert!(
        ir.routes.iter().any(|r| r.path == "/api/users"),
        "group prefix should combine into /api/users, got {:?}",
        ir.routes.iter().map(|r| &r.path).collect::<Vec<_>>()
    );
}

#[test]
fn resty_chained_client_is_http_call() {
    let source = r#"
package main

func call() {
    client.R().Get("http://h/api/z")
}
"#;

    let ir = parse_go("resty_client", source);

    assert!(
        ir.http_calls.iter().any(|c| c.path == "/api/z"),
        "resty client.R().Get should record an http_call for /api/z"
    );
}
