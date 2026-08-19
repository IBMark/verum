use std::io::Write;

use verum_nucleus::HttpMethod;

/// Write `source` to a uniquely-named temp `.rs` file and parse it.
fn parse_rust(name: &str, source: &str) -> verum_nucleus::Ir {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "verum_rust_routes_{}_{}.rs",
        name,
        std::process::id()
    ));
    {
        let mut f = std::fs::File::create(&path).expect("create temp file");
        f.write_all(source.as_bytes()).expect("write temp file");
    }
    let ir = verum_mappa::rust_lang::parse_file(&path).expect("parse rust");
    let _ = std::fs::remove_file(&path);
    ir
}

#[test]
fn extracts_attribute_route_and_reqwest_call() {
    let source = r#"
use actix_web::get;

#[get("/api/users/{id}")]
async fn get_user(id: u32) -> String {
    format!("user {}", id)
}

async fn health_probe() -> bool {
    let resp = reqwest::get("/api/health").await;
    resp.is_ok()
}
"#;

    let ir = parse_rust("attr_and_client", source);

    // Attribute route: #[get("/api/users/{id}")] on get_user.
    let route = ir
        .routes
        .iter()
        .find(|r| r.path == "/api/users/{id}")
        .expect("route for /api/users/{id} should be extracted");
    assert!(
        matches!(route.method, HttpMethod::Get),
        "route method should be GET, got {:?}",
        route.method
    );
    // Controller must resolve to the get_user handler symbol.
    let controller = route.controller.expect("route should have a controller");
    let handler = ir
        .symbols
        .get(&controller)
        .expect("controller symbol should exist");
    assert_eq!(handler.name, "get_user");

    // HTTP client call: reqwest::get("/api/health").
    let call = ir
        .http_calls
        .iter()
        .find(|c| c.path == "/api/health")
        .expect("http call to /api/health should be extracted");
    assert!(
        matches!(call.method, HttpMethod::Get),
        "http call method should be GET, got {:?}",
        call.method
    );
}

#[test]
fn extracts_builder_route_and_client_method() {
    let source = r#"
async fn list_users() -> String {
    String::new()
}

fn build() {
    let app = Router::new().route("/api/users", get(list_users));
    let _ = app;
}

async fn call_backend(client: Client) {
    let _ = client.post("https://api.example.com/v1/orders?trace=1").send().await;
}
"#;

    let ir = parse_rust("builder_and_method", source);

    // Builder route: .route("/api/users", get(list_users)).
    let route = ir
        .routes
        .iter()
        .find(|r| r.path == "/api/users")
        .expect("builder route for /api/users should be extracted");
    assert!(matches!(route.method, HttpMethod::Get));
    let controller = route.controller.expect("builder route controller resolved");
    assert_eq!(ir.symbols.get(&controller).unwrap().name, "list_users");

    // Client method call: URL path stripped of scheme/host/query.
    let call = ir
        .http_calls
        .iter()
        .find(|c| c.path == "/v1/orders")
        .expect("http call to /v1/orders should be extracted");
    assert!(matches!(call.method, HttpMethod::Post));

    // Guard: a plain map/get on a non-URL literal must NOT be an http call.
    assert!(
        !ir.http_calls.iter().any(|c| c.path == "orders"),
        "non-URL string args must not be treated as http calls"
    );
}
