use std::io::Write;

use verum_nucleus::HttpMethod;

/// Write `source` to a uniquely-named temp `.py` file and parse it.
fn parse_python(name: &str, source: &str) -> verum_nucleus::Ir {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "verum_py_routes_{}_{}.py",
        name,
        std::process::id()
    ));
    {
        let mut f = std::fs::File::create(&path).expect("create temp file");
        f.write_all(source.as_bytes()).expect("write temp file");
    }
    let ir = verum_mappa::python::parse_file(&path).expect("parse python");
    let _ = std::fs::remove_file(&path);
    ir
}

/// Same, but with an explicit filename (needed for Django `urls.py` detection).
fn parse_python_named(file_name: &str, source: &str) -> verum_nucleus::Ir {
    let mut path = std::env::temp_dir();
    path.push(format!("verum_py_{}_{}", std::process::id(), file_name));
    {
        let mut f = std::fs::File::create(&path).expect("create temp file");
        f.write_all(source.as_bytes()).expect("write temp file");
    }
    let ir = verum_mappa::python::parse_file(&path).expect("parse python");
    let _ = std::fs::remove_file(&path);
    ir
}

#[test]
fn fastapi_get_decorator_becomes_route_with_controller() {
    let source = r#"
from fastapi import FastAPI

app = FastAPI()

@app.get("/api/x")
def show():
    return {"ok": True}
"#;
    let ir = parse_python("fastapi_get", source);

    let route = ir
        .routes
        .iter()
        .find(|r| r.path == "/api/x")
        .expect("route for /api/x should be extracted");
    assert!(
        matches!(route.method, HttpMethod::Get),
        "method should be GET, got {:?}",
        route.method
    );
    let controller = route.controller.expect("route should have a controller");
    let handler = ir.symbols.get(&controller).expect("controller symbol");
    assert_eq!(
        handler.name, "show",
        "controller should be the show handler"
    );
}

#[test]
fn fastapi_router_prefix_is_applied() {
    let source = r#"
from fastapi import APIRouter

router = APIRouter(prefix="/api")

@router.post("/users")
def create_user():
    return {}
"#;
    let ir = parse_python("fastapi_prefix", source);

    let route = ir
        .routes
        .iter()
        .find(|r| matches!(r.method, HttpMethod::Post))
        .expect("a POST route should exist");
    assert_eq!(
        route.path, "/api/users",
        "APIRouter prefix should be prepended, got {}",
        route.path
    );
}

#[test]
fn flask_route_with_methods_emits_post_route() {
    let source = r#"
from flask import Flask

app = Flask(__name__)

@app.route("/y", methods=["POST"])
def handler():
    return "ok"
"#;
    let ir = parse_python("flask_route", source);

    let route = ir
        .routes
        .iter()
        .find(|r| r.path == "/y")
        .expect("route for /y should be extracted");
    assert!(
        matches!(route.method, HttpMethod::Post),
        "methods=[\"POST\"] should yield a POST route, got {:?}",
        route.method
    );
    let controller = route.controller.expect("route should have a controller");
    assert_eq!(ir.symbols.get(&controller).unwrap().name, "handler");
}

#[test]
fn flask_route_defaults_to_get() {
    let source = r#"
from flask import Flask

app = Flask(__name__)

@app.route("/z")
def index():
    return "home"
"#;
    let ir = parse_python("flask_default", source);
    let route = ir.routes.iter().find(|r| r.path == "/z").expect("route /z");
    assert!(
        matches!(route.method, HttpMethod::Get),
        "no methods= should default to GET, got {:?}",
        route.method
    );
}

#[test]
fn requests_get_becomes_http_call() {
    let source = r#"
import requests

def health():
    return requests.get("http://h/api/x")
"#;
    let ir = parse_python("requests_get", source);

    let call = ir
        .http_calls
        .iter()
        .find(|c| c.path == "/api/x")
        .expect("http call to /api/x should be extracted");
    assert!(
        matches!(call.method, HttpMethod::Get),
        "http call method should be GET, got {:?}",
        call.method
    );
    let caller = ir.symbols.get(&call.caller).expect("caller symbol");
    assert_eq!(caller.name, "health", "caller should be the enclosing fn");
}

#[test]
fn httpx_and_session_client_calls() {
    let source = r#"
import httpx

def fetch(session):
    httpx.post("/api/create")
    session.get("/api/list")
"#;
    let ir = parse_python("httpx_session", source);

    assert!(
        ir.http_calls
            .iter()
            .any(|c| c.path == "/api/create" && matches!(c.method, HttpMethod::Post)),
        "httpx.post should be an http_call"
    );
    assert!(
        ir.http_calls
            .iter()
            .any(|c| c.path == "/api/list" && matches!(c.method, HttpMethod::Get)),
        "session.get should be an http_call"
    );
}

#[test]
fn django_path_becomes_any_route() {
    // View defined before urlpatterns so it can resolve within this single
    // file (cross-file `views.foo` references resolve to None - best-effort).
    let source = r#"
from django.urls import path

def user_detail(request, id):
    return None

urlpatterns = [
    path("users/<int:id>/", user_detail),
]
"#;
    let ir = parse_python_named("urls.py", source);

    let route = ir
        .routes
        .iter()
        .find(|r| r.path == "/users/<int:id>")
        .expect("django path route should be extracted");
    assert!(
        matches!(route.method, HttpMethod::Any),
        "django route method should be Any, got {:?}",
        route.method
    );
    // Controller resolves by trailing view name within the same file.
    let controller = route.controller.expect("view should resolve to controller");
    assert_eq!(ir.symbols.get(&controller).unwrap().name, "user_detail");
}
