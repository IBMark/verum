use std::io::Write;

use verum_nucleus::HttpMethod;

/// Tests run in parallel threads sharing one pid, so file names need a
/// per-call sequence number on top of the pid to stay unique.
static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Write `source` to a uniquely-named temp `.py` file and parse it.
fn parse_python(name: &str, source: &str) -> verum_nucleus::Ir {
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "verum_py_routes_{}_{}_{seq}.py",
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
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("verum_py_{}_{seq}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join(file_name);
    {
        let mut f = std::fs::File::create(&path).expect("create temp file");
        f.write_all(source.as_bytes()).expect("write temp file");
    }
    let ir = verum_mappa::python::parse_file(&path).expect("parse python");
    let _ = std::fs::remove_dir_all(&dir);
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

#[test]
fn django_as_view_route_resolves_to_class() {
    let source = r#"
from django.urls import path
from django.views import View

class ReportView(View):
    def get(self, request):
        return None

urlpatterns = [
    path("reports/", ReportView.as_view()),
]
"#;
    let ir = parse_python_named("urls.py", source);

    let route = ir
        .routes
        .iter()
        .find(|r| r.path == "/reports")
        .expect("as_view route should be extracted");
    let controller = route.controller.expect("class-based view should resolve");
    let sym = ir.symbols.get(&controller).unwrap();
    assert_eq!(
        sym.name, "ReportView",
        "controller should be the view class"
    );
    assert!(
        matches!(sym.kind, verum_nucleus::SymbolKind::Class),
        "as_view() should resolve to the class symbol, got {:?}",
        sym.kind
    );
}

#[test]
fn drf_router_register_resolves_viewset() {
    let source = r#"
from rest_framework import viewsets
from rest_framework.routers import DefaultRouter

class UserViewSet(viewsets.ModelViewSet):
    def list(self, request):
        return None

router = DefaultRouter()
router.register(r"users", UserViewSet)
"#;
    let ir = parse_python("drf_register", source);

    let route = ir
        .routes
        .iter()
        .find(|r| r.path == "/users")
        .expect("router.register should become a route");
    assert!(
        matches!(route.method, HttpMethod::Any),
        "ViewSet registration covers every verb, got {:?}",
        route.method
    );
    let controller = route.controller.expect("ViewSet should resolve");
    assert_eq!(ir.symbols.get(&controller).unwrap().name, "UserViewSet");
}

#[test]
fn non_router_register_is_not_a_route() {
    // `.register(...)` on anything not named like a router is a plugin
    // registry, not a route table.
    let source = r#"
class Plugin:
    pass

registry.register("plugins", Plugin)
"#;
    let ir = parse_python("registry_register", source);
    assert!(
        ir.routes.is_empty(),
        "registry.register must not become a route: {:?}",
        ir.routes
    );
}

#[test]
fn aiohttp_router_add_get_becomes_route() {
    let source = r#"
from aiohttp import web

async def list_pets(request):
    return web.json_response([])

app = web.Application()
app.router.add_get("/pets", list_pets)
"#;
    let ir = parse_python("aiohttp_add_get", source);

    let route = ir
        .routes
        .iter()
        .find(|r| r.path == "/pets")
        .expect("add_get should become a route");
    assert!(matches!(route.method, HttpMethod::Get));
    let controller = route.controller.expect("handler should resolve");
    assert_eq!(ir.symbols.get(&controller).unwrap().name, "list_pets");
}

#[test]
fn aiohttp_web_get_route_table_becomes_route() {
    let source = r#"
from aiohttp import web

async def list_toys(request):
    return web.json_response([])

async def create_toy(request):
    return web.json_response({})

app = web.Application()
app.add_routes([
    web.get("/toys", list_toys),
    web.post("/toys", create_toy),
])
"#;
    let ir = parse_python("aiohttp_table", source);

    assert!(
        ir.routes
            .iter()
            .any(|r| r.path == "/toys" && matches!(r.method, HttpMethod::Get)),
        "web.get entry should be a GET route: {:?}",
        ir.routes
    );
    assert!(
        ir.routes
            .iter()
            .any(|r| r.path == "/toys" && matches!(r.method, HttpMethod::Post)),
        "web.post entry should be a POST route: {:?}",
        ir.routes
    );
}

#[test]
fn aiohttp_web_get_without_handler_is_not_a_route() {
    // Without a handler argument this is an HTTP client shape, not a route
    // declaration - it must stay out of the route table.
    let source = r#"
def probe():
    return web.get("/upstream")
"#;
    let ir = parse_python("aiohttp_no_handler", source);
    assert!(
        ir.routes.is_empty(),
        "web.get without a handler must not become a route: {:?}",
        ir.routes
    );
}

#[test]
fn sanic_verb_decorator_becomes_route() {
    let source = r#"
from sanic import Sanic

app = Sanic("api")

@app.get("/items")
async def items(request):
    return None
"#;
    let ir = parse_python("sanic_get", source);

    let route = ir
        .routes
        .iter()
        .find(|r| r.path == "/items")
        .expect("Sanic @app.get should be a route");
    assert!(matches!(route.method, HttpMethod::Get));
    let controller = route.controller.expect("handler should resolve");
    assert_eq!(ir.symbols.get(&controller).unwrap().name, "items");
}

#[test]
fn sanic_route_decorator_with_methods() {
    let source = r#"
from sanic import Sanic

app = Sanic("api")

@app.route("/submit", methods=["POST"])
async def submit(request):
    return None
"#;
    let ir = parse_python("sanic_route", source);
    let route = ir
        .routes
        .iter()
        .find(|r| r.path == "/submit")
        .expect("Sanic @app.route should be a route");
    assert!(
        matches!(route.method, HttpMethod::Post),
        "methods=[\"POST\"] should yield POST, got {:?}",
        route.method
    );
}

#[test]
fn tornado_application_tuples_become_routes() {
    let source = r#"
import tornado.web

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.write("home")

class ItemHandler(tornado.web.RequestHandler):
    def get(self):
        self.write("items")

def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
        (r"/items", ItemHandler),
    ])
"#;
    let ir = parse_python("tornado_app", source);

    let root = ir
        .routes
        .iter()
        .find(|r| r.path == "/")
        .expect("tornado root route should be extracted");
    assert!(
        matches!(root.method, HttpMethod::Any),
        "tornado handlers cover every verb, got {:?}",
        root.method
    );
    let controller = root.controller.expect("handler class should resolve");
    assert_eq!(ir.symbols.get(&controller).unwrap().name, "MainHandler");
    assert!(
        ir.routes.iter().any(|r| r.path == "/items"),
        "second tuple should be a route too: {:?}",
        ir.routes
    );
}

#[test]
fn non_application_tuple_list_is_not_routes() {
    // Same tuple shape, but the constructor is not an Application - a lookup
    // table of (name, class) pairs must not be misread as a route table.
    let source = r#"
class CsvExporter:
    pass

EXPORTERS = Registry([
    ("csv", CsvExporter),
])
"#;
    let ir = parse_python("tornado_negative", source);
    assert!(
        ir.routes.is_empty(),
        "a non-Application tuple list must not become routes: {:?}",
        ir.routes
    );
}
