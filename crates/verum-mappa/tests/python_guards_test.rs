//! Route guard extraction: the middleware list a Python route carries must
//! mirror exactly what the source declares - Flask/Django decorator guards,
//! FastAPI `Depends(...)` dependencies (decorator kwarg, router constructor,
//! and signature forms), and DRF `permission_classes`. An undeclared guard
//! must never appear (the auth pass treats empty as "unknown", so inventing
//! one would silence real findings), and a declared one must never be lost.

use std::io::Write;

/// Tests run in parallel threads sharing one pid, so file names need a
/// per-call sequence number on top of the pid to stay unique.
static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Write `source` to a uniquely-named temp `.py` file and parse it.
fn parse_python(name: &str, source: &str) -> verum_nucleus::Ir {
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "verum_py_guards_{}_{}_{seq}.py",
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
    let dir = std::env::temp_dir().join(format!("verum_py_guards_{}_{seq}", std::process::id()));
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

fn route_middleware(ir: &verum_nucleus::Ir, path: &str) -> Vec<String> {
    ir.routes
        .iter()
        .find(|r| r.path == path)
        .unwrap_or_else(|| panic!("route {path} should be extracted"))
        .middleware
        .clone()
}

#[test]
fn flask_login_required_decorator_recorded() {
    let source = r#"
from flask import Flask
from flask_login import login_required

app = Flask(__name__)

@app.route("/admin")
@login_required
def admin_panel():
    return "x"
"#;
    let ir = parse_python("flask_login", source);
    let mw = route_middleware(&ir, "/admin");
    assert!(
        mw.contains(&"login_required".to_string()),
        "sibling @login_required should be route middleware, got {mw:?}"
    );
}

#[test]
fn flask_jwt_required_call_decorator_recorded() {
    let source = r#"
from flask import Flask
from flask_jwt_extended import jwt_required

app = Flask(__name__)

@app.route("/me")
@jwt_required()
def me():
    return "me"
"#;
    let ir = parse_python("flask_jwt", source);
    let mw = route_middleware(&ir, "/me");
    assert!(
        mw.contains(&"jwt_required".to_string()),
        "@jwt_required() should record the decorator name, got {mw:?}"
    );
}

#[test]
fn flask_roles_required_with_args_recorded() {
    let source = r#"
from flask import Flask

app = Flask(__name__)

@app.get("/ops")
@roles_required("admin")
def ops():
    return "ops"
"#;
    let ir = parse_python("flask_roles", source);
    let mw = route_middleware(&ir, "/ops");
    assert!(
        mw.contains(&"roles_required".to_string()),
        "@roles_required(...) should record the decorator name, got {mw:?}"
    );
}

#[test]
fn flask_route_without_guard_has_empty_middleware() {
    let source = r#"
from flask import Flask

app = Flask(__name__)

@app.route("/open")
def open_page():
    return "open"
"#;
    let ir = parse_python("flask_bare", source);
    let mw = route_middleware(&ir, "/open");
    assert!(
        mw.is_empty(),
        "an unguarded route must not invent middleware, got {mw:?}"
    );
}

#[test]
fn fastapi_decorator_dependencies_kwarg_recorded() {
    let source = r#"
from fastapi import FastAPI, Depends

app = FastAPI()

@app.get("/users", dependencies=[Depends(get_current_user)])
def list_users():
    return []
"#;
    let ir = parse_python("fastapi_dep_kwarg", source);
    let mw = route_middleware(&ir, "/users");
    assert!(
        mw.contains(&"get_current_user".to_string()),
        "dependencies=[Depends(...)] should record the dependency name, got {mw:?}"
    );
}

#[test]
fn fastapi_router_constructor_dependencies_apply_to_routes() {
    let source = r#"
from fastapi import APIRouter, Depends

router = APIRouter(prefix="/api", dependencies=[Depends(verify_token)])

@router.get("/orders")
def orders():
    return []
"#;
    let ir = parse_python("fastapi_router_dep", source);
    let mw = route_middleware(&ir, "/api/orders");
    assert!(
        mw.contains(&"verify_token".to_string()),
        "APIRouter(dependencies=[...]) should guard every route on it, got {mw:?}"
    );
}

#[test]
fn fastapi_signature_depends_recorded() {
    let source = r#"
from fastapi import FastAPI, Depends

app = FastAPI()

@app.get("/profile")
def profile(user=Depends(get_current_user)):
    return user
"#;
    let ir = parse_python("fastapi_sig_dep", source);
    let mw = route_middleware(&ir, "/profile");
    assert!(
        mw.contains(&"get_current_user".to_string()),
        "Depends(...) in a parameter default should be recorded, got {mw:?}"
    );
}

#[test]
fn fastapi_annotated_depends_recorded() {
    let source = r#"
from typing import Annotated
from fastapi import FastAPI, Depends

app = FastAPI()

@app.get("/settings")
def settings(user: Annotated[dict, Depends(require_admin)]):
    return user
"#;
    let ir = parse_python("fastapi_annotated", source);
    let mw = route_middleware(&ir, "/settings");
    assert!(
        mw.contains(&"require_admin".to_string()),
        "Annotated[..., Depends(...)] should be recorded, got {mw:?}"
    );
}

#[test]
fn fastapi_plain_kwargs_and_defaults_not_recorded_as_guards() {
    let source = r#"
from fastapi import FastAPI

app = FastAPI()

@app.get("/things", response_model=list)
def things(limit=10, q=None):
    return []
"#;
    let ir = parse_python("fastapi_plain", source);
    let mw = route_middleware(&ir, "/things");
    assert!(
        mw.is_empty(),
        "response_model / plain defaults must not become guards, got {mw:?}"
    );
}

#[test]
fn django_login_required_view_guards_urls_route() {
    let source = r#"
from django.urls import path
from django.contrib.auth.decorators import login_required

@login_required
def dashboard(request):
    return None

urlpatterns = [
    path("dashboard/", dashboard),
]
"#;
    let ir = parse_python_named("urls.py", source);
    let mw = route_middleware(&ir, "/dashboard");
    assert!(
        mw.contains(&"login_required".to_string()),
        "a same-file @login_required view should guard its route, got {mw:?}"
    );
}

#[test]
fn drf_permission_classes_decorator_records_class_names() {
    let source = r#"
from django.urls import path
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def whoami(request):
    return None

urlpatterns = [
    path("whoami/", whoami),
]
"#;
    let ir = parse_python_named("urls.py", source);
    let mw = route_middleware(&ir, "/whoami");
    assert!(
        mw.contains(&"IsAuthenticated".to_string()),
        "@permission_classes([...]) should record the class names, got {mw:?}"
    );
}

#[test]
fn drf_class_attribute_permission_classes_on_registered_viewset() {
    let source = r#"
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework.routers import DefaultRouter

class OrderViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]

    def list(self, request):
        return None

router = DefaultRouter()
router.register(r"orders", OrderViewSet)
"#;
    let ir = parse_python("drf_viewset_attr", source);
    let mw = route_middleware(&ir, "/orders");
    assert!(
        mw.contains(&"IsAuthenticated".to_string()),
        "a ViewSet's permission_classes attribute should guard its route, got {mw:?}"
    );
}
