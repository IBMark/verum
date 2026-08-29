//! Framework entry-point marking: Celery tasks, click/Typer commands and
//! groups, pytest fixtures and conftest hooks are invoked by their framework,
//! never by user code, so the extractor must mark them `is_entry_point` - the
//! dead-code pass both skips entry points and seeds reachability from them.
//! The negative cases matter just as much: a bare `@task` or a decorator that
//! merely wraps behaviour must NOT earn the exemption, or genuinely dead code
//! hides behind it.

use std::io::Write;

/// Tests run in parallel threads sharing one pid, so file names need a
/// per-call sequence number on top of the pid to stay unique.
static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Write `source` to a uniquely-named temp `.py` file and parse it.
fn parse_python(name: &str, source: &str) -> verum_nucleus::Ir {
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "verum_py_entry_{}_{}_{seq}.py",
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

/// Same, but with an explicit filename (needed for conftest.py detection).
fn parse_python_named(file_name: &str, source: &str) -> verum_nucleus::Ir {
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("verum_py_entry_{}_{seq}", std::process::id()));
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

fn is_entry(ir: &verum_nucleus::Ir, name: &str) -> bool {
    ir.symbols
        .values()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("symbol {name} should exist"))
        .is_entry_point
}

#[test]
fn celery_task_decorators_mark_entry_points() {
    let source = r#"
from celery import shared_task

@app.task
def send_email():
    return 1

@celery.task(bind=True)
def resync(self):
    return 2

@shared_task
def cleanup():
    return 3
"#;
    let ir = parse_python("celery", source);
    assert!(
        is_entry(&ir, "send_email"),
        "@app.task marks an entry point"
    );
    assert!(
        is_entry(&ir, "resync"),
        "@celery.task(bind=True) marks an entry point"
    );
    assert!(
        is_entry(&ir, "cleanup"),
        "@shared_task marks an entry point"
    );
}

#[test]
fn click_command_and_group_mark_entry_points() {
    let source = r#"
import click

@click.group()
def cli():
    pass

@cli.command()
def migrate():
    pass

@click.command()
def standalone():
    pass
"#;
    let ir = parse_python("click", source);
    assert!(is_entry(&ir, "cli"), "@click.group() marks an entry point");
    assert!(
        is_entry(&ir, "migrate"),
        "@cli.command() marks an entry point"
    );
    assert!(
        is_entry(&ir, "standalone"),
        "@click.command() marks an entry point"
    );
}

#[test]
fn pytest_fixture_marks_entry_point() {
    let source = r#"
import pytest

@pytest.fixture
def db_session():
    return None

@pytest.fixture(scope="session")
def settings():
    return None
"#;
    let ir = parse_python("fixture", source);
    assert!(
        is_entry(&ir, "db_session"),
        "@pytest.fixture marks an entry point"
    );
    assert!(
        is_entry(&ir, "settings"),
        "@pytest.fixture(scope=...) marks an entry point"
    );
}

#[test]
fn conftest_pytest_hooks_mark_entry_points() {
    let source = r#"
def pytest_configure(config):
    pass

def pytest_addoption(parser):
    pass

def ordinary_helper():
    pass
"#;
    let ir = parse_python_named("conftest.py", source);
    assert!(
        is_entry(&ir, "pytest_configure"),
        "pytest_* in conftest.py is a runner hook"
    );
    assert!(
        is_entry(&ir, "pytest_addoption"),
        "pytest_* in conftest.py is a runner hook"
    );
    assert!(
        !is_entry(&ir, "ordinary_helper"),
        "non-hook functions in conftest.py stay ordinary"
    );
}

#[test]
fn pytest_prefix_outside_conftest_is_not_an_entry_point() {
    let source = r#"
def pytest_style_name():
    pass
"#;
    let ir = parse_python("not_conftest", source);
    assert!(
        !is_entry(&ir, "pytest_style_name"),
        "the pytest_ prefix only means something inside conftest.py"
    );
}

#[test]
fn bare_task_and_unrelated_decorators_are_not_entry_points() {
    let source = r#"
@task
def ambiguous():
    return 1

@cache.cached(timeout=50)
def cached_lookup():
    return 2
"#;
    let ir = parse_python("negative", source);
    assert!(
        !is_entry(&ir, "ambiguous"),
        "bare @task carries no framework evidence"
    );
    assert!(
        !is_entry(&ir, "cached_lookup"),
        "a caching decorator is not an entry point"
    );
}
