//! Top-level call attribution.
//!
//! Calls made at file top level (plain-script bootstrap code) have no
//! enclosing function/class. They used to be silently dropped, which made the
//! callee look dead - and `verum clean` could then delete live code. Each
//! frontend must instead attribute such calls to a synthetic file scope.

use verum_nucleus::{CallTarget, Ir};

/// Tests run in parallel threads, so each needs its own file - a shared name
/// races and one test parses another's source.
static SAMPLE_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn write_sample(source: &str, ext: &str) -> std::path::PathBuf {
    let seq = SAMPLE_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir =
        std::env::temp_dir().join(format!("verum_toplevel_test_{}_{seq}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join(format!("sample.{ext}"));
    std::fs::write(&path, source).expect("write sample");
    path
}

/// Best-effort teardown: remove the per-call temp dir a sample was written to.
fn remove_sample(path: &std::path::Path) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::remove_dir_all(dir);
    }
}

fn parse_php(source: &str) -> Ir {
    let path = write_sample(source, "php");
    let ir = verum_mappa::php::parse_file(&path).expect("should parse PHP source");
    remove_sample(&path);
    ir
}

fn parse_python(source: &str) -> Ir {
    let path = write_sample(source, "py");
    let ir = verum_mappa::python::parse_file(&path).expect("should parse Python source");
    remove_sample(&path);
    ir
}

fn parse_js(source: &str) -> Ir {
    let path = write_sample(source, "js");
    let ir = verum_mappa::javascript::parse_file(&path, false).expect("should parse JS source");
    remove_sample(&path);
    ir
}

fn callee_name(target: &CallTarget) -> &str {
    match target {
        CallTarget::Unresolved(name) | CallTarget::Dynamic(name) | CallTarget::Magic(name) => name,
        CallTarget::Resolved(_) => "",
    }
}

fn has_call_edge_containing(ir: &Ir, needle: &str) -> bool {
    ir.calls
        .iter()
        .any(|c| callee_name(&c.callee).contains(needle))
}

#[test]
fn php_toplevel_function_call_is_recorded() {
    let ir = parse_php(
        r#"<?php
bootstrap();
function bootstrap() {}
"#,
    );
    assert!(
        has_call_edge_containing(&ir, "bootstrap"),
        "top-level `bootstrap()` must produce a call edge; calls: {:?}",
        ir.calls
    );
}

#[test]
fn php_toplevel_member_and_scoped_calls_are_recorded() {
    let ir = parse_php(
        r#"<?php
$app = new App();
$app->run();
App::boot();
"#,
    );
    assert!(
        has_call_edge_containing(&ir, "run"),
        "top-level `$app->run()` must produce a call edge; calls: {:?}",
        ir.calls
    );
    assert!(
        has_call_edge_containing(&ir, "boot"),
        "top-level `App::boot()` must produce a call edge; calls: {:?}",
        ir.calls
    );
}

#[test]
fn python_toplevel_call_is_recorded() {
    let ir = parse_python(
        r#"def main():
    pass

main()
"#,
    );
    assert!(
        has_call_edge_containing(&ir, "main"),
        "top-level `main()` must produce a call edge; calls: {:?}",
        ir.calls
    );
}

#[test]
fn js_toplevel_new_is_recorded() {
    let ir = parse_js(
        r#"class Widget {}
new Widget();
"#,
    );
    assert!(
        has_call_edge_containing(&ir, "Widget"),
        "top-level `new Widget()` must produce a call edge referencing Widget; calls: {:?}",
        ir.calls
    );
}
