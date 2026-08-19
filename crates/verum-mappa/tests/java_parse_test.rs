use std::io::Write;

use verum_nucleus::{CallTarget, SymbolKind, Visibility};

static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn parse(src: &str) -> verum_nucleus::Ir {
    // Tests run in parallel - each needs its own file, or concurrent
    // create/truncate+write races a sibling's read of the same path.
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("verum_java_test_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("Sample_{}_{seq}.java", fastid(src)));
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(src.as_bytes()).unwrap();
    verum_mappa::java::parse_file(&path).expect("should parse Java")
}

fn fastid(s: &str) -> u64 {
    // cheap deterministic-ish id to keep temp filenames distinct per test
    s.bytes().fold(1469598103934665603u64, |h, b| {
        (h ^ b as u64).wrapping_mul(1099511628211)
    })
}

const SRC: &str = r#"
package com.example.app;

import com.other.Base;
import com.other.Widget;

public class UserService extends Base implements Runnable {

    private int retries;
    public final String label = "svc";

    @GetMapping("/x")
    @ResponseBody
    public String hello(int a, String b) {
        Widget w = new Widget();
        w.render();
        Base.helper();
        return label;
    }

    void run() {
    }
}
"#;

#[test]
fn test_private_field_is_property() {
    let ir = parse(SRC);
    let retries = ir
        .symbols
        .values()
        .find(|s| s.name == "retries")
        .expect("field 'retries' should be a symbol");
    assert_eq!(retries.kind, SymbolKind::Property);
    assert_eq!(retries.visibility, Visibility::Private);
    // parent is the enclosing class
    let cls = ir
        .symbols
        .values()
        .find(|s| s.name == "UserService")
        .unwrap();
    assert_eq!(retries.parent, Some(cls.id));
}

#[test]
fn test_public_method_param_count() {
    let ir = parse(SRC);
    let hello = ir
        .symbols
        .values()
        .find(|s| s.name == "hello")
        .expect("method 'hello' should exist");
    assert_eq!(hello.kind, SymbolKind::Method);
    assert_eq!(hello.visibility, Visibility::Public);
    assert_eq!(hello.param_count, 2);
}

#[test]
fn test_package_private_visibility_is_global() {
    let ir = parse(SRC);
    let run = ir.symbols.values().find(|s| s.name == "run").unwrap();
    assert_eq!(run.visibility, Visibility::Global);
}

#[test]
fn test_extends_and_implements_edges() {
    let ir = parse(SRC);
    let names: Vec<String> = ir
        .calls
        .iter()
        .filter_map(|c| match &c.callee {
            CallTarget::Unresolved(n) => Some(n.clone()),
            _ => None,
        })
        .collect();
    assert!(
        names.iter().any(|n| n == "Base"),
        "extends Base edge: {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "Runnable"),
        "implements Runnable edge: {names:?}"
    );
    // extends should also emit the imported FQN form
    assert!(
        names.iter().any(|n| n == "com.other.Base"),
        "aliased FQN for Base: {names:?}"
    );
}

#[test]
fn test_import_recorded_as_use() {
    let ir = parse(SRC);
    let has_import_use = ir
        .calls
        .iter()
        .any(|c| matches!(&c.callee, CallTarget::Unresolved(n) if n == "com.other.Widget"));
    assert!(has_import_use, "import com.other.Widget should be a use");
}

#[test]
fn test_receiver_and_static_calls() {
    let ir = parse(SRC);
    let names: Vec<String> = ir
        .calls
        .iter()
        .filter_map(|c| match &c.callee {
            CallTarget::Unresolved(n) => Some(n.clone()),
            _ => None,
        })
        .collect();
    assert!(
        names.iter().any(|n| n == "w.render"),
        "instance call: {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "Base.helper"),
        "static call: {names:?}"
    );
}

#[test]
fn test_new_object_creation_use() {
    let ir = parse(SRC);
    let names: Vec<String> = ir
        .calls
        .iter()
        .filter_map(|c| match &c.callee {
            CallTarget::Unresolved(n) => Some(n.clone()),
            _ => None,
        })
        .collect();
    assert!(
        names.iter().any(|n| n == "Widget"),
        "new Widget() use: {names:?}"
    );
}

#[test]
fn test_annotation_in_doc_comment() {
    let ir = parse(SRC);
    let hello = ir.symbols.values().find(|s| s.name == "hello").unwrap();
    let doc = hello.doc_comment.as_deref().unwrap_or("");
    assert!(doc.contains("@GetMapping(\"/x\")"), "doc_comment: {doc:?}");
    assert!(doc.contains("@ResponseBody"), "doc_comment: {doc:?}");
}
