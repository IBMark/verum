//! Calls written inside macro arguments must still produce call edges.
//!
//! tree-sitter leaves macro arguments as an unparsed token stream, so these
//! calls never appear as `call_expression` nodes. Missing them makes the callee
//! look unreferenced and dead-code analysis reports a false positive.

use verum_nucleus::{CallTarget, Ir};

/// Tests run in parallel threads, so each needs its own file - a shared name
/// races and one test parses another's source.
static SAMPLE_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn parse(source: &str) -> Ir {
    let seq = SAMPLE_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("verum_macro_test_{}_{seq}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("sample.rs");
    std::fs::write(&path, source).expect("write sample");
    let ir = verum_mappa::rust_lang::parse_file(&path).expect("should parse Rust source");
    let _ = std::fs::remove_dir_all(&dir);
    ir
}

fn called_names(ir: &Ir) -> Vec<String> {
    ir.calls
        .iter()
        .filter_map(|c| match &c.callee {
            CallTarget::Unresolved(n) | CallTarget::Dynamic(n) | CallTarget::Magic(n) => {
                Some(n.clone())
            }
            CallTarget::Resolved(_) => None,
        })
        .collect()
}

#[test]
fn records_calls_inside_macro_arguments() {
    let ir = parse(
        r#"
fn main() {
    println!("{}", greet("world"));
}

fn greet(who: &str) -> String {
    format!("hello {who}")
}
"#,
    );

    let names = called_names(&ir);
    assert!(
        names.contains(&"greet".to_string()),
        "greet() inside println! should be a call, got {names:?}"
    );
    assert!(
        names.contains(&"println!".to_string()),
        "the macro itself should still be recorded, got {names:?}"
    );
}

#[test]
fn records_calls_inside_assert_macros() {
    let ir = parse(
        r#"
fn helper() -> u32 { 1 }

#[test]
fn t() {
    assert_eq!(helper(), 1);
}
"#,
    );

    let names = called_names(&ir);
    assert!(
        names.contains(&"helper".to_string()),
        "helper() inside assert_eq! should be a call, got {names:?}"
    );
}

#[test]
fn records_qualified_and_method_calls() {
    let ir = parse(
        r#"
fn main() {
    println!("{} {}", util::compute(1), thing.render());
}
"#,
    );

    let names = called_names(&ir);
    assert!(
        names.contains(&"util::compute".to_string()),
        "path call should keep its segments, got {names:?}"
    );
    assert!(
        names.contains(&"thing.render".to_string()),
        "method call should keep its receiver, got {names:?}"
    );
}

#[test]
fn records_nested_and_deeply_nested_calls() {
    let ir = parse(
        r#"
fn main() {
    println!("{}", outer(inner(leaf())));
    let v = vec![make_item(), make_item()];
}
"#,
    );

    let names = called_names(&ir);
    for expected in ["outer", "inner", "leaf", "make_item"] {
        assert!(
            names.contains(&expected.to_string()),
            "{expected}() should be a call, got {names:?}"
        );
    }
}

#[test]
fn records_macros_nested_in_macro_arguments() {
    let ir = parse(
        r#"
fn main() {
    println!("{}", format!("{}", value()));
}
"#,
    );

    let names = called_names(&ir);
    assert!(
        names.contains(&"format!".to_string()),
        "nested macro should be recorded, got {names:?}"
    );
    assert!(
        names.contains(&"value".to_string()),
        "call inside nested macro should be recorded, got {names:?}"
    );
}

#[test]
fn does_not_invent_calls_from_keywords_or_non_call_tokens() {
    let ir = parse(
        r#"
fn main() {
    let flags = vec![1, 2, 3];
    write!(f, "{}", if (cond) { 1 } else { 2 });
}
"#,
    );

    let names = called_names(&ir);
    for keyword in ["if", "else", "vec", "flags", "cond"] {
        assert!(
            !names.contains(&keyword.to_string()),
            "{keyword} is not a call, got {names:?}"
        );
    }
}
