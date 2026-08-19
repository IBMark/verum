//! Receiver-type inference: method calls on locals and `self.field` should be
//! emitted as `Type::method`, so the resolver can bind them to in-IR impls and
//! downstream passes can classify the receiver.

use verum_nucleus::CallTarget;

fn parse(src: &str) -> verum_nucleus::Ir {
    let dir = std::env::temp_dir().join(format!(
        "verum-recv-test-{}-{}",
        std::process::id(),
        src.len()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("lib.rs");
    std::fs::write(&file, src).unwrap();
    let ir = verum_mappa::rust_lang::parse_file(&file).expect("parse");
    std::fs::remove_dir_all(&dir).ok();
    ir
}

fn unresolved_names(ir: &verum_nucleus::Ir) -> Vec<String> {
    ir.calls
        .iter()
        .filter_map(|c| match &c.callee {
            CallTarget::Unresolved(n) => Some(n.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn let_constructor_types_receiver() {
    let ir = parse(
        "struct Sender;\n\
         impl Sender { fn new() -> Self { Sender } fn send(&self) {} }\n\
         fn main() {\n\
             let s = Sender::new();\n\
             s.send();\n\
         }\n",
    );
    let names = unresolved_names(&ir);
    assert!(
        names.iter().any(|n| n == "Sender::send"),
        "expected Sender::send in {names:?}"
    );
}

#[test]
fn let_annotation_and_wrappers_type_receiver() {
    let ir = parse(
        "fn f() {\n\
             let buf: Vec<u8> = Default::default();\n\
             buf.truncate(4);\n\
             let out = vec![0u8; 8];\n\
             out.clear();\n\
             let conn = Conn::connect(addr).await?;\n\
             conn.write_all(b\"x\");\n\
         }\n",
    );
    let names = unresolved_names(&ir);
    assert!(names.iter().any(|n| n == "Vec::truncate"), "{names:?}");
    assert!(names.iter().any(|n| n == "Vec::clear"), "{names:?}");
    assert!(names.iter().any(|n| n == "Conn::write_all"), "{names:?}");
}

#[test]
fn self_field_types_receiver() {
    let ir = parse(
        "struct Wrap { inner: Socket }\n\
         impl Wrap {\n\
             fn go(&mut self) { self.inner.send_to(b\"x\"); }\n\
         }\n",
    );
    let names = unresolved_names(&ir);
    assert!(
        names.iter().any(|n| n == "Socket::send_to"),
        "expected Socket::send_to in {names:?}"
    );
}

#[test]
fn unknown_receivers_keep_original_shape() {
    let ir = parse(
        "fn f(x: &Thing) {\n\
             x.poke();\n\
             self_like.unknown();\n\
         }\n",
    );
    let names = unresolved_names(&ir);
    assert!(names.iter().any(|n| n == "x.poke"), "{names:?}");
}

#[test]
fn locals_do_not_leak_across_functions() {
    let ir = parse(
        "fn a() { let v = Vec::new(); v.push(1); }\n\
         fn b(v: &T) { v.push(1); }\n",
    );
    let names = unresolved_names(&ir);
    assert!(names.iter().any(|n| n == "Vec::push"), "{names:?}");
    assert!(names.iter().any(|n| n == "v.push"), "{names:?}");
}
