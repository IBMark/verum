//! Attribute handling and impl-resolution precision.
//!
//! Substring matching on attributes used to make `#[cfg(not(test))]` read as a
//! test module and `#[cfg(feature = "latest")]` read as a test function, both
//! of which silently disabled dead-code analysis for the code involved.

use verum_nucleus::{Ir, SymbolKind};

/// Tests run in parallel threads, so each needs its own file - a shared name
/// races and one test parses another's source.
static SAMPLE_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn parse(source: &str) -> Ir {
    let seq = SAMPLE_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir =
        std::env::temp_dir().join(format!("verum_precision_test_{}_{seq}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("sample.rs");
    std::fs::write(&path, source).expect("write sample");
    let ir = verum_mappa::rust_lang::parse_file(&path).expect("should parse Rust source");
    let _ = std::fs::remove_dir_all(&dir);
    ir
}

fn symbol<'a>(ir: &'a Ir, name: &str) -> &'a verum_nucleus::Symbol {
    ir.symbols
        .values()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("symbol `{name}` not found"))
}

/// The fully-qualified name of `sym_name`'s parent symbol, if any. Each
/// `parse()` call re-seeds `SymbolId`s from a fresh temp file path, so raw
/// `SymbolId`s are not comparable across separate parses - the
/// fully-qualified name is the stable, content-derived thing to compare.
fn parent_fq(ir: &Ir, sym_name: &str) -> Option<String> {
    let parent_id = symbol(ir, sym_name).parent?;
    ir.symbols
        .get(&parent_id)
        .map(|s| s.fully_qualified.clone())
}

#[test]
fn cfg_not_test_module_is_production_code() {
    let ir = parse(
        r#"
#[cfg(not(test))]
mod prod {
    pub fn helper() {}
}
"#,
    );
    assert!(
        !symbol(&ir, "helper").is_entry_point,
        "#[cfg(not(test))] code must stay analysable as production code"
    );
}

#[test]
fn cfg_test_module_still_recognised() {
    let ir = parse(
        r#"
#[cfg(test)]
mod tests_inner {
    fn helper() {}
}
"#,
    );
    assert!(
        symbol(&ir, "helper").is_entry_point,
        "#[cfg(test)] module contents are test-only"
    );
}

#[test]
fn feature_named_latest_is_not_a_test() {
    let ir = parse(
        r#"
#[cfg(feature = "latest")]
fn gated() {}
"#,
    );
    assert!(
        !symbol(&ir, "gated").is_entry_point,
        "\"latest\" must not substring-match as a test attribute"
    );
}

#[test]
fn tokio_test_attribute_recognised() {
    let ir = parse(
        r#"
#[tokio::test]
async fn roundtrip() {}
"#,
    );
    assert!(symbol(&ir, "roundtrip").is_entry_point);
}

#[test]
fn allow_dead_code_suppresses_finding() {
    let ir = parse(
        r#"
#[allow(dead_code)]
fn kept_for_later() {}
"#,
    );
    assert!(
        symbol(&ir, "kept_for_later").is_entry_point,
        "#[allow(dead_code)] is an explicit opt-out"
    );
}

#[test]
fn generic_impl_binds_methods_to_type() {
    let ir = parse(
        r#"
pub struct Buffer<T> {
    items: Vec<T>,
}

impl<T> Buffer<T> {
    pub fn push(&mut self, item: T) {
        self.items.push(item);
    }
}
"#,
    );
    let buffer_id = symbol(&ir, "Buffer").id;
    let push = symbol(&ir, "push");
    assert_eq!(push.kind, SymbolKind::Method);
    assert_eq!(
        push.parent,
        Some(buffer_id),
        "impl Buffer<T> methods must parent to the Buffer symbol"
    );
}

#[test]
fn impl_before_type_declaration_still_binds() {
    let ir = parse(
        r#"
impl Widget {
    pub fn render(&self) {}
}

pub struct Widget {
    label: String,
}
"#,
    );
    let widget_id = symbol(&ir, "Widget").id;
    assert_eq!(
        symbol(&ir, "render").parent,
        Some(widget_id),
        "impl blocks above the type declaration must still find their parent"
    );
}

#[test]
fn impl_target_lookup_is_deterministic_under_name_collision() {
    // Two modules each declare a type named `Config`. Resolving `impl
    // Config` used to `.find()` a match directly off the symbol HashMap's
    // iteration order, so which `Config` a method bound to - and therefore
    // its method count - could flip between runs of the identical source,
    // purely from the process's random hash seed. Run the parse many times:
    // every run must bind `configure` to the same `Config`.
    let source = r#"
mod a {
    pub struct Config {
        pub x: i32,
    }
}

mod b {
    pub struct Config {
        pub y: i32,
    }

    impl Config {
        pub fn configure(&self) {}
    }
}
"#;

    let mut seen_parents: std::collections::HashSet<Option<String>> =
        std::collections::HashSet::new();
    for _ in 0..50 {
        let ir = parse(source);
        seen_parents.insert(parent_fq(&ir, "configure"));
    }
    assert_eq!(
        seen_parents.len(),
        1,
        "impl-target resolution must pick the same `Config` on every run, not vary with HashMap iteration order (saw: {seen_parents:?})"
    );
}

#[test]
fn impl_before_type_declaration_is_deterministic_under_name_collision() {
    // Same collision, but for the pending-impl-methods path: the impl block
    // appears before either `Config` is declared, forcing forward-reference
    // resolution once the whole file has been walked.
    let source = r#"
impl Config {
    pub fn configure(&self) {}
}

mod a {
    pub struct Config {
        pub x: i32,
    }
}

mod b {
    pub struct Config {
        pub y: i32,
    }
}
"#;

    let mut seen_parents: std::collections::HashSet<Option<String>> =
        std::collections::HashSet::new();
    for _ in 0..50 {
        let ir = parse(source);
        seen_parents.insert(parent_fq(&ir, "configure"));
    }
    assert_eq!(
        seen_parents.len(),
        1,
        "forward-declared impl resolution must pick the same `Config` on every run, not vary with HashMap iteration order (saw: {seen_parents:?})"
    );
}

#[test]
fn lifetimes_do_not_poison_normalized_hash() {
    // Identical bodies, different comments; lifetimes used to open a phantom
    // string in the comment stripper, dragging comment text into the hash.
    let ir = parse(
        r#"
fn first<'a>(input: &'a str) -> &'a str {
    // original wording here
    input.trim()
}

fn second<'a>(input: &'a str) -> &'a str {
    // completely different wording here
    input.trim()
}
"#,
    );
    let a = symbol(&ir, "first");
    let b = symbol(&ir, "second");
    // Identifiers are placeholder-normalised, so these are renamed duplicates
    // and must collide - before the fix, the lifetime `'a` opened a phantom
    // string that swallowed each function's (different) comment into the hash.
    assert_eq!(
        a.normalized_hash, b.normalized_hash,
        "comment-only differences must not alter normalized_hash in lifetime-using code"
    );
}

#[test]
fn char_literal_quotes_do_not_poison_normalized_hash() {
    // A `'"'` char literal used to open a phantom string in the comment
    // stripper, dragging each function's different comment into the hash.
    let ir = parse(
        r##"
fn first(s: &str) -> usize {
    // original wording
    s.chars().filter(|c| *c == '"').count()
}

fn second(s: &str) -> usize {
    // different wording entirely
    s.chars().filter(|c| *c == '"').count()
}
"##,
    );
    assert_eq!(
        symbol(&ir, "first").normalized_hash,
        symbol(&ir, "second").normalized_hash,
        "char literals containing quotes must not break comment stripping"
    );
}

#[test]
fn structural_flow_hash_catches_same_shape_different_constants() {
    // Same logic, different names AND different literals: invisible to
    // normalized_hash (it keeps literal values), caught by flow_hash.
    let ir = parse(
        r#"
fn handle_video(packets: &[u32]) -> u32 {
    let mut total = 0;
    for p in packets {
        if *p > 1200 {
            total += p * 2;
        } else {
            total += p + 7;
        }
    }
    total
}

fn handle_audio(frames: &[u32]) -> u32 {
    let mut sum = 0;
    for f in frames {
        if *f > 480 {
            sum += f * 3;
        } else {
            sum += f + 11;
        }
    }
    sum
}
"#,
    );
    let a = symbol(&ir, "handle_video");
    let b = symbol(&ir, "handle_audio");
    assert_ne!(a.flow_hash, 0, "a real body gets a flow hash");
    assert_eq!(
        a.flow_hash, b.flow_hash,
        "same shape must collide structurally"
    );
    assert_ne!(
        a.normalized_hash, b.normalized_hash,
        "normalized hash still separates them (different literals)"
    );
}

#[test]
fn trivial_bodies_get_no_flow_hash() {
    let ir = parse(
        r#"
fn tiny_a(&x: &u32) -> u32 { x }
fn tiny_b(&y: &u32) -> u32 { y }
"#,
    );
    assert_eq!(
        symbol(&ir, "tiny_a").flow_hash,
        0,
        "accessor-sized bodies share shapes by coincidence - no flow hash"
    );
}

#[test]
fn allow_dead_code_on_types_is_respected() {
    let ir = parse(
        r#"
#[allow(dead_code)]
pub struct Reserved {
    field: u32,
}
"#,
    );
    assert!(symbol(&ir, "Reserved").is_entry_point);
}

#[test]
fn test_functions_get_no_flow_hash() {
    let ir = parse(
        r#"
#[cfg(test)]
mod tests {
    #[test]
    fn case_one() {
        let mut total = 0;
        for p in [1u32, 2, 3] {
            if p > 1 { total += p * 2; } else { total += p + 7; }
        }
        assert_eq!(total, 18);
    }
}
"#,
    );
    assert_eq!(
        symbol(&ir, "case_one").flow_hash,
        0,
        "structural repetition in tests is convention, not duplication"
    );
}

#[test]
fn function_reference_argument_keeps_callee_alive() {
    let ir = parse(
        r#"
fn main() {
    let names: Vec<usize> = vec!["a", "bb"].into_iter().map(width).collect();
    let _ = names;
}

fn width(s: &str) -> usize {
    s.len()
}
"#,
    );
    let has_ref_edge = ir
        .calls
        .iter()
        .any(|c| matches!(&c.callee, verum_nucleus::CallTarget::Unresolved(n) if n == "width"));
    assert!(has_ref_edge, "`.map(width)` must register a use of `width`");
}

#[test]
fn module_paths_qualify_symbol_names() {
    // src/net/frame.rs -> net::frame::parse_frame
    let seq = SAMPLE_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("verum_modpath_{}_{seq}", std::process::id()));
    let net = dir.join("src/net");
    std::fs::create_dir_all(&net).expect("create dirs");
    let path = net.join("frame.rs");
    std::fs::write(&path, "pub fn parse_frame() {}\n").expect("write");
    let ir = verum_mappa::rust_lang::parse_file(&path).expect("parse");
    assert_eq!(
        symbol(&ir, "parse_frame").fully_qualified,
        "net::frame::parse_frame"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn use_imports_resolve_cross_module_calls() {
    // A call through `use crate::net::frame;` must resolve to the exact
    // definition, not stay a suffix guess.
    let seq = SAMPLE_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("verum_usealias_{}_{seq}", std::process::id()));
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("net")).expect("create dirs");
    std::fs::write(
        src.join("main.rs"),
        "use crate::net::frame;\n\nfn main() {\n    frame::parse_frame();\n}\n",
    )
    .expect("write main");
    std::fs::write(src.join("net/frame.rs"), "pub fn parse_frame() {}\n").expect("write frame");

    let config = verum_mappa::AtlasConfig {
        root: dir.clone(),
        language: verum_nucleus::Language::Rust,
        ..Default::default()
    };
    let ir = verum_mappa::Atlas::new(config)
        .build()
        .expect("atlas build");

    let target = ir
        .symbols
        .values()
        .find(|s| s.fully_qualified == "net::frame::parse_frame")
        .expect("module-qualified symbol exists");
    let resolved = ir
        .calls
        .iter()
        .any(|c| matches!(&c.callee, verum_nucleus::CallTarget::Resolved(id) if *id == target.id));
    assert!(
        resolved,
        "frame::parse_frame() must resolve to the exact definition"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn use_alias_and_group_imports_expand() {
    let ir = parse(
        r#"
use std::collections::{HashMap, BTreeMap as Tree};
use crate::codec::encode_frame;

fn main() {
    let _m: HashMap<u32, u32> = HashMap::new();
    encode_frame();
}

mod codec {
    pub fn encode_frame() {}
}
"#,
    );
    // The import-qualified call carries the full path even before resolution.
    let has_qualified = ir.calls.iter().any(|c| {
        matches!(&c.callee, verum_nucleus::CallTarget::Unresolved(n) if n == "codec::encode_frame")
    });
    assert!(
        has_qualified,
        "use-imported call should be emitted fully qualified"
    );
}

#[test]
fn module_level_static_initializer_keeps_referenced_fns_alive() {
    // Waker vtables: fns referenced only from a `static`/`const` initializer at
    // module scope used to be dropped (no enclosing fn) and read as dead.
    let ir = parse(
        r#"
use std::task::RawWakerVTable;

static VTABLE: RawWakerVTable =
    RawWakerVTable::new(clone_waker, wake_waker, wake_by_ref_waker, drop_waker);

fn clone_waker(_: *const ()) -> std::task::RawWaker { unreachable!() }
fn wake_waker(_: *const ()) {}
fn wake_by_ref_waker(_: *const ()) {}
fn drop_waker(_: *const ()) {}
"#,
    );
    for f in [
        "clone_waker",
        "wake_waker",
        "wake_by_ref_waker",
        "drop_waker",
    ] {
        let referenced = ir
            .calls
            .iter()
            .any(|c| matches!(&c.callee, verum_nucleus::CallTarget::Unresolved(n) if n == f));
        assert!(
            referenced,
            "`{f}` referenced in the vtable must produce a call edge"
        );
    }
}

#[test]
fn serde_attribute_referenced_fn_is_not_dead() {
    // A fn used only via `#[serde(serialize_with = "...")]` must be kept alive.
    let ir = parse(
        r#"
struct Config {
    #[serde(serialize_with = "write_hex")]
    color: u32,
    #[serde(skip_serializing_if = "is_default_port")]
    port: u16,
}

fn write_hex<S>(v: &u32, s: S) -> Result<S::Ok, S::Error> { s.serialize_u32(*v) }
fn is_default_port(p: &u16) -> bool { *p == 8080 }
"#,
    );
    for f in ["write_hex", "is_default_port"] {
        let referenced = ir
            .calls
            .iter()
            .any(|c| matches!(&c.callee, verum_nucleus::CallTarget::Unresolved(n) if n == f));
        assert!(
            referenced,
            "`{f}` referenced via a serde attribute must produce a use edge"
        );
    }
}

#[test]
fn return_type_inference_types_a_local_from_a_bare_call() {
    // `let c = connect();` must type `c` as Connection (connect's return),
    // so `c.query()` resolves to Connection::query.
    let ir = parse(
        r#"
struct Connection;
impl Connection {
    fn query(&self) -> u32 { 0 }
}

fn connect() -> Connection { Connection }

fn run() {
    let c = connect();
    c.query();
}
"#,
    );
    // The method call should be emitted receiver-typed as `Connection::query`.
    let typed = ir.calls.iter().any(|call| {
        matches!(&call.callee, verum_nucleus::CallTarget::Unresolved(n) if n == "Connection::query")
            || matches!(&call.callee, verum_nucleus::CallTarget::Resolved(id)
                if ir.symbols.get(id).map(|s| s.name.as_str()) == Some("query"))
    });
    assert!(
        typed,
        "c.query() should resolve via connect()'s return type"
    );
}
