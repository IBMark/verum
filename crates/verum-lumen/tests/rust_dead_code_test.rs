//! Rust-specific dead-code awareness.
//!
//! Two idioms have no in-crate caller yet are plainly reachable: the `pub` API
//! of a library crate (called by downstream crates) and functions exported to a
//! linker, wasm host or async runtime via attribute. Reporting them as dead is
//! noise that buries real findings.

static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Writes `source` as the given crate-root file name (`lib.rs` or `main.rs`),
/// which is what distinguishes a library crate from a binary one, then returns
/// the names of the symbols reported dead.
fn analyse_crate(root_file: &str, source: &str) -> Vec<String> {
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let crate_dir =
        std::env::temp_dir().join(format!("verum_rust_dead_{}_{}", std::process::id(), seq));
    let src = crate_dir.join("src");
    std::fs::create_dir_all(&src).expect("create temp crate");
    let path = src.join(root_file);
    std::fs::write(&path, source).expect("write crate root");

    let ir = verum_mappa::rust_lang::parse_file(&path).expect("should parse Rust source");
    let findings = verum_lumen::dead_code::analyse(&ir, &Default::default());

    let names = findings
        .iter()
        .filter_map(|f| f.symbol)
        .filter_map(|id| ir.symbols.get(&id).map(|s| s.name.clone()))
        .collect();

    let _ = std::fs::remove_dir_all(&crate_dir);
    names
}

/// Like `analyse_crate`, but writes the source at an arbitrary path relative to
/// the temp crate root (e.g. `benches/foo.rs`), so tests can exercise the
/// per-target directories Cargo compiles independently.
fn analyse_at(rel_path: &str, source: &str) -> Vec<String> {
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let crate_dir =
        std::env::temp_dir().join(format!("verum_rust_dead_{}_{}", std::process::id(), seq));
    let path = crate_dir.join(rel_path);
    std::fs::create_dir_all(path.parent().unwrap()).expect("create temp dirs");
    std::fs::write(&path, source).expect("write source");

    let ir = verum_mappa::rust_lang::parse_file(&path).expect("should parse Rust source");
    let findings = verum_lumen::dead_code::analyse(&ir, &Default::default());

    let names = findings
        .iter()
        .filter_map(|f| f.symbol)
        .filter_map(|id| ir.symbols.get(&id).map(|s| s.name.clone()))
        .collect();

    let _ = std::fs::remove_dir_all(&crate_dir);
    names
}

#[test]
fn benchmark_helpers_are_not_dead() {
    // A file under benches/ is its own compiled target; its helpers are invoked
    // by the bench runner / criterion macros, not by name from the call graph.
    let dead = analyse_at(
        "benches/my_bench.rs",
        r#"
fn bench_contention() -> u32 {
    1
}
"#,
    );
    assert!(
        !dead.iter().any(|n| n == "bench_contention"),
        "a benches/ helper has no cross-file caller and must not be reported dead, got {dead:?}"
    );
}

#[test]
fn example_helpers_are_not_dead() {
    let dead = analyse_at(
        "examples/demo.rs",
        r#"
fn helper() -> u32 {
    1
}

fn main() {
    let _ = helper();
}
"#,
    );
    assert!(
        !dead.iter().any(|n| n == "helper"),
        "an examples/ helper must not be reported dead, got {dead:?}"
    );
}

#[test]
fn uncalled_fn_in_src_is_still_dead_regression() {
    // Regression guard: the benches/examples skip must not leak into src/.
    let dead = analyse_at(
        "src/lib.rs",
        r#"
fn dead_in_src() -> u32 {
    1
}
"#,
    );
    assert!(
        dead.iter().any(|n| n == "dead_in_src"),
        "a private uncalled fn under src/ must still be reported, got {dead:?}"
    );
}

const SAMPLE: &str = r#"
pub fn public_api() -> u32 {
    7
}

#[no_mangle]
pub extern "C" fn ffi_entry() -> u32 {
    7
}

#[wasm_bindgen]
pub fn wasm_entry() -> u32 {
    7
}

fn truly_dead() -> u32 {
    1
}
"#;

#[test]
fn public_api_of_a_library_crate_is_not_dead() {
    let dead = analyse_crate("lib.rs", SAMPLE);
    assert!(
        !dead.iter().any(|n| n == "public_api"),
        "pub fn in a lib crate is the published API, got {dead:?}"
    );
}

#[test]
fn exported_entry_points_are_not_dead() {
    let dead = analyse_crate("lib.rs", SAMPLE);
    for entry in ["ffi_entry", "wasm_entry"] {
        assert!(
            !dead.iter().any(|n| n == entry),
            "{entry} is reachable from outside the crate, got {dead:?}"
        );
    }
}

#[test]
fn genuinely_unused_private_function_is_still_reported() {
    let dead = analyse_crate("lib.rs", SAMPLE);
    assert!(
        dead.iter().any(|n| n == "truly_dead"),
        "a private uncalled fn must still be reported, got {dead:?}"
    );
}

#[test]
fn pub_in_a_binary_crate_gets_no_api_pass() {
    // No lib.rs, so `pub` grants no external reach and the item really is dead.
    let dead = analyse_crate(
        "main.rs",
        r#"
fn main() {}

pub fn unused_helper() -> u32 {
    1
}
"#,
    );
    assert!(
        dead.iter().any(|n| n == "unused_helper"),
        "pub in a bin crate is not an API surface, got {dead:?}"
    );
}

#[test]
fn calls_inside_macros_keep_their_callee_alive() {
    // End-to-end guard for the macro token-stream fix: `greet` is only ever
    // called from inside `println!`.
    let dead = analyse_crate(
        "main.rs",
        r#"
fn main() {
    println!("{}", greet("world"));
}

fn greet(who: &str) -> String {
    String::from(who)
}
"#,
    );
    assert!(
        !dead.iter().any(|n| n == "greet"),
        "greet() is called inside println!, got {dead:?}"
    );
}

#[test]
fn underscore_prefix_is_intentionally_unused() {
    let dead = analyse_crate(
        "main.rs",
        r#"
fn main() {}

fn _kept_on_purpose() -> u32 {
    3
}
"#,
    );
    assert!(
        !dead.iter().any(|n| n == "_kept_on_purpose"),
        "a leading underscore already declares the item unused, got {dead:?}"
    );
}

#[test]
fn cfg_not_test_helpers_are_still_analysed() {
    // #[cfg(not(test))] used to be misread as a test module, hiding everything
    // inside it from dead-code analysis.
    let dead = analyse_crate(
        "main.rs",
        r#"
fn main() {}

#[cfg(not(test))]
mod runtime {
    fn genuinely_dead() -> u32 {
        9
    }
}
"#,
    );
    assert!(
        dead.iter().any(|n| n == "genuinely_dead"),
        "production-only modules must stay visible to dead-code analysis, got {dead:?}"
    );
}
