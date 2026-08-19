//! Same-named definitions in different files must not collapse onto one symbol.
//!
//! Module-private helpers repeated per file (`hash_path`, `count_params`) all
//! share a fully-qualified name. Binding every caller to whichever was indexed
//! first invents wrong call edges and leaves the other definitions looking
//! uncalled.

use verum_nucleus::{CallTarget, Ir, Language, SymbolId};

/// Tests run in parallel threads sharing one pid; a pid-only dir would make
/// one test's `remove_dir_all` race the other's build.
static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn build(files: &[(&str, &str)]) -> Ir {
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir =
        std::env::temp_dir().join(format!("verum_resolver_test_{}_{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp crate");
    for (name, source) in files {
        std::fs::write(dir.join(name), source).expect("write source");
    }

    let config = verum_mappa::AtlasConfig {
        root: dir.clone(),
        language: Language::Rust,
        ..Default::default()
    };
    let ir = verum_mappa::Atlas::new(config)
        .build()
        .expect("should build IR");
    let _ = std::fs::remove_dir_all(&dir);
    ir
}

const HELPER_A: &str = r#"
pub fn entry_a(s: &str) -> u64 {
    shared_helper(s)
}

fn shared_helper(s: &str) -> u64 {
    s.len() as u64
}
"#;

const HELPER_B: &str = r#"
pub fn entry_b(s: &str) -> u64 {
    shared_helper(s)
}

fn shared_helper(s: &str) -> u64 {
    (s.len() * 2) as u64
}
"#;

/// Every `shared_helper` definition must be the target of a call.
#[test]
fn duplicate_private_helpers_each_resolve_to_their_own_file() {
    let ir = build(&[("a.rs", HELPER_A), ("b.rs", HELPER_B)]);

    let helper_ids: Vec<SymbolId> = ir
        .symbols
        .iter()
        .filter(|(_, s)| s.name == "shared_helper")
        .map(|(id, _)| *id)
        .collect();
    assert_eq!(helper_ids.len(), 2, "both definitions should be extracted");

    for id in &helper_ids {
        let sym = &ir.symbols[id];
        let called_here = ir.calls.iter().any(|c| match &c.callee {
            // Resolved: must point at the definition in the caller's own file.
            CallTarget::Resolved(target) => target == id && c.file == sym.file,
            // Unresolved by name is also acceptable - it keeps liveness correct
            // without asserting a call edge that cannot be proven.
            CallTarget::Unresolved(n) => n == "shared_helper",
            _ => false,
        });
        assert!(
            called_here,
            "shared_helper in {} should be seen as called",
            sym.file.display()
        );
    }
}

/// A call must never bind to a same-named definition in an unrelated file.
#[test]
fn calls_do_not_bind_across_files() {
    let ir = build(&[("a.rs", HELPER_A), ("b.rs", HELPER_B)]);

    for call in &ir.calls {
        if let CallTarget::Resolved(target) = &call.callee {
            let Some(sym) = ir.symbols.get(target) else {
                continue;
            };
            if sym.name != "shared_helper" {
                continue;
            }
            assert_eq!(
                call.file,
                sym.file,
                "call in {} bound to shared_helper defined in {}",
                call.file.display(),
                sym.file.display()
            );
        }
    }
}
