//! The shared [`ScanContext`] must be invisible to findings.
//!
//! `transport`, `taint` and `rust_insights` can each be driven two ways: from a
//! pre-read context (what the full pipeline does, so one read and one symbol
//! index serve all three) or standalone (reading each file on demand). Those two
//! paths must agree exactly, or a performance change would silently move
//! findings.

use std::path::PathBuf;

use verum_lumen::scan::ScanContext;
use verum_nucleus::{Finding, Ir};

fn fixture_ir(name: &str) -> Ir {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .parent()
        .expect("repo root")
        .join("tests/fixtures")
        .join(name);
    let atlas = verum_mappa::Atlas::new(verum_mappa::AtlasConfig {
        root,
        ..Default::default()
    });
    atlas.build().expect("fixture should parse")
}

/// Findings compared in full, so a drifting message or confidence fails too.
fn rendered(findings: &[Finding]) -> Vec<String> {
    findings.iter().map(|f| format!("{f:?}")).collect()
}

fn assert_context_is_invisible(fixture: &str) {
    let ir = fixture_ir(fixture);
    let ctx = ScanContext::build(&ir);

    assert_eq!(
        rendered(&verum_lumen::transport::analyse_with_context(&ir, &ctx)),
        rendered(&verum_lumen::transport::analyse(&ir)),
        "transport findings differ between the shared and standalone paths on {fixture}",
    );
    assert_eq!(
        rendered(&verum_lumen::rust_insights::analyse_with_context(&ir, &ctx)),
        rendered(&verum_lumen::rust_insights::analyse(&ir)),
        "rust_insights findings differ between the shared and standalone paths on {fixture}",
    );
    assert_eq!(
        rendered(&verum_lumen::taint::analyse_with_context(&ir, &ctx).0),
        rendered(&verum_lumen::taint::analyse(&ir)),
        "taint findings differ between the shared and standalone paths on {fixture}",
    );
}

/// Positive: on a fixture the passes actually fire on, both paths report the
/// same findings - and there are some, so the equality is not vacuous.
#[test]
fn shared_context_reproduces_findings_on_a_firing_fixture() {
    let ir = fixture_ir("rust_net_server");
    let ctx = ScanContext::build(&ir);

    let shared = verum_lumen::rust_insights::analyse_with_context(&ir, &ctx);
    assert!(
        !shared.is_empty(),
        "rust_net_server should produce rust_insights findings, \
         otherwise this test proves nothing"
    );
    assert_context_is_invisible("rust_net_server");
}

/// Negative: a fixture in a language these passes mostly skip must stay just as
/// quiet through the shared context - no finding is invented by pre-reading.
#[test]
fn shared_context_invents_no_findings() {
    assert_context_is_invisible("php_security");
    assert_context_is_invisible("go_simple");
}

/// The symbol index must hold exactly the symbols each file declares - that
/// equivalence is what lets the passes drop their `symbol.file == path` scan.
#[test]
fn symbol_index_matches_a_direct_scan() {
    let ir = fixture_ir("rust_net_server");
    let ctx = ScanContext::build(&ir);

    let mut files: Vec<&PathBuf> = ir.files.keys().collect();
    files.sort();
    assert!(!files.is_empty(), "fixture should have files");

    for file in files {
        let mut direct: Vec<u64> = ir
            .symbols
            .values()
            .filter(|s| &s.file == file)
            .map(|s| s.id.0)
            .collect();
        direct.sort_unstable();

        let indexed: Vec<u64> = ctx.symbols(file).iter().map(|id| id.0).collect();
        assert_eq!(direct, indexed, "symbol index disagrees for {file:?}");
    }
}
