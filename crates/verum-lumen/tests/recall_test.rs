//! Recall floor: known true positives that FP-reduction work must never
//! silence. The `tests/fixtures/recall/` files each seed a labelled real issue;
//! if any stops firing, this test fails. This is the no-FN counterweight to the
//! no-FP corpus work - "minimal false positives" must not become "minimal
//! findings".

use verum_lumen::{Prism, Standard};
use verum_nucleus::FindingKind;

fn recall_findings() -> Vec<verum_nucleus::Finding> {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/recall");
    let config = verum_mappa::AtlasConfig {
        root: fixture,
        ..Default::default()
    };
    let ir = verum_mappa::Atlas::new(config)
        .build()
        .expect("map recall fixtures");
    Prism::analyse(&ir, &Standard::default())
        .expect("analyse recall fixtures")
        .findings
}

#[test]
fn known_true_positives_still_fire() {
    let findings = recall_findings();
    let has = |k: FindingKind| findings.iter().any(|f| f.kind == k);

    // Security - the trust-critical path. None of these may ever go silent.
    assert!(
        has(FindingKind::SqlInjection),
        "SQL injection must be caught"
    );
    assert!(
        has(FindingKind::WeakCrypto),
        "weak crypto (md5) must be caught"
    );
    assert!(
        has(FindingKind::EvalUsage),
        "eval on user input must be caught"
    );
    assert!(
        has(FindingKind::HardcodedSecret),
        "hardcoded secret must be caught"
    );
    assert!(
        has(FindingKind::XssVulnerability),
        "reflected XSS must be caught"
    );

    // Rust systems insights.
    assert!(has(FindingKind::PanicRisk), "hot-path panic must be caught");
    assert!(
        has(FindingKind::UnboundedChannel),
        "unbounded channel must be caught"
    );
    assert!(
        has(FindingKind::BlockingInAsync),
        "blocking-in-async must be caught"
    );

    // A genuinely dead private function must still be reported - the FP work on
    // trait methods / vtables / benches must not have blanketed real dead code.
    assert!(
        findings.iter().any(|f| {
            f.kind == FindingKind::DeadFunction && f.message.contains("orphaned_helper")
        }),
        "the genuinely dead `orphaned_helper` must be reported"
    );
}
