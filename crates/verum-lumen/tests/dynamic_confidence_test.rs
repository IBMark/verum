//! Dynamic-call confidence is scoped per symbol, not codebase-global.
//!
//! One `call_user_func` used to drop every dead-code finding in the project to
//! 0.60 - below the auto-fix bar - so a single dynamic call silently disabled
//! `verum clean` everywhere.

use verum_nucleus::Ir;

/// Tests across this binary run in parallel threads that share one pid, so a
/// pid-only temp dir is a shared path - each call gets a fresh dir instead.
static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn parse_php(dir: &std::path::Path, name: &str, source: &str) -> Ir {
    let path = dir.join(name);
    std::fs::write(&path, source).expect("write sample");
    verum_mappa::php::parse_file(&path).expect("should parse PHP source")
}

#[test]
fn dynamic_calls_only_lower_confidence_where_they_can_reach() {
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("verum_dynamic_conf_{}_{seq}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");

    let mut ir = parse_php(
        &dir,
        "dispatch.php",
        r#"<?php
function alpha() {
    call_user_func($GLOBALS['handler']);
}
function alpha_dead() {
    return 1;
}
"#,
    );
    ir.merge(parse_php(
        &dir,
        "helpers.php",
        r#"<?php
function beta_dead() {
    return 2;
}
"#,
    ));

    let findings = verum_lumen::dead_code::analyse(&ir, &Default::default());
    let confidence = |name: &str| {
        findings
            .iter()
            .find(|f| {
                f.symbol
                    .and_then(|id| ir.symbols.get(&id))
                    .is_some_and(|s| s.name == name)
            })
            .unwrap_or_else(|| panic!("expected a dead-code finding for `{name}`"))
            .confidence
    };

    // Same file as the dynamic call: could plausibly be its target.
    assert!(
        (confidence("alpha_dead") - 0.60).abs() < 1e-6,
        "symbols sharing a file with a dynamic call stay low-confidence"
    );
    // Different file, name never mentioned dynamically: full confidence.
    assert!(
        (confidence("beta_dead") - 0.95).abs() < 1e-6,
        "a dynamic call elsewhere must not lower confidence globally"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
