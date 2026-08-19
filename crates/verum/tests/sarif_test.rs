//! End-to-end test: `verum report --format sarif` emits valid SARIF 2.1.0 that
//! GitHub code scanning can ingest.

use std::process::Command;

#[test]
fn sarif_report_is_valid() {
    let bin = env!("CARGO_BIN_EXE_verum");
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/php_security");

    let out = Command::new(bin)
        .args(["report", fixture.to_str().unwrap(), "--format", "sarif"])
        .output()
        .expect("run verum");
    assert!(out.status.success(), "verum report exited non-zero");

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("output is valid JSON");
    assert_eq!(v["version"], "2.1.0");

    let run = &v["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "Verum");
    assert!(
        !run["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .is_empty(),
        "a rule catalog is present"
    );

    let results = run["results"].as_array().expect("results array");
    assert!(
        !results.is_empty(),
        "the vulnerable fixture yields findings"
    );
    for r in results {
        assert!(r["ruleId"].is_string(), "each result names a rule");
        let level = r["level"].as_str().unwrap();
        assert!(
            ["error", "warning", "note"].contains(&level),
            "unexpected SARIF level {level}"
        );
        let region = &r["locations"][0]["physicalLocation"]["region"];
        assert!(
            region["startLine"].as_u64().unwrap() >= 1,
            "each result has a 1-based start line"
        );
    }
}
