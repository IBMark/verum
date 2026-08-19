//! End-to-end test: `verum report --format sarif` emits valid SARIF 2.1.0 that
//! GitHub code scanning can ingest.

use std::process::Command;

/// Run the just-built `verum` binary, retrying on ETXTBSY: on CI another
/// process can transiently hold the freshly linked executable open for
/// writing, which makes exec fail with "text file busy".
fn run_verum(args: &[&str]) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_verum");
    let mut attempts = 0u32;
    loop {
        match Command::new(bin).args(args).output() {
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy && attempts < 50 => {
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            other => return other.expect("run verum"),
        }
    }
}

#[test]
fn sarif_report_is_valid() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/php_security");

    let out = run_verum(&["report", fixture.to_str().unwrap(), "--format", "sarif"]);
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
