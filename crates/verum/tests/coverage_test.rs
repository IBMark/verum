//! End-to-end: `verum report --coverage <lcov>` ingests measured coverage,
//! reports it as measured, and lets it replace the static reachability
//! estimate in the score.

use std::path::{Path, PathBuf};
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

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .parent()
        .expect("workspace root")
        .join("tests/fixtures")
        .join(name)
}

fn report_json(args: &[&str]) -> serde_json::Value {
    let output = run_verum(args);
    assert!(
        output.status.success(),
        "verum {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("report is valid JSON")
}

#[test]
fn measured_coverage_is_ingested_and_labelled() {
    let target = fixture("loc_tested");
    let lcov = fixture("coverage/lcov.info");
    let json = report_json(&[
        "report",
        target.to_str().unwrap(),
        "--format",
        "json",
        "--coverage",
        lcov.to_str().unwrap(),
    ]);

    let measured = &json["measured_coverage"];
    assert_eq!(measured["format"], "lcov");
    assert_eq!(measured["lines_found"], 10);
    assert_eq!(measured["lines_hit"], 6);
    assert_eq!(measured["line_percent"], 60.0);
    assert_eq!(measured["functions_found"], 3);
    assert_eq!(measured["functions_hit"], 2);

    // Measured data replaces the static estimate in the score dimension.
    assert_eq!(json["score_after"]["test_coverage"], 60);
}

#[test]
fn without_coverage_the_report_carries_only_the_static_estimate() {
    let target = fixture("loc_tested");
    let json = report_json(&["report", target.to_str().unwrap(), "--format", "json"]);

    assert!(
        json.get("measured_coverage").is_none(),
        "nothing was measured, so nothing is claimed"
    );
    let reachability = &json["test_reachability"];
    assert!(reachability["test_roots"].as_u64().expect("a number") > 0);
    assert!(reachability["reachable"].as_u64().expect("a number") > 0);
}

#[test]
fn the_json_report_keeps_every_field_it_had_before() {
    // The new sections are additive: nothing that consumed this report can
    // break because a field moved or was renamed.
    let target = fixture("loc_tested");
    let json = report_json(&["report", target.to_str().unwrap(), "--format", "json"]);
    for field in [
        "score_before",
        "score_after",
        "lines_before",
        "lines_after",
        "passes",
        "findings",
        "auto_fixed",
        "ai_decisions",
        "human_review",
        "duplicate_groups",
        "duration_ms",
        "deploy_gate_passed",
        "deploy_gate_reasons",
    ] {
        assert!(json.get(field).is_some(), "{field} must still be present");
    }
    assert!(json.get("loc").is_some());
    assert!(json.get("test_reachability").is_some());
}

#[test]
fn line_counts_appear_in_the_report() {
    let target = fixture("loc_tested");
    let json = report_json(&["report", target.to_str().unwrap(), "--format", "json"]);
    let totals = &json["loc"]["totals"];
    let (total, code, comment, blank) = (
        totals["total"].as_u64().expect("a number"),
        totals["code"].as_u64().expect("a number"),
        totals["comment"].as_u64().expect("a number"),
        totals["blank"].as_u64().expect("a number"),
    );
    assert!(total > 0);
    assert_eq!(code + comment + blank, total, "buckets partition the lines");
}

#[test]
fn a_malformed_coverage_file_fails_loudly() {
    let target = fixture("loc_tested");
    let broken = fixture("coverage/broken.info");
    let output = run_verum(&[
        "report",
        target.to_str().unwrap(),
        "--format",
        "json",
        "--coverage",
        broken.to_str().unwrap(),
    ]);
    assert!(
        !output.status.success(),
        "a coverage file that does not parse must not read as zero coverage"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lcov") && stderr.contains("line 2"),
        "the error should name the format and the offending line: {stderr}"
    );
}

#[test]
fn a_missing_coverage_file_fails_loudly() {
    let target = fixture("loc_tested");
    let output = run_verum(&[
        "report",
        target.to_str().unwrap(),
        "--format",
        "json",
        "--coverage",
        "/no/such/lcov.info",
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("/no/such/lcov.info"));
}

#[test]
fn the_markdown_report_shows_the_per_file_table() {
    let target = fixture("loc_tested");
    let output = run_verum(&["report", target.to_str().unwrap()]);
    assert!(output.status.success());
    let md = String::from_utf8_lossy(&output.stdout);
    assert!(md.contains("## Lines of code"), "{md}");
    assert!(
        md.contains("| File | Lines | Code | Comments | Funcs | Test-reach% |"),
        "{md}"
    );
    assert!(md.contains("## Test reachability (static)"), "{md}");
    assert!(
        !md.contains("## Measured coverage"),
        "nothing was measured: {md}"
    );
}

#[test]
fn the_markdown_report_labels_measured_coverage_as_measured() {
    let target = fixture("loc_tested");
    let lcov = fixture("coverage/lcov.info");
    let output = run_verum(&[
        "report",
        target.to_str().unwrap(),
        "--coverage",
        lcov.to_str().unwrap(),
    ]);
    assert!(output.status.success());
    let md = String::from_utf8_lossy(&output.stdout);
    assert!(md.contains("## Measured coverage"), "{md}");
    assert!(md.contains("Test coverage (measured)"), "{md}");
    assert!(md.contains("did not run any tests"), "{md}");
}

#[test]
fn the_same_input_produces_the_same_measurements() {
    // The report as a whole carries a wall-clock `duration_ms`; every section
    // this feature adds must be byte-identical run to run.
    let target = fixture("loc_tested");
    let lcov = fixture("coverage/lcov.info");
    let args = [
        "report",
        target.to_str().unwrap(),
        "--format",
        "json",
        "--coverage",
        lcov.to_str().unwrap(),
    ];
    let first = report_json(&args);
    let second = report_json(&args);
    for section in ["loc", "test_reachability", "measured_coverage", "findings"] {
        assert_eq!(
            serde_json::to_string(&first[section]).expect("serializable"),
            serde_json::to_string(&second[section]).expect("serializable"),
            "{section} must be identical for identical input"
        );
    }
}
