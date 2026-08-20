//! End-to-end: `verum check` - the machine verdict.
//!
//! Covers the JSON contract shape, the stable exit codes (0 pass / 1 fail /
//! 2 operational error), the --files view filter, the fail-then-fix loop a
//! coding agent runs, determinism of the verdict bytes, and the opt-in
//! VERUM_STATS local stats line.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Run the just-built `verum` binary, retrying on ETXTBSY: on CI another
/// process can transiently hold the freshly linked executable open for
/// writing, which makes exec fail with "text file busy".
fn run_verum_env(args: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_verum");
    let mut attempts = 0u32;
    loop {
        let mut cmd = Command::new(bin);
        cmd.args(args)
            .env_remove("VERUM_STATS")
            .env_remove("VERUM_STATS_FILE");
        for (k, v) in envs {
            cmd.env(k, v);
        }
        match cmd.output() {
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy && attempts < 50 => {
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            other => return other.expect("run verum"),
        }
    }
}

fn run_verum(args: &[&str]) -> std::process::Output {
    run_verum_env(args, &[])
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

fn check_json(args: &[&str]) -> (serde_json::Value, i32) {
    let output = run_verum(args);
    let code = output.status.code().expect("an exit code");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("verdict is valid JSON ({e}): {args:?}"));
    (json, code)
}

/// A scratch directory that cleans up after itself.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("verum-check-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        TempDir(dir)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// JSON contract
// ---------------------------------------------------------------------------

#[test]
fn json_contract_shape_on_a_failing_tree() {
    let target = fixture("php_security");
    let (json, code) = check_json(&["check", target.to_str().unwrap()]);

    assert_eq!(code, 1, "critical findings must exit 1");
    assert_eq!(json["pass"], false);

    // counts: the four documented buckets, summing to findings.len()
    let counts = &json["counts"];
    for key in ["critical", "high", "medium", "low"] {
        assert!(counts[key].is_u64(), "counts.{key} must be a number");
    }
    let findings = json["findings"].as_array().expect("findings is an array");
    let sum = ["critical", "high", "medium", "low"]
        .iter()
        .map(|k| counts[k].as_u64().unwrap())
        .sum::<u64>() as usize;
    assert_eq!(sum, findings.len(), "counts must sum to findings.len()");
    assert!(counts["critical"].as_u64().unwrap() >= 1);

    // per-finding shape
    for f in findings {
        for key in [
            "kind",
            "severity",
            "file",
            "message",
            "why",
            "fix_hint",
            "suggestion",
        ] {
            let v = f[key]
                .as_str()
                .unwrap_or_else(|| panic!("{key} is a string: {f}"));
            if key != "suggestion" {
                assert!(!v.trim().is_empty(), "{key} must be non-empty: {f}");
            }
        }
        assert!(f["line"].is_u64(), "line is a number: {f}");
        assert!(f["confidence"].is_number(), "confidence is a number: {f}");
        assert!(
            ["critical", "high", "medium", "low"].contains(&f["severity"].as_str().unwrap()),
            "severity is one of the four levels: {f}"
        );
        // paths are root-relative, never absolute
        assert!(
            !f["file"].as_str().unwrap().starts_with('/'),
            "file is root-relative: {f}"
        );
    }

    // findings are sorted by severity, highest first
    let ranks: Vec<i32> = findings
        .iter()
        .map(|f| match f["severity"].as_str().unwrap() {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            _ => 1,
        })
        .collect();
    let mut sorted = ranks.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    assert_eq!(
        ranks, sorted,
        "findings must be severity-sorted, highest first"
    );

    assert!(json["duration_ms"].is_u64());

    // stdout carried exactly one JSON object and nothing else
    let output = run_verum(&["check", target.to_str().unwrap()]);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        stdout.trim().lines().count(),
        1,
        "stdout is the verdict only"
    );
}

#[test]
fn a_clean_tree_passes_with_exit_zero() {
    let target = fixture("loc_tested");
    let (json, code) = check_json(&["check", target.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert_eq!(json["pass"], true);
    assert_eq!(json["findings"].as_array().unwrap().len(), 0);
}

#[test]
fn fail_on_threshold_is_respected() {
    // php_simple has medium findings but nothing high/critical:
    // default (--fail-on high) passes, --fail-on medium fails.
    let target = fixture("php_simple");
    let (json, code) = check_json(&["check", target.to_str().unwrap()]);
    assert_eq!(code, 0, "medium findings pass the default high threshold");
    assert_eq!(json["pass"], true);
    assert!(json["counts"]["medium"].as_u64().unwrap() > 0);

    let (json, code) = check_json(&["check", target.to_str().unwrap(), "--fail-on", "medium"]);
    assert_eq!(code, 1);
    assert_eq!(json["pass"], false);
}

// ---------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------

#[test]
fn missing_path_is_an_operational_error_exit_two() {
    let output = run_verum(&["check", "/no/such/path/anywhere-at-all"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "no verdict on operational error");
    assert!(!output.stderr.is_empty(), "the error goes to stderr");
}

#[test]
fn bad_flag_value_is_an_operational_error_exit_two() {
    let target = fixture("php_simple");
    let output = run_verum(&[
        "check",
        target.to_str().unwrap(),
        "--fail-on",
        "catastrophic",
    ]);
    assert_eq!(output.status.code(), Some(2));

    let output = run_verum(&["check", target.to_str().unwrap(), "--format", "xml"]);
    assert_eq!(output.status.code(), Some(2));
}

// ---------------------------------------------------------------------------
// --files view filter
// ---------------------------------------------------------------------------

#[test]
fn files_filter_narrows_the_verdict_to_a_view() {
    let target = fixture("php_security");

    // Filtering to the file with the findings changes nothing.
    let (unfiltered, _) = check_json(&["check", target.to_str().unwrap()]);
    let (filtered, code) = check_json(&[
        "check",
        target.to_str().unwrap(),
        "--files",
        "vulnerable.php",
    ]);
    assert_eq!(code, 1);
    assert_eq!(unfiltered["findings"], filtered["findings"]);

    // Filtering to a file with no findings empties the view - and pass
    // follows the view (the filter narrows the verdict, not the analysis).
    let (empty, code) = check_json(&[
        "check",
        target.to_str().unwrap(),
        "--files",
        "some_other_file.php",
    ]);
    assert_eq!(code, 0);
    assert_eq!(empty["pass"], true);
    assert_eq!(empty["findings"].as_array().unwrap().len(), 0);
    assert_eq!(empty["counts"]["critical"], 0);
}

// ---------------------------------------------------------------------------
// The agent loop: fail with a hint, apply the hint, pass
// ---------------------------------------------------------------------------

const BUGGY_PHP: &str = r#"<?php

function runScript() {
    $cmd = $_POST['command'];
    eval($cmd);
}

runScript();
"#;

const FIXED_PHP: &str = r#"<?php

function runScript() {
    $cmd = $_POST['command'];
    $allowed = ['status' => 'showStatus', 'reload' => 'reloadConfig'];
    if (isset($allowed[$cmd])) {
        $allowed[$cmd]();
    }
}

runScript();
"#;

#[test]
fn introduce_bug_check_fails_with_hint_fix_it_check_passes() {
    let dir = TempDir::new("agent-loop");
    let file = dir.path().join("runner.php");

    // Introduce the bug: eval on request input.
    std::fs::write(&file, BUGGY_PHP).unwrap();
    let (json, code) = check_json(&["check", dir.path().to_str().unwrap()]);
    assert_eq!(code, 1, "the bug must fail the check");
    assert_eq!(json["pass"], false);
    let findings = json["findings"].as_array().unwrap();
    let eval_finding = findings
        .iter()
        .find(|f| f["kind"] == "EvalUsage")
        .expect("an EvalUsage finding");
    let hint = eval_finding["fix_hint"].as_str().unwrap();
    assert!(
        hint.contains("whitelisted map"),
        "the hint names the concrete edit: {hint}"
    );
    assert!(
        hint.contains("runner.php"),
        "the hint cites the location: {hint}"
    );

    // Apply the hint (explicit whitelisted dispatch instead of eval).
    std::fs::write(&file, FIXED_PHP).unwrap();
    let (json, code) = check_json(&["check", dir.path().to_str().unwrap()]);
    assert_eq!(code, 0, "after applying the hint the check passes: {json}");
    assert_eq!(json["pass"], true);
    assert!(
        !json["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["kind"] == "EvalUsage"),
        "the EvalUsage finding is gone"
    );
}

// ---------------------------------------------------------------------------
// Determinism and formats
// ---------------------------------------------------------------------------

#[test]
fn verdict_is_deterministic_apart_from_duration() {
    let target = fixture("php_security");
    let (mut a, _) = check_json(&["check", target.to_str().unwrap()]);
    let (mut b, _) = check_json(&["check", target.to_str().unwrap()]);
    a.as_object_mut().unwrap().remove("duration_ms");
    b.as_object_mut().unwrap().remove("duration_ms");
    assert_eq!(a, b, "identical input must yield an identical verdict");
}

#[test]
fn text_format_prints_verdict_and_hints() {
    let target = fixture("php_security");
    let output = run_verum(&["check", target.to_str().unwrap(), "--format", "text"]);
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("FAIL "), "verdict first: {stdout}");
    assert!(stdout.contains("fix: "), "hints are printed");
    assert!(stdout.contains("why: "), "consequences are printed");

    let clean = fixture("loc_tested");
    let output = run_verum(&["check", clean.to_str().unwrap(), "--format", "text"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("PASS "));
}

// ---------------------------------------------------------------------------
// Opt-in local stats
// ---------------------------------------------------------------------------

#[test]
fn stats_line_is_appended_only_when_opted_in() {
    let dir = TempDir::new("stats");
    let stats_file = dir.path().join("stats.jsonl");
    let target = fixture("php_security");

    // Off by default: no stats file appears.
    let output = run_verum_env(
        &["check", target.to_str().unwrap()],
        &[("VERUM_STATS_FILE", stats_file.to_str().unwrap())],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(!stats_file.exists(), "no stats without VERUM_STATS=1");

    // Opted in: exactly one line per invocation, with the documented fields
    // and no code text.
    for _ in 0..2 {
        let output = run_verum_env(
            &["check", target.to_str().unwrap()],
            &[
                ("VERUM_STATS", "1"),
                ("VERUM_STATS_FILE", stats_file.to_str().unwrap()),
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(1),
            "stats never affect the exit code"
        );
    }
    let content = std::fs::read_to_string(&stats_file).unwrap();
    let lines: Vec<&str> = content.trim().lines().collect();
    assert_eq!(lines.len(), 2, "one line per invocation");
    for line in lines {
        let entry: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(entry["cmd"], "check");
        assert_eq!(entry["pass"], false);
        assert!(entry["ts_ms"].is_u64());
        assert!(entry["duration_ms"].is_u64());
        assert!(entry["counts"]["critical"].is_u64());
        assert!(
            !line.contains("eval") && !line.contains("vulnerable.php"),
            "stats must not carry code text or scanned-file paths it was never given: {line}"
        );
    }

    // The verdict bytes are identical with and without stats enabled.
    let (mut with_stats, _) = {
        let output = run_verum_env(
            &["check", target.to_str().unwrap()],
            &[
                ("VERUM_STATS", "1"),
                ("VERUM_STATS_FILE", stats_file.to_str().unwrap()),
            ],
        );
        (
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
            output.status.code(),
        )
    };
    let (mut without_stats, _) = check_json(&["check", target.to_str().unwrap()]);
    with_stats.as_object_mut().unwrap().remove("duration_ms");
    without_stats.as_object_mut().unwrap().remove("duration_ms");
    assert_eq!(with_stats, without_stats);
}

#[test]
fn empty_analysis_is_an_operational_error_exit_two() {
    // A directory with nothing analysable must not produce a passing verdict:
    // a typo'd hook path would otherwise wave every edit through forever.
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "verum_check_empty_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("notes.txt"), "not source code").unwrap();
    let out = run_verum(&["check", dir.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no analysable files"), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);

    // gate must fail closed on the same input (exit 1 with an error, not a pass).
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("notes.txt"), "not source code").unwrap();
    let out = run_verum(&["gate", dir.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no analysable files"), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}
