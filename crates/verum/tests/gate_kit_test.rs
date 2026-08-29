//! End-to-end tests for the gate kit: stable finding fingerprints, baseline
//! mode, and inline suppressions, exercised through the real binary.

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

fn report_over(path: &Path) -> serde_json::Value {
    report_json(&["report", path.to_str().unwrap(), "--format", "json"])
}

/// The (kind, fingerprint) pairs of a report's findings, sorted.
fn kind_fingerprints(report: &serde_json::Value) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = report["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .map(|f| {
            (
                f["kind"].as_str().expect("kind").to_string(),
                f["fingerprint"].as_str().expect("fingerprint").to_string(),
            )
        })
        .collect();
    pairs.sort();
    pairs
}

fn fingerprint_of(report: &serde_json::Value, kind: &str) -> String {
    report["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .find(|f| f["kind"] == kind)
        .unwrap_or_else(|| panic!("a {kind} finding"))["fingerprint"]
        .as_str()
        .expect("fingerprint is a string")
        .to_string()
}

/// A scratch directory that is removed on drop, without external crates.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "verum-gate-kit-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        ScratchDir(dir)
    }

    fn path(&self) -> &Path {
        self.0.as_path()
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("create target dir");
    for entry in std::fs::read_dir(from).expect("read source dir") {
        let entry = entry.expect("dir entry");
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copy file");
        }
    }
}

// ---------------------------------------------------------------------------
// Stable fingerprints
// ---------------------------------------------------------------------------

#[test]
fn every_reported_finding_carries_a_fingerprint() {
    let report = report_over(&fixture("gate_kit/v1"));
    let findings = report["findings"].as_array().expect("findings");
    assert!(!findings.is_empty(), "the fixture has deliberate findings");
    for f in findings {
        let fp = f["fingerprint"].as_str().expect("fingerprint present");
        assert_eq!(fp.len(), 16, "hex-encoded 64-bit hash: {fp:?}");
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

#[test]
fn fingerprints_survive_edits_elsewhere_in_the_file() {
    // v2 adds a line above and changes an unrelated function; the md5 finding
    // moved lines but must keep its identity. Its id, by contrast, embeds the
    // line and does change - which is exactly why the fingerprint exists.
    let v1 = report_over(&fixture("gate_kit/v1"));
    let v2 = report_over(&fixture("gate_kit/v2"));
    assert_eq!(
        fingerprint_of(&v1, "WeakCrypto"),
        fingerprint_of(&v2, "WeakCrypto")
    );
    assert_eq!(
        fingerprint_of(&v1, "DeadFunction"),
        fingerprint_of(&v2, "DeadFunction")
    );
}

#[test]
fn fingerprints_survive_the_repo_living_at_a_different_absolute_path() {
    let a = ScratchDir::new("root-a");
    let b = ScratchDir::new("root-b");
    copy_tree(&fixture("gate_kit/v1"), &a.path().join("checkout"));
    copy_tree(
        &fixture("gate_kit/v1"),
        &b.path().join("elsewhere/deep/checkout"),
    );

    let at_a = report_over(&a.path().join("checkout"));
    let at_b = report_over(&b.path().join("elsewhere/deep/checkout"));
    assert_eq!(kind_fingerprints(&at_a), kind_fingerprints(&at_b));
}

#[test]
fn different_findings_have_distinct_fingerprints() {
    let report = report_over(&fixture("gate_kit/v1"));
    let mut fps: Vec<(String, String)> = kind_fingerprints(&report);
    let before = fps.len();
    fps.dedup_by(|a, b| a.1 == b.1);
    assert_eq!(before, fps.len(), "no two findings share a fingerprint");
}

// ---------------------------------------------------------------------------
// Baseline mode
// ---------------------------------------------------------------------------

/// `verum baseline` over the v1 fixture, written into `dir`.
fn write_v1_baseline(dir: &ScratchDir) -> PathBuf {
    let baseline = dir.path().join("baseline.json");
    let output = run_verum(&[
        "baseline",
        fixture("gate_kit/v1").to_str().unwrap(),
        "--out",
        baseline.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "verum baseline failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    baseline
}

#[test]
fn the_baseline_file_is_minimal_sorted_and_diff_friendly() {
    let dir = ScratchDir::new("baseline-format");
    let baseline = write_v1_baseline(&dir);
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&baseline).unwrap()).unwrap();
    assert_eq!(doc["version"], 2);
    let findings = doc["findings"].as_array().expect("findings array");
    assert!(!findings.is_empty());
    let mut fps = Vec::new();
    for f in findings {
        let obj = f.as_object().expect("finding entry");
        // Identity only: no path, no message, no line number to churn.
        assert_eq!(
            obj.keys().collect::<Vec<_>>(),
            ["fingerprint", "kind", "severity"]
        );
        fps.push(obj["fingerprint"].as_str().unwrap().to_string());
    }
    let mut sorted = fps.clone();
    sorted.sort();
    assert_eq!(fps, sorted, "entries are sorted by fingerprint");
}

#[test]
fn report_partitions_findings_into_new_existing_resolved() {
    // v1 -> v2: the eval() was fixed (resolved), a hardcoded secret was
    // introduced (new), and the md5 + two dead functions carried over.
    let dir = ScratchDir::new("baseline-partition");
    let baseline = write_v1_baseline(&dir);

    let v1 = report_over(&fixture("gate_kit/v1"));
    let v2 = report_json(&[
        "report",
        fixture("gate_kit/v2").to_str().unwrap(),
        "--format",
        "json",
        "--baseline",
        baseline.to_str().unwrap(),
    ]);

    let section = &v2["baseline"];
    assert_eq!(
        section["new"],
        serde_json::json!([fingerprint_of(&v2, "HardcodedSecret")])
    );
    assert_eq!(
        section["resolved"],
        serde_json::json!([fingerprint_of(&v1, "EvalUsage")])
    );
    assert_eq!(section["existing_count"], 3);
}

#[test]
fn without_a_baseline_the_report_carries_no_baseline_section() {
    let report = report_over(&fixture("gate_kit/v1"));
    assert!(
        report.get("baseline").is_none(),
        "the section is additive and only present on request"
    );
}

#[test]
fn gate_passes_on_baselined_findings_even_critical_ones() {
    // v1 has two Criticals of its own; against its own baseline the gate
    // must pass - inherited debt does not gate.
    let dir = ScratchDir::new("baseline-gate-pass");
    let baseline = write_v1_baseline(&dir);
    let output = run_verum(&[
        "gate",
        fixture("gate_kit/v1").to_str().unwrap(),
        "--baseline",
        baseline.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "gate must pass: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn gate_fails_on_a_new_critical_and_names_only_the_new_finding() {
    let dir = ScratchDir::new("baseline-gate-fail");
    let baseline = write_v1_baseline(&dir);
    let output = run_verum(&[
        "gate",
        fixture("gate_kit/v2").to_str().unwrap(),
        "--baseline",
        baseline.to_str().unwrap(),
    ]);
    assert!(
        !output.status.success(),
        "a new Critical must fail the gate"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("NEW") && stdout.contains("HardcodedSecret"));
    // The carried-over Criticals are waived, not re-litigated.
    assert!(!stdout.contains("NEW CRITICAL: WeakCrypto"));
    assert!(stdout.contains("1 new critical"));
}

#[test]
fn a_full_json_report_works_as_a_baseline_too() {
    let dir = ScratchDir::new("baseline-from-report");
    let old_report = dir.path().join("v1-report.json");
    let output = run_verum(&[
        "report",
        fixture("gate_kit/v1").to_str().unwrap(),
        "--format",
        "json",
        "--out",
        old_report.to_str().unwrap(),
    ]);
    assert!(output.status.success());

    let ok = run_verum(&[
        "gate",
        fixture("gate_kit/v1").to_str().unwrap(),
        "--baseline",
        old_report.to_str().unwrap(),
    ]);
    assert!(ok.status.success(), "old report waives its own findings");

    let fail = run_verum(&[
        "gate",
        fixture("gate_kit/v2").to_str().unwrap(),
        "--baseline",
        old_report.to_str().unwrap(),
    ]);
    assert!(!fail.status.success(), "the new Critical still gates");
}

#[test]
fn a_missing_baseline_is_a_loud_error_not_an_empty_one() {
    let output = run_verum(&[
        "gate",
        fixture("gate_kit/v1").to_str().unwrap(),
        "--baseline",
        "/nonexistent/verum-baseline.json",
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Failed to read baseline file"),
        "stderr: {stderr}"
    );
}

#[test]
fn a_corrupt_baseline_is_a_loud_error_not_an_empty_one() {
    let dir = ScratchDir::new("baseline-corrupt");

    let garbage = dir.path().join("garbage.json");
    std::fs::write(&garbage, "{not json").unwrap();
    let output = run_verum(&[
        "gate",
        fixture("gate_kit/v1").to_str().unwrap(),
        "--baseline",
        garbage.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("is not valid JSON"));

    let wrong_shape = dir.path().join("wrong-shape.json");
    std::fs::write(&wrong_shape, r#"{"hello": "world"}"#).unwrap();
    let output = run_verum(&[
        "report",
        fixture("gate_kit/v1").to_str().unwrap(),
        "--format",
        "json",
        "--baseline",
        wrong_shape.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no `findings` array"));

    // A findings array whose entries predate fingerprints is refused, not
    // silently treated as matching nothing.
    let no_fingerprints = dir.path().join("no-fingerprints.json");
    std::fs::write(
        &no_fingerprints,
        r#"{"findings": [{"kind": "EvalUsage", "severity": "Critical"}]}"#,
    )
    .unwrap();
    let output = run_verum(&[
        "gate",
        fixture("gate_kit/v1").to_str().unwrap(),
        "--baseline",
        no_fingerprints.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("has no fingerprint"));
}

// ---------------------------------------------------------------------------
// Inline suppressions
// ---------------------------------------------------------------------------

/// (kind, basename, line) triples for a findings array, sorted.
fn kind_locations(findings: &serde_json::Value) -> Vec<(String, String, u64)> {
    let mut rows: Vec<(String, String, u64)> = findings
        .as_array()
        .expect("findings array")
        .iter()
        .map(|f| {
            let file = f["file"].as_str().expect("file");
            // Report paths are native, so split on both separators (Windows
            // reports `fixtures\app.py`).
            let base = file.rsplit(['/', '\\']).next().unwrap_or(file).to_string();
            (
                f["kind"].as_str().expect("kind").to_string(),
                base,
                f["line_start"].as_u64().expect("line"),
            )
        })
        .collect();
    rows.sort();
    rows
}

#[test]
fn each_comment_family_suppresses_and_the_report_counts_them() {
    let report = report_over(&fixture("gate_kit/suppressed"));

    // `#` above the line, `#` trailing, `//` above, `/* */` above - all four
    // deliberate suppressions took effect.
    assert_eq!(report["suppressed_count"], 4);
    let kept = kind_locations(&report["findings"]);
    assert!(
        !kept.iter().any(
            |(kind, file, _)| (kind == "WeakCrypto" && file == "app.py") || kind == "EvalUsage"
        ),
        "suppressed findings must leave the findings list: {kept:?}"
    );

    // Without --show-suppressed the individual findings are not listed...
    assert!(report.get("suppressed").is_none());

    // ...with it, they are, each with its identity intact.
    let shown = report_json(&[
        "report",
        fixture("gate_kit/suppressed").to_str().unwrap(),
        "--format",
        "json",
        "--show-suppressed",
    ]);
    let listed = kind_locations(&shown["suppressed"]);
    assert_eq!(
        listed,
        vec![
            ("EvalUsage".into(), "app.js".into(), 3),
            ("EvalUsage".into(), "app.js".into(), 8),
            ("EvalUsage".into(), "app.py".into(), 10),
            ("WeakCrypto".into(), "app.py".into(), 6),
        ]
    );
    for f in shown["suppressed"].as_array().unwrap() {
        assert_eq!(f["fingerprint"].as_str().unwrap().len(), 16);
    }
}

#[test]
fn a_normal_comment_never_suppresses() {
    // normal.py has an ordinary comment directly above its md5 finding; the
    // finding must survive.
    let report = report_over(&fixture("gate_kit/suppressed"));
    let kept = kind_locations(&report["findings"]);
    assert!(
        kept.contains(&("WeakCrypto".to_string(), "normal.py".to_string(), 5)),
        "kept: {kept:?}"
    );
}

#[test]
fn a_stale_suppression_becomes_a_low_finding() {
    // stale.py's ignore names SqlInjection but the line below has WeakCrypto:
    // the comment suppresses nothing, the finding survives, and the rot is
    // reported.
    let report = report_over(&fixture("gate_kit/suppressed"));
    let kept = kind_locations(&report["findings"]);
    assert!(kept.contains(&("StaleSuppression".to_string(), "stale.py".to_string(), 3)));
    assert!(kept.contains(&("WeakCrypto".to_string(), "stale.py".to_string(), 4)));

    let stale = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["kind"] == "StaleSuppression")
        .expect("stale finding");
    assert_eq!(stale["severity"], "Low");
    assert!(stale["message"]
        .as_str()
        .unwrap()
        .contains("verum:ignore[SqlInjection]"));
    assert_eq!(stale["fingerprint"].as_str().unwrap().len(), 16);
}

#[test]
fn a_tree_without_ignore_comments_reports_zero_suppressed() {
    let report = report_over(&fixture("gate_kit/v1"));
    assert_eq!(report["suppressed_count"], 0);
    assert!(report.get("suppressed").is_none());
    assert!(
        !report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["kind"] == "StaleSuppression"),
        "no comments, no stale diagnostics"
    );
}

#[test]
fn gate_show_suppressed_lists_the_waived_findings() {
    let output = run_verum(&[
        "gate",
        fixture("gate_kit/suppressed").to_str().unwrap(),
        "--show-suppressed",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Suppressed findings (4)"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("EvalUsage"));
    assert!(stdout.contains("Stale suppressions: 1"));
}

#[test]
fn suppressed_findings_and_stale_diagnostics_are_baseline_transparent() {
    // Baseline the suppressed tree, then gate the same tree against it: the
    // remaining real Criticals are waived, the suppressed ones are absent,
    // and the Low StaleSuppression is neither baselined nor gate-relevant -
    // the gate must pass.
    let dir = ScratchDir::new("suppress-gate");
    let baseline = dir.path().join("baseline.json");
    let output = run_verum(&[
        "baseline",
        fixture("gate_kit/suppressed").to_str().unwrap(),
        "--out",
        baseline.to_str().unwrap(),
    ]);
    assert!(output.status.success());

    // The baseline records no StaleSuppression entries.
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&baseline).unwrap()).unwrap();
    assert!(!doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["kind"] == "StaleSuppression"));

    let gate = run_verum(&[
        "gate",
        fixture("gate_kit/suppressed").to_str().unwrap(),
        "--baseline",
        baseline.to_str().unwrap(),
    ]);
    assert!(
        gate.status.success(),
        "same tree vs its own baseline must pass: {}",
        String::from_utf8_lossy(&gate.stdout)
    );
}

// ---------------------------------------------------------------------------
// Auto-loaded verum.baseline.json (ratchet mode)
// ---------------------------------------------------------------------------

#[test]
fn the_auto_loaded_v2_baseline_ratchets_the_gate() {
    // `verum baseline <path>` then plain `verum gate <path>` - no flag - must
    // pick up the fresh v2 verum.baseline.json and waive the inherited
    // Criticals.
    let dir = ScratchDir::new("auto-ratchet-v2");
    let app = dir.path().join("app");
    copy_tree(&fixture("gate_kit/v1"), &app);

    let output = run_verum(&["baseline", app.to_str().unwrap()]);
    assert!(output.status.success());
    assert!(app.join("verum.baseline.json").exists());

    let gate = run_verum(&["gate", app.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&gate.stdout);
    assert!(
        gate.status.success(),
        "v2 auto baseline must waive inherited findings: {stdout}"
    );
    assert!(stdout.contains("Baseline active"), "stdout: {stdout}");
}

#[test]
fn a_legacy_v1_baseline_file_still_waives_its_findings() {
    // Baselines written by earlier releases carry textual
    // `kind|relative/path|message-with-digits-stripped` identities under a
    // `fingerprints` key. They must keep working unchanged.
    let dir = ScratchDir::new("auto-ratchet-v1");
    let app = dir.path().join("app");
    copy_tree(&fixture("gate_kit/v1"), &app);

    let v1_doc = serde_json::json!({
        "version": 1,
        "count": 2,
        "fingerprints": [
            "WeakCrypto|app.py|Weak cryptographic function `md()` detected",
            "EvalUsage|app.py|eval() usage detected - potential code injection",
        ],
    });
    std::fs::write(
        app.join("verum.baseline.json"),
        serde_json::to_string_pretty(&v1_doc).unwrap(),
    )
    .unwrap();

    let gate = run_verum(&["gate", app.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&gate.stdout);
    // The two Criticals are waived (the Medium dead-code findings are "new"
    // to this hand-written baseline, but Medium never gates).
    assert!(
        gate.status.success(),
        "legacy v1 fingerprints must still waive: {stdout}"
    );
    assert!(
        stdout.contains("Baseline active: 2 known finding(s) waived"),
        "stdout: {stdout}"
    );
}
