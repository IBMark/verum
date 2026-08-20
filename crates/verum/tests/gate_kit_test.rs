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
