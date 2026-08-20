//! End-to-end tests for the explainer: `verum explain`, the generated
//! detector reference, and the source frames in the human-readable output.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Run the just-built `verum` binary, retrying on ETXTBSY: on CI another
/// process can transiently hold the freshly linked executable open for
/// writing, which makes exec fail with "text file busy".
fn run_verum_env(args: &[&str], env: &[(&str, &str)]) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_verum");
    let mut attempts = 0u32;
    loop {
        let mut cmd = Command::new(bin);
        cmd.args(args);
        for (key, value) in env {
            cmd.env(key, value);
        }
        // The inherited environment must not decide colour for these tests.
        if !env.iter().any(|(k, _)| *k == "NO_COLOR") {
            cmd.env_remove("NO_COLOR");
        }
        if !env.iter().any(|(k, _)| *k == "CLICOLOR_FORCE") {
            cmd.env_remove("CLICOLOR_FORCE");
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

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8(out.stdout.clone()).expect("stdout is utf-8")
}

/// `docs/detectors.md` is generated, never hand-edited. If this fails, run:
/// `cargo run -p verum -- explain --all --format markdown > docs/detectors.md`
#[test]
fn generated_docs_match_the_detector_table() {
    let path = workspace_root().join("docs/detectors.md");
    let committed = std::fs::read_to_string(&path).expect("docs/detectors.md exists");
    let generated = verum_nucleus::reference::markdown_document();
    assert_eq!(
        committed, generated,
        "docs/detectors.md is out of date - regenerate it with \
         `cargo run -p verum -- explain --all --format markdown > docs/detectors.md`"
    );
}

/// The same bytes come out of the CLI, so the documented command really is
/// how the file is produced.
#[test]
fn explain_all_markdown_reproduces_the_docs_file() {
    let out = run_verum(&["explain", "--all", "--format", "markdown"]);
    assert!(out.status.success());
    let committed =
        std::fs::read_to_string(workspace_root().join("docs/detectors.md")).expect("docs file");
    assert_eq!(stdout(&out), committed);
}

#[test]
fn every_finding_kind_has_an_entry() {
    // The table is exhaustive by construction (the lookup matches on the
    // enum), so this asserts the list is complete and self-consistent.
    let kinds = verum_nucleus::reference::ALL_KINDS;
    assert!(kinds.len() >= 60, "suspiciously few kinds: {}", kinds.len());
    let out = run_verum(&["explain"]);
    let listing = stdout(&out);
    for kind in kinds {
        let entry = verum_nucleus::reference::reference(kind);
        assert!(
            listing.contains(entry.kind),
            "`verum explain` index is missing {}",
            entry.kind
        );
    }
    // One line per kind, plus the trailing hint.
    let lines = listing.lines().filter(|l| !l.trim().is_empty()).count();
    assert_eq!(lines, kinds.len() + 2, "index is not one line per kind");
}

#[test]
fn explain_accepts_the_enum_name_and_the_kebab_alias() {
    let by_name = stdout(&run_verum(&["explain", "NonConstantTimeComparison"]));
    let by_alias = stdout(&run_verum(&["explain", "non-constant-time-comparison"]));
    let by_shouting = stdout(&run_verum(&["explain", "NON_CONSTANT_TIME_COMPARISON"]));
    assert_eq!(by_name, by_alias);
    assert_eq!(by_name, by_shouting);
    assert!(by_name.contains("NonConstantTimeComparison"));
    assert!(by_name.contains("ct_eq"), "the fixed example is shown");
    assert!(by_name.contains("Reasonable to suppress"));
}

#[test]
fn unknown_kind_fails_with_close_matches() {
    let out = run_verum(&["explain", "sqlinjektion"]);
    assert!(!out.status.success(), "an unknown kind must exit non-zero");
    let err = String::from_utf8(out.stderr).expect("stderr is utf-8");
    assert!(err.contains("unknown finding kind"), "{err}");
    assert!(err.contains("SqlInjection"), "{err}");
    assert!(err.contains("sql-injection"), "{err}");
}

#[test]
fn explain_output_has_no_ansi_when_colour_is_disabled() {
    let out = run_verum_env(&["explain", "static-aead-nonce"], &[("NO_COLOR", "1")]);
    let text = stdout(&out);
    assert!(
        !text.contains('\u{1b}'),
        "ANSI escapes leaked under NO_COLOR"
    );
    assert!(text.contains("StaticAeadNonce"));
}

fn php_security_fixture() -> PathBuf {
    workspace_root().join("tests/fixtures/php_security")
}

#[test]
fn audit_prints_a_source_frame_under_each_security_finding() {
    let fixture = php_security_fixture();
    let out = run_verum_env(
        &["audit", fixture.to_str().unwrap()],
        &[("NO_COLOR", "1"), ("CLICOLOR", "0")],
    );
    assert!(out.status.success());
    let text = stdout(&out);

    // The fixture's SQL injection is on the `DB::raw` line; the frame shows
    // it marked, with the two lines above it for context.
    assert!(
        text.contains(">  8 |         $result = \\DB::raw(\"SELECT * FROM users WHERE id = \""),
        "no marked frame line in:\n{text}"
    );
    assert!(
        text.contains("   7 |         $id = $_GET['id'];"),
        "no context line in:\n{text}"
    );
    assert!(
        !text.contains('\u{1b}'),
        "ANSI escapes leaked under NO_COLOR"
    );
    assert!(!text.contains('▸'), "non-ASCII marker used under NO_COLOR");
}

#[test]
fn frames_are_coloured_when_colour_is_forced() {
    let fixture = php_security_fixture();
    let out = run_verum_env(
        &["audit", fixture.to_str().unwrap()],
        &[("CLICOLOR_FORCE", "1")],
    );
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(
        text.contains('\u{1b}'),
        "no ANSI escapes with colour forced"
    );
    assert!(text.contains('▸'), "no pointer glyph with colour forced");
}

#[test]
fn frames_never_reach_the_machine_readable_reports() {
    let fixture = php_security_fixture();
    for format in ["json", "sarif"] {
        let out = run_verum(&["report", fixture.to_str().unwrap(), "--format", format]);
        assert!(out.status.success(), "{format} report failed");
        let text = stdout(&out);
        serde_json::from_str::<serde_json::Value>(&text)
            .unwrap_or_else(|e| panic!("{format} report is not valid JSON: {e}"));
        assert!(!text.contains(" | $id = "), "a frame leaked into {format}");
    }
}

#[test]
fn markdown_report_carries_frames() {
    let fixture = php_security_fixture();
    let out = run_verum(&["report", fixture.to_str().unwrap(), "--format", "markdown"]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.contains("```text"), "no frame block in:\n{text}");
    assert!(
        text.contains("|         $id = $_GET['id'];"),
        "no framed source line"
    );
    assert!(
        !text.contains('\u{1b}'),
        "ANSI escapes in a markdown report"
    );
}
