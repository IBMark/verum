//! End-to-end proof for the Python insight detectors: the
//! `tests/fixtures/python_insights/` tree pairs every trap with the safe
//! idiom beside it - blocking calls in `async def` next to their awaited
//! equivalents, mutable defaults next to the `None` idiom, swallowed
//! exceptions next to handlers that log or re-raise, assert-validation next
//! to checks that survive `python -O`. Every unsafe line must fire through
//! the full map+analyse pipeline, and every safe idiom must stay silent.

use verum_lumen::{Prism, Standard};
use verum_nucleus::{Finding, FindingKind};

fn fixture_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/python_insights")
}

fn fixture_findings() -> Vec<Finding> {
    let config = verum_mappa::AtlasConfig {
        root: fixture_root(),
        ..Default::default()
    };
    let ir = verum_mappa::Atlas::new(config)
        .build()
        .expect("map python_insights fixtures");
    Prism::analyse(&ir, &Standard::default())
        .expect("analyse python_insights fixtures")
        .findings
}

/// The findings of `kind` in `file`, as their line numbers.
fn lines_of(findings: &[Finding], file: &str, kind: FindingKind) -> Vec<u32> {
    findings
        .iter()
        .filter(|f| f.kind == kind && f.file.to_string_lossy().ends_with(file))
        .map(|f| f.line_start)
        .collect()
}

/// The 1-based line of the first occurrence of `needle` in a fixture.
fn fixture_line(file: &str, needle: &str) -> u32 {
    let text = std::fs::read_to_string(fixture_root().join(file)).expect("read fixture");
    for (idx, line) in text.lines().enumerate() {
        if line.contains(needle) {
            return (idx + 1) as u32;
        }
    }
    panic!("fixture {file} does not contain {needle:?}");
}

#[test]
fn blocking_calls_in_async_defs_fire() {
    let findings = fixture_findings();
    let mut expected = vec![
        fixture_line("async_service.py", "time.sleep(2)"),
        fixture_line("async_service.py", "requests.get(f\"https://"),
        fixture_line("async_service.py", "subprocess.run([\"generate-invoice\""),
    ];
    expected.sort_unstable();
    assert_eq!(
        lines_of(&findings, "async_service.py", FindingKind::BlockingInAsync),
        expected,
        "the three blocking calls inside async defs must be the only \
         BlockingInAsync findings - awaited/offloaded/sync-def lines must \
         stay silent: {findings:?}"
    );
}

#[test]
fn mutable_defaults_fire() {
    let findings = fixture_findings();
    let mut expected = vec![
        fixture_line("defaults.py", "tags=[]"),
        fixture_line("defaults.py", "overrides={}"),
        fixture_line("defaults.py", "initial=set()"),
    ];
    expected.sort_unstable();
    assert_eq!(
        lines_of(&findings, "defaults.py", FindingKind::MutableDefaultArg),
        expected,
        "the three mutable defaults must fire; None/scalar/tuple defaults \
         must not: {findings:?}"
    );
}

#[test]
fn swallowed_exceptions_fire() {
    let findings = fixture_findings();
    let mut expected = vec![
        // The FIRST `except Exception:` is the pass-only swallow; the second
        // (in publish_reraised) logs and re-raises and must stay silent.
        fixture_line("errors.py", "except Exception:"),
        fixture_line("errors.py", "except:"),
    ];
    expected.sort_unstable();
    assert_eq!(
        lines_of(&findings, "errors.py", FindingKind::SwallowedException),
        expected,
        "only the pass-only catch-alls swallow; logging, re-raising, and \
         specific types (even with pass) must stay silent: {findings:?}"
    );
}

#[test]
fn assert_validation_fires() {
    let findings = fixture_findings();
    let mut expected = vec![
        fixture_line("validation.py", "assert request.form[\"amount\"]"),
        fixture_line("validation.py", "assert params[\"limit\"]"),
    ];
    expected.sort_unstable();
    assert_eq!(
        lines_of(&findings, "validation.py", FindingKind::AssertAsValidation),
        expected,
        "the input-shaped asserts must fire; the raising check, the \
         is-not-None narrowing, and the internal invariant must stay \
         silent: {findings:?}"
    );
}

#[test]
fn the_safe_idioms_stay_silent() {
    let findings = fixture_findings();
    let insight_kinds = [
        FindingKind::BlockingInAsync,
        FindingKind::MutableDefaultArg,
        FindingKind::SwallowedException,
        FindingKind::AssertAsValidation,
    ];
    for (file, needle) in [
        ("async_service.py", "await asyncio.sleep(2)"),
        ("async_service.py", "await client.get("),
        ("async_service.py", "run_in_executor"),
        ("async_service.py", "time.sleep(5)"),
        ("defaults.py", "tags=None"),
        ("defaults.py", "overrides=None"),
        ("defaults.py", "count=0, name=\"order\", flags=()"),
        ("errors.py", "except ConnectionError:"),
        ("errors.py", "except FileNotFoundError:"),
        ("validation.py", "if not request.form"),
        ("validation.py", "assert request is not None"),
        ("validation.py", "assert len(batch) > 0"),
    ] {
        let line = fixture_line(file, needle);
        for kind in &insight_kinds {
            assert!(
                !findings.iter().any(|f| {
                    f.kind == *kind
                        && f.file.to_string_lossy().ends_with(file)
                        && f.line_start == line
                }),
                "safe idiom {needle:?} in {file} line {line} flagged as {kind:?}"
            );
        }
    }
}
