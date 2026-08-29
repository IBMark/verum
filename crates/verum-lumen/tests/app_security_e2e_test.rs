//! End-to-end proof for the Python/TypeScript/JavaScript security detectors:
//! the `tests/fixtures/app_security/` tree mirrors the historic misses (a
//! Stripe-style live key in a config.ts, an MD5 password hash in a workers
//! .py, a `===` webhook signature check in TS) next to their safe idioms.
//! Every unsafe line must fire through the full map+analyse pipeline, and
//! every safe idiom must stay silent.

use verum_lumen::{Prism, Standard};
use verum_nucleus::{Finding, FindingKind};

fn fixture_findings() -> Vec<Finding> {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/app_security");
    let config = verum_mappa::AtlasConfig {
        root: fixture,
        ..Default::default()
    };
    let ir = verum_mappa::Atlas::new(config)
        .build()
        .expect("map app_security fixtures");
    Prism::analyse(&ir, &Standard::default())
        .expect("analyse app_security fixtures")
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

fn fixture_line(file: &str, needle: &str) -> u32 {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/app_security")
        .join(file);
    let text = std::fs::read_to_string(path).expect("read fixture");
    for (idx, line) in text.lines().enumerate() {
        if line.contains(needle) {
            return (idx + 1) as u32;
        }
    }
    panic!("fixture {file} does not contain {needle:?}");
}

#[test]
fn the_three_known_misses_fire() {
    let findings = fixture_findings();

    // 1. Stripe-style live key in config.ts.
    let secret_lines = lines_of(&findings, "config.ts", FindingKind::HardcodedSecret);
    assert_eq!(
        secret_lines,
        vec![fixture_line("config.ts", "sk_live_")],
        "the live-mode Stripe key must be the only hardcoded secret: {findings:?}"
    );

    // 2. MD5 password hash in workers.py - and only the password use, never
    //    the etag use.
    let weak_lines = lines_of(&findings, "workers.py", FindingKind::WeakCrypto);
    assert_eq!(
        weak_lines,
        vec![fixture_line("workers.py", "hashlib.md5(password")],
        "md5-of-password must flag and md5-etag must not: {findings:?}"
    );

    // 3. `===` webhook signature check in webhook.ts - the timingSafeEqual
    //    variant stays silent.
    let cmp_lines = lines_of(
        &findings,
        "webhook.ts",
        FindingKind::NonConstantTimeComparison,
    );
    assert_eq!(
        cmp_lines,
        vec![fixture_line("webhook.ts", "computedSignature === header")],
        "the strict-equality HMAC check must be the only comparison finding: {findings:?}"
    );
}

#[test]
fn the_supporting_detectors_fire_on_their_unsafe_lines_only() {
    let findings = fixture_findings();

    let tls = lines_of(
        &findings,
        "workers.py",
        FindingKind::TlsVerificationDisabled,
    );
    assert_eq!(
        tls,
        vec![fixture_line("workers.py", "verify=False")],
        "verify=False must flag and the CA-pinned call must not: {findings:?}"
    );

    let deser = lines_of(&findings, "workers.py", FindingKind::UnsafeDeserialization);
    assert_eq!(
        deser,
        vec![
            fixture_line("workers.py", "pickle.loads(blob)"),
            fixture_line("workers.py", "yaml.load(stream)"),
        ],
        "pickle/yaml.load must flag and json/safe_load must not: {findings:?}"
    );

    let weak_random = lines_of(&findings, "workers.py", FindingKind::WeakRandom);
    assert_eq!(
        weak_random,
        vec![fixture_line("workers.py", "random.randint(100000")],
        "the OTP from random.randint must flag; sampling and secrets must not: {findings:?}"
    );
}

#[test]
fn the_safe_idioms_stay_silent() {
    let findings = fixture_findings();
    let security_kinds = [
        FindingKind::HardcodedSecret,
        FindingKind::WeakCrypto,
        FindingKind::WeakRandom,
        FindingKind::TlsVerificationDisabled,
        FindingKind::UnsafeDeserialization,
        FindingKind::NonConstantTimeComparison,
        FindingKind::EvalUsage,
    ];
    for needle in [
        "process.env.STRIPE_SECRET_KEY",
        "etag = hashlib.md5(content)",
        "secrets.token_urlsafe",
        "random.random() < rate",
        "verify=\"/etc/ssl/certs/ca.pem\"",
        "yaml.safe_load(stream)",
        "json.loads(text)",
        "timingSafeEqual",
    ] {
        for file in ["config.ts", "workers.py", "webhook.ts"] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("tests/fixtures/app_security")
                .join(file);
            let text = std::fs::read_to_string(path).expect("read fixture");
            let Some(line) = text
                .lines()
                .position(|l| l.contains(needle))
                .map(|idx| (idx + 1) as u32)
            else {
                continue;
            };
            for kind in &security_kinds {
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
}
