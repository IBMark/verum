//! Dependency audit - offline, deterministic.
//!
//! Parses lockfiles - `Cargo.lock` for Rust; `requirements.txt`, `poetry.lock`
//! and `uv.lock` for Python - and matches locked versions against curated
//! snapshots of published advisories embedded at build time. No network, no
//! external process: the same lockfile always produces the same findings.
//!
//! The embedded tables ([`SEED_ADVISORIES`], [`PY_SEED_ADVISORIES`]) are
//! intentionally small and contain only advisories whose affected-version
//! boundaries are stated with confidence - a wrong boundary is a false
//! positive, which this project treats as worse than a miss. The sets are
//! meant to be regenerated/augmented from full advisory databases; the
//! matching engine below is the durable part.

use std::path::Path;

use verum_nucleus::{Finding, FindingKind, Severity};

/// A semantic version reduced to the three numeric components we compare on.
/// Pre-release/build metadata is ignored (advisory boundaries are release
/// versions), which is conservative: we never upgrade a match on metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl Version {
    pub fn parse(s: &str) -> Option<Version> {
        let core = s.split(['-', '+']).next().unwrap_or(s);
        let mut it = core.split('.');
        let major = it.next()?.parse().ok()?;
        let minor = it.next().unwrap_or("0").parse().ok()?;
        let patch = it.next().unwrap_or("0").parse().ok()?;
        Some(Version {
            major,
            minor,
            patch,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvisoryKind {
    /// A security vulnerability fixed in `patched` (all versions below the
    /// first patched release in each affected major line are vulnerable).
    Vulnerability,
    /// The crate is unmaintained/abandoned - applies to every version.
    Unmaintained,
}

/// One curated advisory. `patched` is the lowest version that is *not*
/// affected within the relevant major line; `None` means "all versions"
/// (used for unmaintained crates). Python entries store `package` in PEP 503
/// normalized form (lowercase, `-`/`_`/`.` collapsed to `-`).
#[derive(Debug, Clone)]
pub struct Advisory {
    pub package: &'static str,
    pub id: &'static str,
    pub kind: AdvisoryKind,
    pub severity: Severity,
    /// First fixed version. `None` = every version is affected.
    pub patched: Option<Version>,
    pub title: &'static str,
}

const fn v(major: u64, minor: u64, patch: u64) -> Version {
    Version {
        major,
        minor,
        patch,
    }
}

/// Curated snapshot of real RustSec advisories. Every entry here is a
/// published advisory with a boundary stated in its RUSTSEC record. Add only
/// advisories whose affected range you can cite - a fabricated or mis-bounded
/// entry is exactly the false positive this tool must not emit.
pub const SEED_ADVISORIES: &[Advisory] = &[
    Advisory {
        package: "time",
        id: "RUSTSEC-2020-0071",
        kind: AdvisoryKind::Vulnerability,
        severity: Severity::High,
        patched: Some(v(0, 2, 23)),
        title: "Potential segfault in `localtime_r` invocations",
    },
    Advisory {
        package: "chrono",
        id: "RUSTSEC-2020-0159",
        kind: AdvisoryKind::Vulnerability,
        severity: Severity::Medium,
        patched: Some(v(0, 4, 20)),
        title: "Soundness issue via `time` (segfault in localtime_r)",
    },
    Advisory {
        package: "smallvec",
        id: "RUSTSEC-2021-0003",
        kind: AdvisoryKind::Vulnerability,
        severity: Severity::High,
        patched: Some(v(1, 6, 1)),
        title: "Buffer overflow in `SmallVec::insert_many`",
    },
    Advisory {
        package: "term",
        id: "RUSTSEC-2018-0015",
        kind: AdvisoryKind::Unmaintained,
        severity: Severity::Low,
        patched: None,
        title: "`term` is unmaintained; use `term`/`termcolor` alternatives",
    },
    Advisory {
        package: "net2",
        id: "RUSTSEC-2020-0016",
        kind: AdvisoryKind::Unmaintained,
        severity: Severity::Low,
        patched: None,
        title: "`net2` is deprecated in favour of `socket2`",
    },
];

/// Curated snapshot of published Python advisories, matched against PEP 503
/// normalized package names. The same rule as the Rust seed applies, harder:
/// only advisories whose fix landed in exactly one release line are listed,
/// because `patched` expresses a single boundary. Django and Flask are
/// deliberately absent - their security fixes are backported across several
/// maintained series at once (e.g. Flask CVE-2023-30861 fixed in both 2.2.5
/// and 2.3.2), so a single boundary would flag patched backport releases:
/// exactly the false positive this tool must not emit.
pub const PY_SEED_ADVISORIES: &[Advisory] = &[
    Advisory {
        package: "pyyaml",
        id: "CVE-2020-14343",
        kind: AdvisoryKind::Vulnerability,
        severity: Severity::Critical,
        patched: Some(v(5, 4, 0)),
        title: "Arbitrary code execution via `full_load`/`FullLoader` (incomplete 2020-1747 fix)",
    },
    Advisory {
        package: "requests",
        id: "CVE-2024-35195",
        kind: AdvisoryKind::Vulnerability,
        severity: Severity::Medium,
        patched: Some(v(2, 32, 0)),
        title: "`Session` keeps certificate verification off after one `verify=False` request",
    },
    Advisory {
        package: "urllib3",
        id: "CVE-2021-33503",
        kind: AdvisoryKind::Vulnerability,
        severity: Severity::High,
        patched: Some(v(1, 26, 5)),
        title: "Catastrophic backtracking parsing URLs with an `@` in the authority",
    },
    Advisory {
        package: "jinja2",
        id: "CVE-2020-28493",
        kind: AdvisoryKind::Vulnerability,
        severity: Severity::Medium,
        patched: Some(v(2, 11, 3)),
        title: "Regular expression denial of service in the `urlize` filter",
    },
    Advisory {
        package: "lxml",
        id: "CVE-2021-43818",
        kind: AdvisoryKind::Vulnerability,
        severity: Severity::Medium,
        patched: Some(v(4, 6, 5)),
        title: "HTML Cleaner allows crafted script content through",
    },
    Advisory {
        package: "aiohttp",
        id: "CVE-2024-23334",
        kind: AdvisoryKind::Vulnerability,
        severity: Severity::High,
        patched: Some(v(3, 9, 2)),
        title: "Path traversal in static routes with `follow_symlinks=True`",
    },
    Advisory {
        package: "werkzeug",
        id: "CVE-2023-25577",
        kind: AdvisoryKind::Vulnerability,
        severity: Severity::High,
        patched: Some(v(2, 2, 3)),
        title: "Unlimited multipart parts exhaust memory and CPU during form parsing",
    },
];

/// A package as pinned in a lockfile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedPackage {
    pub name: String,
    pub version: String,
}

/// PEP 503 name normalization: lowercase, with every run of `-`, `_`, `.`
/// collapsed to a single `-`. `PyYAML`, `pyyaml`; `typing_extensions`,
/// `typing-extensions` - one index name each.
pub fn pep503_normalize(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_sep = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !prev_sep {
                out.push('-');
            }
            prev_sep = true;
        } else {
            out.push(c.to_ascii_lowercase());
            prev_sep = false;
        }
    }
    out
}

/// Rust package names need no normalization: Cargo.lock records the exact
/// registry name.
fn identity_normalize(name: &str) -> String {
    name.to_string()
}

/// Parse the `[[package]]` blocks shared by Cargo.lock, poetry.lock and
/// uv.lock. Hand-rolled: each file is a regular subset of TOML (one
/// `name`/`version` string per package block), so this avoids a TOML
/// dependency while staying exact for the real formats.
///
/// Capture stops at any other section header (`[metadata]`,
/// `[package.dependencies]`, ...) so a dependency literally named `name` or
/// `version` in a poetry `[package.dependencies]` table can never overwrite
/// the block's own fields.
fn parse_package_blocks(text: &str) -> Vec<LockedPackage> {
    let mut packages = Vec::new();
    let mut in_package = false;
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;

    let flush =
        |packages: &mut Vec<LockedPackage>, n: &mut Option<String>, ver: &mut Option<String>| {
            if let (Some(name), Some(version)) = (n.take(), ver.take()) {
                packages.push(LockedPackage { name, version });
            } else {
                *n = None;
                *ver = None;
            }
        };

    for line in text.lines() {
        let t = line.trim();
        if t == "[[package]]" {
            flush(&mut packages, &mut name, &mut version);
            in_package = true;
        } else if t.starts_with('[') {
            flush(&mut packages, &mut name, &mut version);
            in_package = false;
        } else if in_package {
            if let Some(rest) = t.strip_prefix("name = ") {
                name = unquote(rest);
            } else if let Some(rest) = t.strip_prefix("version = ") {
                version = unquote(rest);
            }
        }
    }
    flush(&mut packages, &mut name, &mut version);
    packages
}

/// Parse the `[[package]]` blocks of a Cargo.lock.
pub fn parse_cargo_lock(text: &str) -> Vec<LockedPackage> {
    parse_package_blocks(text)
}

/// Parse the `[[package]]` blocks of a poetry.lock.
pub fn parse_poetry_lock(text: &str) -> Vec<LockedPackage> {
    parse_package_blocks(text)
}

/// Parse the `[[package]]` blocks of a uv.lock.
pub fn parse_uv_lock(text: &str) -> Vec<LockedPackage> {
    parse_package_blocks(text)
}

/// Parse a requirements.txt. Only exact `name==version` pins produce a
/// comparable version; every range, marker-gated spec, URL, editable install
/// or option line is skipped silently - a guessed version is a guessed
/// finding. `-r`/`-c` includes are not followed: this reads one file.
pub fn parse_requirements_txt(text: &str) -> Vec<LockedPackage> {
    let mut packages = Vec::new();
    for raw in text.lines() {
        let line = strip_requirements_comment(raw).trim();
        // pip-compile emits `pkg==1.2.3 \` followed by `--hash=...` lines;
        // dropping the continuation keeps the pin, and the hash lines start
        // with `-` and fall to the option filter below.
        let line = line.strip_suffix('\\').map(str::trim_end).unwrap_or(line);
        if line.is_empty() || line.starts_with('-') {
            continue;
        }
        // Environment markers gate installation on the target platform; the
        // pin before the `;` is still the locked version when it applies.
        let line = line.split(';').next().unwrap_or(line).trim();
        let Some((name_part, ver_part)) = line.split_once("==") else {
            continue;
        };
        // `===` is arbitrary (string) equality, not a version comparison.
        let ver = ver_part.trim();
        if ver.starts_with('=') {
            continue;
        }
        // Options after the version (`--hash=...`) end the version token.
        let ver = ver.split_whitespace().next().unwrap_or("");
        // A compound specifier (`==1.2.*`, `==1.2,<2`) is a range, not a pin.
        if ver.is_empty() || ver.contains([',', '<', '>', '!', '~', '*']) {
            continue;
        }
        // Extras select optional features, not a different package.
        let name = name_part.split('[').next().unwrap_or(name_part).trim();
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            continue;
        }
        packages.push(LockedPackage {
            name: name.to_string(),
            version: ver.to_string(),
        });
    }
    packages
}

/// pip treats `#` as a comment only at line start or after whitespace, so
/// a `#` inside a URL fragment does not truncate the line.
fn strip_requirements_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
            return &line[..i];
        }
    }
    line
}

fn unquote(s: &str) -> Option<String> {
    let s = s.trim();
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .map(str::to_string)
}

/// Whether `locked` is affected by `adv`.
fn is_affected(adv: &Advisory, locked: Version) -> bool {
    match adv.patched {
        None => true, // unmaintained: every version
        Some(patched) => {
            // Only affected within the same compatibility line and below the
            // patch - a fix in 1.6.1 says nothing about a 0.x or 2.x release.
            // For 0.x the minor is the breaking axis, so a fix in 0.4.20 says
            // nothing about 0.3.x either.
            if patched.major == 0 {
                locked.major == 0 && locked.minor == patched.minor && locked < patched
            } else {
                locked.major == patched.major && locked < patched
            }
        }
    }
}

/// Match locked packages against an advisory table. `normalize` maps both
/// sides' names into the ecosystem's canonical form (identity for Rust,
/// PEP 503 for Python - the tables already store the canonical spelling).
fn match_advisories(
    packages: &[LockedPackage],
    advisories: &[Advisory],
    lock_path: &Path,
    normalize: fn(&str) -> String,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for pkg in packages {
        let Some(locked) = Version::parse(&pkg.version) else {
            continue;
        };
        let canonical = normalize(&pkg.name);
        for adv in advisories.iter().filter(|a| a.package == canonical) {
            if !is_affected(adv, locked) {
                continue;
            }
            let (kind, verb) = match adv.kind {
                AdvisoryKind::Vulnerability => (FindingKind::VulnerableDependency, "has advisory"),
                AdvisoryKind::Unmaintained => {
                    (FindingKind::UnmaintainedDependency, "is unmaintained")
                }
            };
            let fix = match adv.patched {
                Some(p) => format!("upgrade to >= {}.{}.{}", p.major, p.minor, p.patch),
                None => "migrate to a maintained alternative".to_string(),
            };
            findings.push(Finding {
                fingerprint: String::new(),
                id: format!("dep-{}-{}", adv.id, canonical),
                kind,
                severity: adv.severity.clone(),
                confidence: 1.0,
                file: lock_path.to_path_buf(),
                line_start: 0,
                line_end: 0,
                symbol: None,
                message: format!(
                    "`{}` {} {} ({}): {}",
                    pkg.name, pkg.version, verb, adv.id, adv.title
                ),
                suggestion: fix,
                auto_fixable: false,
                related: Vec::new(),
            });
        }
    }
    findings
}

/// Audit a project root: reads whichever supported lockfiles are present -
/// `Cargo.lock`, `requirements.txt`, `poetry.lock`, `uv.lock`.
pub fn analyse(root: &Path) -> Vec<Finding> {
    let mut findings = analyse_with(root, SEED_ADVISORIES);
    findings.extend(analyse_python_with(root, PY_SEED_ADVISORIES));
    findings.sort_by(|a, b| a.id.cmp(&b.id));
    findings
}

/// Testable core for the Rust path: advisory table injected.
pub fn analyse_with(root: &Path, advisories: &[Advisory]) -> Vec<Finding> {
    let lock_path = root.join("Cargo.lock");
    let Ok(text) = std::fs::read_to_string(&lock_path) else {
        return Vec::new();
    };
    let packages = parse_cargo_lock(&text);
    let mut findings = match_advisories(&packages, advisories, &lock_path, identity_normalize);

    // Duplicate incompatible versions of one crate - diamond-dependency bloat.
    // The compatibility unit is cargo's, not just the major: for 0.x releases
    // the minor is the breaking axis (0.7 vs 0.8), so key on minor when major
    // is 0. Rust-only: a Python environment resolves each package to exactly
    // one version, so the duplicate shape cannot occur there.
    let compat_key = |ver: Version| -> String {
        if ver.major == 0 {
            format!("0.{}", ver.minor)
        } else {
            ver.major.to_string()
        }
    };
    let mut by_name: std::collections::BTreeMap<&str, std::collections::BTreeSet<String>> =
        std::collections::BTreeMap::new();
    for pkg in &packages {
        if let Some(ver) = Version::parse(&pkg.version) {
            by_name
                .entry(pkg.name.as_str())
                .or_default()
                .insert(compat_key(ver));
        }
    }
    for (name, majors) in by_name {
        if majors.len() > 1 {
            let list = majors.iter().cloned().collect::<Vec<_>>().join(", ");
            findings.push(Finding {
                fingerprint: String::new(),
                id: format!("dep-dup-{name}"),
                kind: FindingKind::DuplicateDependency,
                severity: Severity::Low,
                confidence: 0.9,
                file: lock_path.clone(),
                line_start: 0,
                line_end: 0,
                symbol: None,
                message: format!("`{name}` is present at multiple major versions ({list})"),
                suggestion:
                    "Align dependents on one major version to cut build time and binary size"
                        .to_string(),
                auto_fixable: false,
                related: Vec::new(),
            });
        }
    }

    findings.sort_by(|a, b| a.id.cmp(&b.id));
    findings
}

/// Testable core for the Python path: advisory table injected. Reads every
/// Python lockfile present at the root; a project carrying both a
/// requirements.txt and a uv.lock is audited through both, and identical
/// pins produce one finding id, deduplicated downstream like any other.
pub fn analyse_python_with(root: &Path, advisories: &[Advisory]) -> Vec<Finding> {
    type Parser = fn(&str) -> Vec<LockedPackage>;
    const SOURCES: [(&str, Parser); 3] = [
        ("requirements.txt", parse_requirements_txt),
        ("poetry.lock", parse_poetry_lock),
        ("uv.lock", parse_uv_lock),
    ];

    let mut findings = Vec::new();
    for (file, parse) in SOURCES {
        let path = root.join(file);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let packages = parse(&text);
        findings.extend(match_advisories(
            &packages,
            advisories,
            &path,
            pep503_normalize,
        ));
    }
    findings.sort_by(|a, b| a.id.cmp(&b.id));
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = r#"
# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "time"
version = "0.2.10"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "smallvec"
version = "1.6.1"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "term"
version = "0.5.2"

[[package]]
name = "serde"
version = "1.0.200"
"#;

    #[test]
    fn parses_packages() {
        let pkgs = parse_cargo_lock(LOCK);
        assert_eq!(pkgs.len(), 4);
        assert_eq!(
            pkgs[0],
            LockedPackage {
                name: "time".into(),
                version: "0.2.10".into()
            }
        );
    }

    #[test]
    fn flags_vulnerable_below_patch_only() {
        let dir = std::env::temp_dir().join(format!("verum-deps-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Cargo.lock"), LOCK).unwrap();
        let findings = analyse_with(&dir, SEED_ADVISORIES);
        std::fs::remove_dir_all(&dir).ok();

        // time 0.2.10 < 0.2.23 -> vulnerable.
        assert!(findings
            .iter()
            .any(|f| f.kind == FindingKind::VulnerableDependency && f.message.contains("time")));
        // smallvec 1.6.1 is exactly the patch -> NOT vulnerable (boundary test).
        assert!(!findings.iter().any(|f| f.message.contains("smallvec")));
        // term is unmaintained -> flagged regardless of version.
        assert!(findings
            .iter()
            .any(|f| f.kind == FindingKind::UnmaintainedDependency && f.message.contains("term")));
        // serde is clean.
        assert!(!findings.iter().any(|f| f.message.contains("serde")));
    }

    #[test]
    fn zero_x_advisories_track_the_minor_line() {
        // For 0.x the minor is the breaking axis: a fix in 0.4.20 says
        // nothing about 0.3.x, which predates the affected code entirely.
        let adv = Advisory {
            package: "example",
            id: "TEST-0000",
            kind: AdvisoryKind::Vulnerability,
            severity: Severity::High,
            patched: Some(v(0, 4, 20)),
            title: "test advisory",
        };
        assert!(is_affected(&adv, v(0, 4, 19)));
        assert!(!is_affected(&adv, v(0, 4, 20)));
        assert!(
            !is_affected(&adv, v(0, 3, 7)),
            "0.3.x is a different compat line"
        );
        assert!(!is_affected(&adv, v(0, 5, 0)));
    }

    #[test]
    fn different_major_is_not_affected() {
        // A 1.x smallvec advisory must not touch a hypothetical 2.x.
        assert!(!is_affected(&SEED_ADVISORIES[2], v(2, 0, 0)));
        assert!(is_affected(&SEED_ADVISORIES[2], v(1, 0, 0)));
    }

    #[test]
    fn detects_duplicate_majors() {
        let lock = r#"
[[package]]
name = "rand"
version = "0.7.3"

[[package]]
name = "rand"
version = "0.8.5"
"#;
        let dir = std::env::temp_dir().join(format!("verum-deps-dup-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Cargo.lock"), lock).unwrap();
        let findings = analyse_with(&dir, SEED_ADVISORIES);
        std::fs::remove_dir_all(&dir).ok();
        assert!(findings
            .iter()
            .any(|f| f.kind == FindingKind::DuplicateDependency && f.message.contains("rand")));
    }

    #[test]
    fn no_lockfile_is_quiet() {
        let dir = std::env::temp_dir().join(format!("verum-deps-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let findings = analyse_with(&dir, SEED_ADVISORIES);
        std::fs::remove_dir_all(&dir).ok();
        assert!(findings.is_empty());
    }

    // ---- Python -----------------------------------------------------------

    #[test]
    fn pep503_normalizes_case_and_separators() {
        assert_eq!(pep503_normalize("PyYAML"), "pyyaml");
        assert_eq!(pep503_normalize("pyyaml"), "pyyaml");
        assert_eq!(
            pep503_normalize("typing_extensions"),
            pep503_normalize("typing-extensions")
        );
        assert_eq!(pep503_normalize("zope.interface"), "zope-interface");
        assert_eq!(pep503_normalize("a--b__c..d"), "a-b-c-d");
    }

    #[test]
    fn requirements_takes_only_exact_pins() {
        let text = r#"
# a comment
PyYAML==5.3.1
requests[socks]==2.31.0
urllib3==1.26.4 ; python_version < "3.10"
jinja2==2.11.2  # trailing comment
flask>=2.0            # range: skipped
django~=4.2           # compatible release: skipped
numpy==1.24.*         # wildcard: skipped
pip===23.0.1          # arbitrary equality: skipped
lxml==4.6.4,!=4.6.3   # compound specifier: skipped
-r other.txt
-e .
--index-url https://pypi.org/simple
pkg @ https://example.invalid/pkg-1.0.tar.gz
aiohttp==3.9.1 \
    --hash=sha256:0000000000000000000000000000000000000000000000000000000000000000
"#;
        let pkgs = parse_requirements_txt(text);
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["PyYAML", "requests", "urllib3", "jinja2", "aiohttp"]
        );
        assert_eq!(pkgs[1].version, "2.31.0");
        assert_eq!(pkgs[2].version, "1.26.4");
        assert_eq!(pkgs[4].version, "3.9.1");
    }

    #[test]
    fn requirements_keeps_url_fragments_intact() {
        // `#` starts a comment only at line start or after whitespace.
        let text = "good==1.0 # cut here\n";
        let pkgs = parse_requirements_txt(text);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].version, "1.0");
    }

    #[test]
    fn parses_poetry_lock_blocks() {
        // The [package.dependencies] table maps dependency NAMES to specs, so
        // a dependency literally called `version` must not overwrite the
        // block's own version.
        let text = r#"
[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."
optional = false
python-versions = ">=3.7"

[package.dependencies]
certifi = ">=2017.4.17"
version = ">=99.0"

[[package]]
name = "PyYAML"
version = "5.3.1"

[metadata]
lock-version = "2.0"
"#;
        let pkgs = parse_poetry_lock(text);
        assert_eq!(
            pkgs,
            vec![
                LockedPackage {
                    name: "requests".into(),
                    version: "2.31.0".into()
                },
                LockedPackage {
                    name: "PyYAML".into(),
                    version: "5.3.1".into()
                },
            ]
        );
    }

    #[test]
    fn parses_uv_lock_blocks() {
        // Inline dependency tables (`{ name = "..." }`) must not read as
        // package names.
        let text = r#"
version = 1
requires-python = ">=3.10"

[[package]]
name = "aiohttp"
version = "3.9.1"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "aiosignal" },
    { name = "attrs" },
]

[package.metadata]
requires-dist = [{ name = "aiosignal", specifier = ">=1.1.2" }]

[[package]]
name = "aiosignal"
version = "1.3.1"
source = { registry = "https://pypi.org/simple" }
"#;
        let pkgs = parse_uv_lock(text);
        assert_eq!(
            pkgs,
            vec![
                LockedPackage {
                    name: "aiohttp".into(),
                    version: "3.9.1".into()
                },
                LockedPackage {
                    name: "aiosignal".into(),
                    version: "1.3.1".into()
                },
            ]
        );
    }

    #[test]
    fn python_names_match_across_spellings() {
        // The seed stores `pyyaml`; the lockfile says `PyYAML`. PEP 503 makes
        // them the same package.
        let dir = std::env::temp_dir().join(format!("verum-deps-py-norm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("requirements.txt"), "PyYAML==5.3.1\n").unwrap();
        let findings = analyse_python_with(&dir, PY_SEED_ADVISORIES);
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FindingKind::VulnerableDependency);
        assert!(findings[0].message.contains("CVE-2020-14343"));
        assert!(findings[0].id.ends_with("-pyyaml"));
    }

    #[test]
    fn python_boundary_version_is_not_flagged() {
        // The patched version itself must stay silent: 5.4 is the fix for
        // CVE-2020-14343, and 2.32.0 the fix for CVE-2024-35195.
        let dir = std::env::temp_dir().join(format!("verum-deps-py-fixed-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("requirements.txt"),
            "pyyaml==5.4\nrequests==2.32.0\n",
        )
        .unwrap();
        let findings = analyse_python_with(&dir, PY_SEED_ADVISORIES);
        std::fs::remove_dir_all(&dir).ok();
        assert!(findings.is_empty());
    }

    #[test]
    fn unpinned_requirements_never_flag() {
        // A range that COULD resolve to a vulnerable version is not evidence
        // that it did - skipped, never guessed.
        let dir = std::env::temp_dir().join(format!("verum-deps-py-range-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("requirements.txt"), "pyyaml>=5.0,<5.4\n").unwrap();
        let findings = analyse_python_with(&dir, PY_SEED_ADVISORIES);
        std::fs::remove_dir_all(&dir).ok();
        assert!(findings.is_empty());
    }

    #[test]
    fn poetry_and_uv_pins_flag_like_requirements() {
        let dir = std::env::temp_dir().join(format!("verum-deps-py-toml-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("poetry.lock"),
            "[[package]]\nname = \"urllib3\"\nversion = \"1.26.4\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("uv.lock"),
            "[[package]]\nname = \"werkzeug\"\nversion = \"2.2.2\"\n",
        )
        .unwrap();
        let findings = analyse_python_with(&dir, PY_SEED_ADVISORIES);
        std::fs::remove_dir_all(&dir).ok();
        assert!(findings
            .iter()
            .any(|f| f.message.contains("CVE-2021-33503")));
        assert!(findings
            .iter()
            .any(|f| f.message.contains("CVE-2023-25577")));
    }

    #[test]
    fn analyse_covers_rust_and_python_together() {
        // End to end through the entry point the pipeline calls: a vulnerable
        // Python pin is found, a fixed one stays silent, alongside the Rust
        // lockfile audit.
        let dir = std::env::temp_dir().join(format!("verum-deps-e2e-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("requirements.txt"),
            "PyYAML==5.3.1\nrequests==2.32.3\njinja2==2.11.3\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("Cargo.lock"),
            "[[package]]\nname = \"smallvec\"\nversion = \"1.6.0\"\n",
        )
        .unwrap();
        let findings = analyse(&dir);
        std::fs::remove_dir_all(&dir).ok();

        assert!(findings
            .iter()
            .any(|f| f.kind == FindingKind::VulnerableDependency
                && f.message.contains("CVE-2020-14343")));
        assert!(findings
            .iter()
            .any(|f| f.kind == FindingKind::VulnerableDependency
                && f.message.contains("RUSTSEC-2021-0003")));
        // requests 2.32.3 and jinja2 2.11.3 are at or past their fixes.
        assert!(!findings.iter().any(|f| f.message.contains("requests")));
        assert!(!findings.iter().any(|f| f.message.contains("jinja2")));
    }
}
