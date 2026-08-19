//! Dependency audit - offline, deterministic.
//!
//! Parses `Cargo.lock` and matches locked crate versions against a curated
//! snapshot of RustSec advisories embedded at build time. No network, no
//! external process: the same lockfile always produces the same findings.
//!
//! The embedded [`SEED_ADVISORIES`] is intentionally small and contains only
//! advisories whose affected-version boundaries are stated with confidence -
//! a wrong boundary is a false positive, which this project treats as worse
//! than a miss. The set is meant to be regenerated/augmented from a full
//! `advisory-db` checkout; the matching engine below is the durable part.

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
/// (used for unmaintained crates).
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

/// A crate as pinned in Cargo.lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedPackage {
    pub name: String,
    pub version: String,
}

/// Parse the `[[package]]` blocks of a Cargo.lock. Hand-rolled: the file is a
/// regular subset of TOML (one `name`/`version` string per package block), so
/// this avoids a TOML dependency while staying exact for the real format.
pub fn parse_cargo_lock(text: &str) -> Vec<LockedPackage> {
    let mut packages = Vec::new();
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
        } else if let Some(rest) = t.strip_prefix("name = ") {
            name = unquote(rest);
        } else if let Some(rest) = t.strip_prefix("version = ") {
            version = unquote(rest);
        }
    }
    flush(&mut packages, &mut name, &mut version);
    packages
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

/// Audit a project root: reads `<root>/Cargo.lock` if present.
pub fn analyse(root: &Path) -> Vec<Finding> {
    analyse_with(root, SEED_ADVISORIES)
}

/// Testable core: advisory table injected.
pub fn analyse_with(root: &Path, advisories: &[Advisory]) -> Vec<Finding> {
    let lock_path = root.join("Cargo.lock");
    let Ok(text) = std::fs::read_to_string(&lock_path) else {
        return Vec::new();
    };
    let packages = parse_cargo_lock(&text);
    let mut findings = Vec::new();

    for pkg in &packages {
        let Some(locked) = Version::parse(&pkg.version) else {
            continue;
        };
        for adv in advisories.iter().filter(|a| a.package == pkg.name) {
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
                id: format!("dep-{}-{}", adv.id, pkg.name),
                kind,
                severity: adv.severity.clone(),
                confidence: 1.0,
                file: lock_path.clone(),
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

    // Duplicate incompatible versions of one crate - diamond-dependency bloat.
    // The compatibility unit is cargo's, not just the major: for 0.x releases
    // the minor is the breaking axis (0.7 vs 0.8), so key on minor when major
    // is 0.
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
}
