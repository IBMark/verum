//! Crate-semantics rules - behavioural facts about specific crates that
//! syntax analysis can't see.
//!
//! `interval.tick()` is syntactically perfect; whether it's a bug depends on
//! knowing that tokio's first tick fires immediately, or that `udp-stream`
//! maps one write to one datagram. That's curated knowledge, encoded here as
//! data and matched against files whose project actually depends on the crate
//! (which keeps the checks silent on unrelated code). Each rule should be a
//! specific, defensible fact with a low false-positive shape.

use std::collections::HashSet;
use std::path::Path;

use verum_nucleus::{matchable_path, Finding, FindingKind, Ir, Language, Severity};

/// A behavioural rule keyed to a crate. `needle` is the code shape that
/// triggers it; `guard` (if present) suppresses the rule for the whole file
/// when it appears anywhere in that file - a guard means "the author already
/// handled this", which is a per-file fact, not a per-line one.
struct CrateRule {
    krate: &'static str,
    needle: &'static str,
    guard: Option<&'static str>,
    severity: Severity,
    message: &'static str,
    suggestion: &'static str,
}

/// Curated rule table. Every entry states a documented behaviour of the named
/// crate whose naive use is a real defect.
const RULES: &[CrateRule] = &[
    CrateRule {
        krate: "tokio",
        needle: ".tick().await",
        guard: None,
        severity: Severity::Low,
        message: "tokio `interval` fires its FIRST tick immediately, not after \
                  one period - a loop that ticks then works starts with a \
                  zero-delay iteration",
        suggestion: "if you need a leading delay, tick once before the loop, or \
                     use `interval_at(Instant::now() + period, period)`; confirm \
                     the immediate first tick is intended",
    },
    CrateRule {
        krate: "tokio",
        // Fires at interval creation sites (`interval(` also matches
        // `interval_at(` - same Burst default) when the file never calls
        // `set_missed_tick_behavior`. Matching the type name itself would flag
        // exactly the people who imported it to fix the problem.
        needle: "interval(",
        guard: Some("set_missed_tick_behavior"),
        severity: Severity::Low,
        message: "tokio `interval` default missed-tick behaviour is `Burst`, \
                  which fires backlogged ticks rapidly after a stall",
        suggestion: "for steady-rate media/timers call \
                     `set_missed_tick_behavior(MissedTickBehavior::Delay|Skip)`",
    },
    CrateRule {
        krate: "udp-stream",
        needle: "UDP_BUFFER_SIZE",
        guard: None,
        severity: Severity::Medium,
        message: "udp-stream's internal recv buffer (17 480 bytes) is NOT a \
                  network-safe datagram size - writes map 1:1 to `send_to`, so a \
                  buffer-sized write fragments and is lost as a unit",
        suggestion: "size datagrams to the path MTU (~1200 bytes), not the crate \
                     recv buffer; see the transport pass",
    },
    CrateRule {
        krate: "std",
        needle: "mem::forget",
        guard: None,
        severity: Severity::Low,
        message: "`mem::forget` on a lock guard or RAII handle leaks the \
                  resource - a forgotten `MutexGuard` never unlocks",
        suggestion: "confirm the leak is intentional (e.g. handing ownership to \
                     FFI); otherwise drop normally or use `ManuallyDrop` with an \
                     explicit teardown",
    },
];

/// Reads every Rust file itself; prefer [`analyse_with_context`] when a
/// pre-read [`ScanContext`](crate::scan::ScanContext) is already available.
pub fn analyse(ir: &Ir, root: Option<&Path>) -> Vec<Finding> {
    analyse_with_context(ir, root, &crate::scan::ScanContext::index_only(ir))
}

/// Rule matching over the shared [`ScanContext`](crate::scan::ScanContext)
/// lines, so the tree is read once for all line-scanning passes. The
/// file-scoped guard check runs per line; guards are single-line needles, so
/// this matches the whole-content `contains` it replaces.
pub fn analyse_with_context(
    ir: &Ir,
    root: Option<&Path>,
    ctx: &crate::scan::ScanContext,
) -> Vec<Finding> {
    let Some(root) = root else { return Vec::new() };
    let deps = read_dependency_names(root);
    if deps.is_empty() {
        return Vec::new();
    }
    // `std` rules always apply; crate rules only when the crate is a dependency.
    let active: Vec<&CrateRule> = RULES
        .iter()
        .filter(|r| r.krate == "std" || deps.contains(r.krate))
        .collect();
    if active.is_empty() {
        return Vec::new();
    }

    let mut files: Vec<&std::path::PathBuf> = ir
        .files
        .iter()
        .filter(|(_, info)| info.language == Language::Rust)
        .map(|(p, _)| p)
        .collect();
    files.sort();

    let mut findings = Vec::new();
    for path in files {
        let path_str = matchable_path(path);
        if path_str.contains("/target/") {
            continue;
        }
        let Some(lines) = ctx.lines(path) else {
            continue;
        };
        // File-scoped guards: if a rule's guard appears anywhere in the file,
        // the author has already handled that behaviour - suppress the rule
        // for the whole file. Guards are single-line needles, so a per-line
        // scan finds exactly what a whole-content `contains` did.
        let file_rules: Vec<&&CrateRule> = active
            .iter()
            .filter(|r| {
                !r.guard
                    .is_some_and(|g| lines.iter().any(|line| line.contains(g)))
            })
            .collect();
        if file_rules.is_empty() {
            continue;
        }
        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with('*') {
                continue;
            }
            for rule in &file_rules {
                if !contains_needle(line, rule.needle) {
                    continue;
                }
                findings.push(Finding {
                    id: format!("crate-{}-{}:{}", rule.krate, path.display(), idx + 1),
                    kind: FindingKind::CrateApiMisuse,
                    severity: rule.severity.clone(),
                    confidence: 0.7,
                    file: path.to_path_buf(),
                    line_start: (idx + 1) as u32,
                    line_end: (idx + 1) as u32,
                    symbol: None,
                    message: format!("[{}] {}", rule.krate, rule.message),
                    suggestion: rule.suggestion.to_string(),
                    auto_fixable: false,
                    related: Vec::new(),
                });
            }
        }
    }
    findings.sort_by(|a, b| (&a.file, a.line_start).cmp(&(&b.file, b.line_start)));
    findings
}

/// Match `needle` in `line` with a leading word boundary when the needle
/// starts with an identifier character. Without this, `interval(` matches
/// inside `frame_interval(` - a false positive. Needles that start with a
/// non-identifier char (e.g. `.tick().await`) need no leading boundary; the
/// preceding token is part of the shape being matched.
fn contains_needle(line: &str, needle: &str) -> bool {
    let boundary_needed = needle
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
    if !boundary_needed {
        return line.contains(needle);
    }
    let mut from = 0;
    while let Some(pos) = line[from..].find(needle) {
        let abs = from + pos;
        let prev_ok = line[..abs]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_');
        if prev_ok {
            return true;
        }
        from = abs + 1;
    }
    false
}

/// Dependency crate names from `<root>/Cargo.toml` `[dependencies]` and
/// `[dev-dependencies]`/`[build-dependencies]` tables, including the
/// `[dependencies.<name>]` table-header form. Hand-parsed to avoid a
/// TOML dependency; hyphens/underscores are both retained as written.
fn read_dependency_names(root: &Path) -> HashSet<String> {
    let mut names = HashSet::new();
    let Ok(text) = std::fs::read_to_string(root.join("Cargo.toml")) else {
        return names;
    };
    let mut in_deps = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            let header = t.trim_start_matches('[').trim_end_matches(']').trim();
            // `[dependencies.tokio]`-style table headers declare the dep in the
            // header itself (also `[dev-dependencies.x]`, `[build-dependencies.x]`,
            // `[workspace.dependencies.x]`). Body keys (version, features) are
            // attributes of that one dep, not dep names.
            if let Some((table, name)) = header.rsplit_once('.') {
                if table.ends_with("dependencies") {
                    names.insert(name.trim().to_string());
                    in_deps = false;
                    continue;
                }
            }
            in_deps = header.contains("dependencies");
            continue;
        }
        if !in_deps || t.is_empty() || t.starts_with('#') {
            continue;
        }
        // `name = "1.0"` or `name = { version = "1" }`.
        if let Some(name) = t.split(['=', ' ']).next() {
            if !name.is_empty() {
                names.insert(name.to_string());
            }
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(tag: &str, cargo_toml: &str, rs: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("verum-crate-sem-{}-{}", std::process::id(), tag));
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("Cargo.toml"), cargo_toml).unwrap();
        std::fs::write(dir.join("src/lib.rs"), rs).unwrap();
        dir
    }

    fn analyse_project(dir: &Path) -> Vec<Finding> {
        let config = verum_mappa::AtlasConfig {
            root: dir.to_path_buf(),
            language: Language::Rust,
            ..Default::default()
        };
        let ir = verum_mappa::Atlas::new(config).build().expect("build");
        analyse(&ir, Some(dir))
    }

    #[test]
    fn tokio_interval_tick_flagged_when_tokio_present() {
        let dir = project(
            "tick-flagged",
            "[dependencies]\ntokio = \"1\"\n",
            "async fn run() {\n    let mut i = interval(dur);\n    loop { i.tick().await; work(); }\n}\n",
        );
        let findings = analyse_project(&dir);
        std::fs::remove_dir_all(&dir).ok();
        assert!(findings
            .iter()
            .any(
                |f| f.kind == FindingKind::CrateApiMisuse && f.message.contains("first tick")
                    || f.message.contains("FIRST tick")
            ));
    }

    #[test]
    fn rule_silent_without_dependency() {
        // Same code shape, but tokio is not a dependency -> no crate rule fires.
        let dir = project(
            "no-dep",
            "[dependencies]\nserde = \"1\"\n",
            "async fn run() {\n    thing.tick().await;\n}\n",
        );
        let findings = analyse_project(&dir);
        std::fs::remove_dir_all(&dir).ok();
        assert!(!findings.iter().any(|f| f.message.contains("tick")));
    }

    #[test]
    fn needle_respects_word_boundary() {
        // `interval(` must not match inside `frame_interval(`.
        assert!(!contains_needle(
            "    pub fn frame_interval(&self) -> Duration {",
            "interval("
        ));
        assert!(!contains_needle(
            "    let d = source.frame_interval();",
            "interval("
        ));
        // Real tokio interval creation still matches.
        assert!(contains_needle(
            "    let t = time::interval(dur);",
            "interval("
        ));
        assert!(contains_needle("    let t = interval(dur);", "interval("));
        // Needles that start with punctuation match as-is.
        assert!(contains_needle(
            "        ticker.tick().await;",
            ".tick().await"
        ));
    }

    #[test]
    fn frame_interval_is_not_flagged() {
        // Regression: a `frame_interval` method and its call
        // site must produce zero interval findings; only real interval sites do.
        let dir = project(
            "frame-interval-fp",
            "[dependencies]\ntokio = \"1\"\n",
            "pub fn frame_interval(&self) -> u64 { 1 }\n\
             fn run() { let d = self.frame_interval(); let _t = tokio::time::interval(d); }\n",
        );
        let findings = analyse_project(&dir);
        std::fs::remove_dir_all(&dir).ok();
        let interval_notes = findings
            .iter()
            .filter(|f| f.message.contains("missed-tick"))
            .count();
        assert_eq!(
            interval_notes, 1,
            "only the real interval() site should flag"
        );
    }

    #[test]
    fn std_rule_always_active() {
        let dir = project(
            "std-rule",
            "[dependencies]\nserde = \"1\"\n",
            "fn leak(g: Guard) {\n    std::mem::forget(g);\n}\n",
        );
        let findings = analyse_project(&dir);
        std::fs::remove_dir_all(&dir).ok();
        assert!(findings.iter().any(|f| f.message.contains("mem::forget")));
    }

    #[test]
    fn guard_suppresses_finding() {
        let dir = project(
            "guard-same-line",
            "[dependencies]\ntokio = \"1\"\n",
            "fn cfg(i: &mut Interval) {\n    i.set_missed_tick_behavior(MissedTickBehavior::Delay);\n}\n",
        );
        let findings = analyse_project(&dir);
        std::fs::remove_dir_all(&dir).ok();
        assert!(!findings.iter().any(|f| f.message.contains("missed-tick")));
    }

    #[test]
    fn interval_without_missed_tick_setter_flagged() {
        // `interval(` creation with no set_missed_tick_behavior anywhere in the
        // file -> the Burst-default rule fires.
        let dir = project(
            "interval-no-setter",
            "[dependencies]\ntokio = \"1\"\n",
            "async fn run() {\n    let mut i = tokio::time::interval(period);\n    loop { i.tick().await; work(); }\n}\n",
        );
        let findings = analyse_project(&dir);
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            findings.iter().any(|f| f.message.contains("missed-tick")),
            "interval( without set_missed_tick_behavior should flag Burst default"
        );
    }

    #[test]
    fn file_scoped_guard_suppresses_interval_rule() {
        // The guard appears on a DIFFERENT line from the interval creation -
        // file-scoped suppression must still apply.
        let dir = project(
            "interval-guarded",
            "[dependencies]\ntokio = \"1\"\n",
            "async fn run() {\n    let mut i = tokio::time::interval(period);\n    i.set_missed_tick_behavior(MissedTickBehavior::Delay);\n    loop { i.tick().await; work(); }\n}\n",
        );
        let findings = analyse_project(&dir);
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            !findings.iter().any(|f| f.message.contains("missed-tick")),
            "set_missed_tick_behavior anywhere in the file should suppress the rule"
        );
    }

    #[test]
    fn importing_missed_tick_behavior_not_flagged() {
        // Importing the type to FIX the problem must not trigger the rule.
        let dir = project(
            "import-not-flagged",
            "[dependencies]\ntokio = \"1\"\n",
            "use tokio::time::MissedTickBehavior;\n\nfn cfg(i: &mut Interval) {\n    i.set_missed_tick_behavior(MissedTickBehavior::Delay);\n}\n",
        );
        let findings = analyse_project(&dir);
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            !findings.iter().any(|f| f.message.contains("missed-tick")),
            "importing MissedTickBehavior + calling the setter must not flag"
        );
    }

    #[test]
    fn table_header_dependency_detected() {
        // `[dependencies.tokio]` table-header form must activate tokio rules.
        let dir = project(
            "table-header-dep",
            "[dependencies.tokio]\nversion = \"1\"\nfeatures = [\"full\"]\n",
            "async fn run() {\n    let mut i = tokio::time::interval(period);\n    loop { i.tick().await; work(); }\n}\n",
        );
        let findings = analyse_project(&dir);
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            findings.iter().any(|f| f.message.contains("missed-tick")),
            "[dependencies.tokio] header should register tokio as a dependency"
        );
        assert!(
            findings.iter().any(|f| f.message.contains("FIRST tick")),
            "tokio first-tick rule should also be active"
        );
    }

    #[test]
    fn read_dependency_names_handles_all_table_header_forms() {
        let dir = std::env::temp_dir().join(format!(
            "verum-crate-sem-{}-dep-headers",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("Cargo.toml"),
            "[dependencies]\nserde = \"1\"\n\n\
             [dependencies.tokio]\nversion = \"1\"\nfeatures = [\"full\"]\n\n\
             [dev-dependencies.proptest]\nversion = \"1\"\n\n\
             [workspace.dependencies.anyhow]\nversion = \"1\"\n",
        )
        .unwrap();
        let names = read_dependency_names(&dir);
        std::fs::remove_dir_all(&dir).ok();
        assert!(names.contains("serde"));
        assert!(names.contains("tokio"));
        assert!(names.contains("proptest"));
        assert!(names.contains("anyhow"));
        // Table-body attribute keys must not be mistaken for dep names.
        assert!(!names.contains("version"));
        assert!(!names.contains("features"));
    }
}
