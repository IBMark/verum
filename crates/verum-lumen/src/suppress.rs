//! Inline finding suppressions: `verum:ignore` comments.
//!
//! A comment on the finding's line, or on the line directly above it,
//! suppresses the finding:
//!
//! ```text
//! // verum:ignore                       - every kind on this/the next line
//! # verum:ignore[WeakCrypto]            - only the listed kinds
//! /* verum:ignore[SqlInjection,EvalUsage] reviewed 2024-06 */ - with a reason
//! -- verum:ignore checksum, not auth
//! ```
//!
//! The token must sit inside a comment for the file's language family
//! (`//`/`/*` for the C-family languages, `#` for Python/shell/YAML/HCL,
//! `--` for SQL/Lua/Haskell); a `verum:ignore` inside plain code or a string
//! with no comment marker before it on the line does nothing. Kind names are
//! the canonical labels reports print ([`FindingKind::label`]).
//!
//! This is a cheap post-pass: it scans only the files that HAVE findings
//! (through [`ScanContext::lines`], so pre-read files are not re-read), after
//! analysis has already produced its final sorted finding list. Suppressed
//! findings are removed from the report and counted; a suppression that
//! matches nothing becomes a Low [`FindingKind::StaleSuppression`] finding so
//! stale comments cannot rot silently - either they document a fixed issue
//! (delete them) or they sit ready to swallow the next real finding there.
//!
//! Findings pinned to no line (`line_start == 0` - whole-file and
//! dependency-level findings) cannot be suppressed inline: there is no line
//! to put the comment on.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use verum_nucleus::{Finding, FindingKind, Severity};

use crate::scan::{ScanContext, MAX_SCAN_LINE_BYTES};

/// The marker every suppression comment carries.
const TOKEN: &str = "verum:ignore";

/// The outcome of applying inline suppressions to a finding list.
#[derive(Debug, Default)]
pub struct Outcome {
    /// Findings that survive, in their incoming order.
    pub kept: Vec<Finding>,
    /// Findings removed by a matching `verum:ignore`, in their incoming order.
    pub suppressed: Vec<Finding>,
    /// One Low [`FindingKind::StaleSuppression`] finding per `verum:ignore`
    /// comment that suppressed nothing, ordered by file then line.
    pub stale: Vec<Finding>,
}

/// One parsed `verum:ignore` site.
#[derive(Debug)]
struct Site {
    /// 1-based line the comment sits on; it covers findings on this line and
    /// the next.
    line: u32,
    /// `None` = all kinds; `Some(labels)` = only these kinds.
    kinds: Option<Vec<String>>,
    /// Whether any finding was suppressed by this site.
    used: bool,
}

impl Site {
    fn allows(&self, kind: &FindingKind) -> bool {
        match &self.kinds {
            None => true,
            Some(labels) => labels.iter().any(|l| l == kind.label()),
        }
    }

    /// The canonical text of the comment, reconstructed for the stale
    /// diagnostic - never the raw line, which could carry anything.
    fn display(&self) -> String {
        match &self.kinds {
            None => TOKEN.to_string(),
            Some(labels) => format!("{TOKEN}[{}]", labels.join(",")),
        }
    }
}

/// Apply inline suppressions to `findings` (already in final sorted order).
pub fn apply(findings: Vec<Finding>, ctx: &ScanContext) -> Outcome {
    // Only the files that have findings are scanned, sorted so the stale
    // diagnostics come out in a fixed order.
    let files: BTreeSet<PathBuf> = findings
        .iter()
        .filter(|f| f.line_start > 0)
        .map(|f| f.file.clone())
        .collect();

    let mut sites: BTreeMap<PathBuf, Vec<Site>> = BTreeMap::new();
    for file in files {
        let found = collect_sites(&file, ctx);
        if !found.is_empty() {
            sites.insert(file, found);
        }
    }

    let mut outcome = Outcome::default();
    if sites.is_empty() {
        outcome.kept = findings;
        return outcome;
    }

    for finding in findings {
        let mut matched = false;
        if finding.line_start > 0 {
            if let Some(file_sites) = sites.get_mut(&finding.file) {
                for site in file_sites.iter_mut().filter(|s| {
                    (s.line == finding.line_start || s.line + 1 == finding.line_start)
                        && s.allows(&finding.kind)
                }) {
                    site.used = true;
                    matched = true;
                }
            }
        }
        if matched {
            outcome.suppressed.push(finding);
        } else {
            outcome.kept.push(finding);
        }
    }

    for (file, file_sites) in &sites {
        for site in file_sites.iter().filter(|s| !s.used) {
            outcome.stale.push(stale_finding(file, site));
        }
    }

    outcome
}

/// Every `verum:ignore` site in `path`, in line order.
fn collect_sites(path: &Path, ctx: &ScanContext) -> Vec<Site> {
    let Some(lines) = ctx.lines(path) else {
        return Vec::new();
    };
    let markers = comment_markers(path);
    let mut sites = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        if line.len() > MAX_SCAN_LINE_BYTES {
            continue;
        }
        if let Some(kinds) = parse_line(line, markers) {
            sites.push(Site {
                line: (idx + 1) as u32,
                kinds,
                used: false,
            });
        }
    }
    sites
}

/// The comment markers that can introduce a suppression in this file. An
/// unknown extension accepts every family - wrongly honoring a clearly
/// deliberate `# verum:ignore` in some niche config format beats silently
/// ignoring it.
fn comment_markers(path: &Path) -> &'static [&'static str] {
    const SLASH: &[&str] = &["//", "/*"];
    const HASH: &[&str] = &["#"];
    const SLASH_OR_HASH: &[&str] = &["//", "/*", "#"];
    const DASH: &[&str] = &["--"];
    const ALL: &[&str] = &["//", "/*", "#", "--"];

    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if file_name == "Dockerfile" || file_name.starts_with("Dockerfile.") {
        return HASH;
    }
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "rs" | "go" | "java" | "js" | "jsx" | "ts" | "tsx" | "c" | "h" | "cc" | "cpp" | "hpp"
        | "cs" | "kt" | "swift" | "scala" => SLASH,
        // PHP comments come in both families.
        "php" => SLASH_OR_HASH,
        "py" | "rb" | "sh" | "bash" | "yaml" | "yml" | "toml" | "tf" | "tfvars" => HASH,
        "sql" | "lua" | "hs" => DASH,
        _ => ALL,
    }
}

/// Parse one line for a suppression. `Some(None)` = suppress all kinds;
/// `Some(Some(labels))` = suppress the listed kinds; `None` = no suppression
/// on this line.
///
/// The token must appear AFTER a comment marker on the same line, so a
/// string literal containing `verum:ignore` in code position is inert. A
/// malformed kind list (`[` without `]`) is not a suppression at all - a
/// parse fallback that silently widened to "ignore everything" would be a
/// trap. The optional reason after the token/list is free text and ignored.
#[allow(clippy::type_complexity)]
fn parse_line(line: &str, markers: &[&str]) -> Option<Option<Vec<String>>> {
    let token_at = line.find(TOKEN)?;
    let before = &line[..token_at];
    if !markers.iter().any(|m| before.contains(m)) {
        return None;
    }
    let rest = &line[token_at + TOKEN.len()..];
    match rest.as_bytes().first() {
        // Bare `verum:ignore`, optionally followed by a reason.
        None => Some(None),
        Some(b' ') | Some(b'\t') => Some(None),
        Some(b'[') => {
            let end = rest.find(']')?;
            let kinds: Vec<String> = rest[1..end]
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
            Some(Some(kinds))
        }
        // `verum:ignored`, `verum:ignore-this`, ... are not the token.
        Some(_) => None,
    }
}

fn stale_finding(file: &Path, site: &Site) -> Finding {
    Finding {
        id: format!("stale-suppression-{}:{}", file.display(), site.line),
        kind: FindingKind::StaleSuppression,
        severity: Severity::Low,
        confidence: 1.0,
        file: file.to_path_buf(),
        line_start: site.line,
        line_end: site.line,
        symbol: None,
        message: format!(
            "Stale suppression: `{}` matches no finding on its line or the line below",
            site.display()
        ),
        suggestion: "remove the comment if the issue is fixed, or correct its kind list; \
                     a stale suppression will silently swallow the next finding here"
            .to_string(),
        auto_fixable: false,
        related: Vec::new(),
        fingerprint: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use verum_nucleus::{Finding, FindingKind, Severity};

    fn finding(file: &Path, line: u32, kind: FindingKind) -> Finding {
        Finding {
            id: format!("t-{}:{line}", file.display()),
            kind,
            severity: Severity::Critical,
            confidence: 1.0,
            file: file.to_path_buf(),
            line_start: line,
            line_end: line,
            symbol: None,
            message: "test finding".to_string(),
            suggestion: String::new(),
            auto_fixable: false,
            related: Vec::new(),
            fingerprint: String::new(),
        }
    }

    /// A scratch file the on-demand `ScanContext::lines` fallback can read.
    struct TempFile(std::path::PathBuf);

    impl TempFile {
        fn new(name: &str, content: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "verum-suppress-{}-{}-{name}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::write(&path, content).expect("write temp file");
            TempFile(path)
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn parse_accepts_each_comment_family() {
        assert_eq!(parse_line("// verum:ignore", &["//", "/*"]), Some(None));
        assert_eq!(
            parse_line("/* verum:ignore reviewed */", &["//", "/*"]),
            Some(None)
        );
        assert_eq!(parse_line("# verum:ignore", &["#"]), Some(None));
        assert_eq!(parse_line("-- verum:ignore", &["--"]), Some(None));
        assert_eq!(
            parse_line("x = 1  # verum:ignore trailing comment", &["#"]),
            Some(None)
        );
    }

    #[test]
    fn parse_reads_the_kind_list_and_ignores_the_reason() {
        assert_eq!(
            parse_line("// verum:ignore[WeakCrypto] gravatar only", &["//"]),
            Some(Some(vec!["WeakCrypto".to_string()]))
        );
        assert_eq!(
            parse_line("# verum:ignore[SqlInjection, EvalUsage]", &["#"]),
            Some(Some(vec![
                "SqlInjection".to_string(),
                "EvalUsage".to_string()
            ]))
        );
    }

    #[test]
    fn parse_rejects_non_comments_and_near_misses() {
        // Plain comments never suppress.
        assert_eq!(parse_line("// TODO: clean this up", &["//", "/*"]), None);
        // The token in code/string position, with no comment marker before it.
        assert_eq!(parse_line("let s = \"verum:ignore\";", &["//", "/*"]), None);
        assert_eq!(parse_line("s = 'verum:ignore'", &["#"]), None);
        // The wrong family's marker for this language.
        assert_eq!(parse_line("# verum:ignore", &["//", "/*"]), None);
        // A longer word that merely starts with the token.
        assert_eq!(parse_line("// verum:ignored", &["//", "/*"]), None);
        // A malformed kind list must not widen to ignore-everything.
        assert_eq!(
            parse_line("// verum:ignore[WeakCrypto", &["//", "/*"]),
            None
        );
    }

    #[test]
    fn a_suppression_on_the_finding_line_or_above_suppresses_it() {
        let same = TempFile::new(
            "same.rs",
            "fn main() {\n    let d = md5(x); // verum:ignore checksum only\n}\n",
        );
        let above = TempFile::new(
            "above.rs",
            "fn main() {\n    // verum:ignore checksum only\n    let d = md5(x);\n}\n",
        );
        let ctx = ScanContext::default();

        let out = apply(vec![finding(&same.0, 2, FindingKind::WeakCrypto)], &ctx);
        assert_eq!(out.kept.len(), 0);
        assert_eq!(out.suppressed.len(), 1);
        assert_eq!(out.stale.len(), 0);

        let out = apply(vec![finding(&above.0, 3, FindingKind::WeakCrypto)], &ctx);
        assert_eq!(out.kept.len(), 0);
        assert_eq!(out.suppressed.len(), 1);
        assert_eq!(out.stale.len(), 0);
    }

    #[test]
    fn a_kind_filter_only_suppresses_the_listed_kinds() {
        let file = TempFile::new(
            "filter.py",
            "# verum:ignore[WeakCrypto]\nh = md5(eval(x))\n",
        );
        let ctx = ScanContext::default();
        let out = apply(
            vec![
                finding(&file.0, 2, FindingKind::WeakCrypto),
                finding(&file.0, 2, FindingKind::EvalUsage),
            ],
            &ctx,
        );
        assert_eq!(out.suppressed.len(), 1);
        assert_eq!(out.suppressed[0].kind, FindingKind::WeakCrypto);
        assert_eq!(out.kept.len(), 1);
        assert_eq!(out.kept[0].kind, FindingKind::EvalUsage);
        // The site suppressed something, so it is not stale.
        assert_eq!(out.stale.len(), 0);
    }

    #[test]
    fn an_unmatched_suppression_becomes_a_stale_finding() {
        let file = TempFile::new(
            "stale.py",
            "# verum:ignore[SqlInjection]\nh = md5(x)\nok = 1\n# verum:ignore\n",
        );
        let ctx = ScanContext::default();
        let out = apply(vec![finding(&file.0, 2, FindingKind::WeakCrypto)], &ctx);
        // The WeakCrypto finding survives: the filter names a different kind.
        assert_eq!(out.kept.len(), 1);
        assert_eq!(out.suppressed.len(), 0);
        // Both sites matched nothing.
        assert_eq!(out.stale.len(), 2);
        assert!(out
            .stale
            .iter()
            .all(|f| f.kind == FindingKind::StaleSuppression));
        assert!(out.stale.iter().all(|f| f.severity == Severity::Low));
        assert_eq!(out.stale[0].line_start, 1);
        assert!(out.stale[0].message.contains("verum:ignore[SqlInjection]"));
        assert_eq!(out.stale[1].line_start, 4);
    }

    #[test]
    fn normal_comments_and_unrelated_lines_never_suppress() {
        let file = TempFile::new(
            "normal.rs",
            "// this md5 use is reviewed and fine\nlet d = md5(x);\n",
        );
        let ctx = ScanContext::default();
        let out = apply(vec![finding(&file.0, 2, FindingKind::WeakCrypto)], &ctx);
        assert_eq!(out.kept.len(), 1);
        assert_eq!(out.suppressed.len(), 0);
        assert_eq!(out.stale.len(), 0);
    }

    #[test]
    fn a_suppression_two_lines_above_does_not_reach_the_finding() {
        let file = TempFile::new("distance.rs", "// verum:ignore\n\nlet d = md5(x);\n");
        let ctx = ScanContext::default();
        let out = apply(vec![finding(&file.0, 3, FindingKind::WeakCrypto)], &ctx);
        assert_eq!(out.kept.len(), 1);
        assert_eq!(out.stale.len(), 1, "the out-of-range site is stale");
    }

    #[test]
    fn line_zero_findings_cannot_be_suppressed() {
        // Whole-file findings have no line to carry a comment; a comment on
        // line 1 must not swallow them.
        let file = TempFile::new("filelevel.tf", "# verum:ignore\nresource {}\n");
        let ctx = ScanContext::default();
        let out = apply(
            vec![finding(&file.0, 0, FindingKind::UnencryptedStorage)],
            &ctx,
        );
        assert_eq!(out.kept.len(), 1);
        assert_eq!(out.suppressed.len(), 0);
    }
}
