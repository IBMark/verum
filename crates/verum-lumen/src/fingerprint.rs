//! Stable finding fingerprints for baseline matching.
//!
//! A finding's `id` string embeds the absolute path and often a line number,
//! so it changes whenever the repo moves directories or an unrelated edit
//! shifts lines - useless as an identity for "is this the same finding as
//! last week?". The fingerprint assigned here is built only from properties
//! that survive both:
//!
//! * the kind's canonical label,
//! * the repo-RELATIVE path (never the absolute one),
//! * the symbol's short name, when the finding is pinned to a symbol,
//! * the message with every ASCII digit stripped (line numbers, counts and
//!   sizes cited in the text all drift; the words do not), and
//! * an occurrence index that disambiguates several findings sharing the
//!   same tuple in one file, counted in the findings' sorted order so it is
//!   deterministic.
//!
//! The hash is the workspace's documented [`verum_nucleus::stable_hash`]
//! (FNV-1a 64), hex-encoded to 16 chars. Line numbers are deliberately
//! absent: editing an unrelated part of a file, or checking the repo out at
//! a different absolute path, keeps every fingerprint identical - the two
//! properties the tests below pin down.

use std::collections::HashMap;
use std::path::Path;

use verum_nucleus::{stable_hash, Finding, Ir};

/// Assign a fingerprint to every finding in `findings`, in place.
///
/// `findings` must already be in its final sorted order (the global
/// file/line/id sort in [`crate::Prism`]): the occurrence index that keeps
/// duplicates of the same tuple distinct is the position among its
/// tuple-mates in iteration order, so a caller-visible order is what makes
/// the index reproducible.
///
/// `root` is the analysis root; it is canonicalized so a relative `.` and
/// the absolute path it resolves to produce identical fingerprints. Findings
/// outside `root` (or all findings, when `root` is `None`) fall back to the
/// path as recorded - such fingerprints are still deterministic but not
/// relocation-stable, which only affects trees analysed without a root.
pub fn assign(findings: &mut [Finding], ir: &Ir, root: Option<&Path>) {
    let canon = root.map(|r| std::fs::canonicalize(r).unwrap_or_else(|_| r.to_path_buf()));
    let mut occurrences: HashMap<String, u32> = HashMap::new();
    for f in findings {
        let material = material_for(f, ir, canon.as_deref());
        let index = occurrences.entry(material.clone()).or_insert(0);
        f.fingerprint = format!("{:016x}", stable_hash(&format!("{material}|{index}")));
        *index += 1;
    }
}

/// The hash input for one finding, minus the occurrence index.
fn material_for(f: &Finding, ir: &Ir, root: Option<&Path>) -> String {
    let rel = relative_path(f, root);
    let symbol = f
        .symbol
        .and_then(|id| ir.symbols.get(&id))
        .map(|s| s.name.as_str())
        .unwrap_or("");
    let message: String = f.message.chars().filter(|c| !c.is_ascii_digit()).collect();
    format!("{}|{}|{}|{}", f.kind.label(), rel, symbol, message.trim())
}

/// The finding's path relative to `root`, `/`-separated on every platform.
fn relative_path(f: &Finding, root: Option<&Path>) -> String {
    let stripped = match root {
        Some(root) => f.file.strip_prefix(root).unwrap_or(&f.file),
        None => &f.file,
    };
    stripped.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use verum_nucleus::{FindingKind, Severity};

    fn finding(file: &str, line: u32, message: &str) -> Finding {
        Finding {
            id: format!("test-{file}-{line}"),
            kind: FindingKind::WeakCrypto,
            severity: Severity::Medium,
            confidence: 1.0,
            file: PathBuf::from(file),
            line_start: line,
            line_end: line,
            symbol: None,
            message: message.to_string(),
            suggestion: String::new(),
            auto_fixable: false,
            related: Vec::new(),
            fingerprint: String::new(),
        }
    }

    #[test]
    fn line_numbers_do_not_change_the_fingerprint() {
        // The same finding before and after an unrelated edit above it: the
        // line shifted and the message cites the new line, nothing else moved.
        let mut before = vec![finding("/repo/src/lib.rs", 10, "weak md5 on line 10")];
        let mut after = vec![finding("/repo/src/lib.rs", 42, "weak md5 on line 42")];
        let ir = Ir::new();
        assign(&mut before, &ir, Some(Path::new("/repo")));
        assign(&mut after, &ir, Some(Path::new("/repo")));
        assert_eq!(before[0].fingerprint, after[0].fingerprint);
        assert_eq!(before[0].fingerprint.len(), 16);
    }

    #[test]
    fn the_absolute_path_of_the_repo_does_not_matter() {
        // The same repo checked out under two different absolute roots must
        // fingerprint identically - only the repo-relative path is hashed.
        let mut at_home = vec![finding("/home/dev/repo/src/lib.rs", 5, "weak md5")];
        let mut in_ci = vec![finding("/ci/build/1234/src/lib.rs", 5, "weak md5")];
        let ir = Ir::new();
        assign(&mut at_home, &ir, Some(Path::new("/home/dev/repo")));
        assign(&mut in_ci, &ir, Some(Path::new("/ci/build/1234")));
        assert_eq!(at_home[0].fingerprint, in_ci[0].fingerprint);
    }

    #[test]
    fn different_kinds_files_and_messages_differ() {
        let ir = Ir::new();
        let root = Some(Path::new("/repo"));

        let mut base = vec![finding("/repo/a.rs", 1, "weak md5")];
        assign(&mut base, &ir, root);

        let mut other_file = vec![finding("/repo/b.rs", 1, "weak md5")];
        assign(&mut other_file, &ir, root);
        assert_ne!(base[0].fingerprint, other_file[0].fingerprint);

        let mut other_message = vec![finding("/repo/a.rs", 1, "weak sha-one")];
        assign(&mut other_message, &ir, root);
        assert_ne!(base[0].fingerprint, other_message[0].fingerprint);

        let mut other_kind = vec![finding("/repo/a.rs", 1, "weak md5")];
        other_kind[0].kind = FindingKind::HardcodedSecret;
        assign(&mut other_kind, &ir, root);
        assert_ne!(base[0].fingerprint, other_kind[0].fingerprint);
    }

    #[test]
    fn duplicates_of_the_same_tuple_get_distinct_stable_fingerprints() {
        // Two hits of the same kind+message in one file (different lines)
        // must not collide, and the pair must be reproducible run-to-run.
        let ir = Ir::new();
        let root = Some(Path::new("/repo"));
        let mut run1 = vec![
            finding("/repo/a.rs", 3, "weak md5"),
            finding("/repo/a.rs", 9, "weak md5"),
        ];
        let mut run2 = run1.clone();
        assign(&mut run1, &ir, root);
        assign(&mut run2, &ir, root);
        assert_ne!(run1[0].fingerprint, run1[1].fingerprint);
        assert_eq!(run1[0].fingerprint, run2[0].fingerprint);
        assert_eq!(run1[1].fingerprint, run2[1].fingerprint);
    }

    #[test]
    fn the_symbol_name_separates_same_message_findings_across_symbols() {
        use verum_nucleus::{Language, Symbol, SymbolId, SymbolKind, Visibility};
        let mut ir = Ir::new();
        for (id, name) in [(1u64, "alpha"), (2, "beta")] {
            ir.symbols.insert(
                SymbolId(id),
                Symbol {
                    id: SymbolId(id),
                    name: name.to_string(),
                    fully_qualified: name.to_string(),
                    kind: SymbolKind::Function,
                    visibility: Visibility::Public,
                    file: PathBuf::from("/repo/a.rs"),
                    line_start: 1,
                    line_end: 2,
                    col_start: 0,
                    col_end: 0,
                    language: Language::Rust,
                    parent: None,
                    hash: 0,
                    normalized_hash: 0,
                    flow_hash: 0,
                    param_count: 0,
                    is_entry_point: false,
                    doc_comment: None,
                },
            );
        }
        let mut findings = vec![
            finding("/repo/a.rs", 1, "too complex"),
            finding("/repo/a.rs", 20, "too complex"),
        ];
        findings[0].symbol = Some(SymbolId(1));
        findings[1].symbol = Some(SymbolId(2));
        assign(&mut findings, &ir, Some(Path::new("/repo")));
        assert_ne!(findings[0].fingerprint, findings[1].fingerprint);
    }
}
