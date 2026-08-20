//! Shared, computed-once inputs for the line-scanning passes.
//!
//! `transport`, `taint` and `rust_insights` all walk the tree file by file and,
//! for each file, need the same two things: the file's lines, and the symbols
//! declared in it. Each pass used to derive both for itself, which cost twice
//! over:
//!
//! * every file was `std::fs::read` and split into a `Vec<String>` once per
//!   pass, serially; and
//! * the symbols of a file were found by scanning *all* of `ir.symbols` and
//!   comparing paths, making the per-file loop quadratic in the size of the
//!   repo (`files x symbols`) - the dominant cost on a large tree, and paid
//!   again on every round of `taint`'s fixpoint.
//!
//! [`ScanContext`] does both once: the symbol index is a single O(symbols)
//! bucketing, and [`ScanContext::build`] additionally reads and line-splits the
//! whole tree in parallel (the shape `verum-mappa` already uses for parsing) so
//! the three passes share one copy.
//!
//! The context is a pure performance layer. [`ScanContext::lines`] falls back to
//! reading from disk for any path it does not hold, so a pass driven with
//! [`ScanContext::index_only`] behaves exactly as it did when it read the file
//! itself. Findings are unchanged either way.

use std::borrow::Cow;
use std::collections::HashMap;
use std::io::BufRead;
use std::path::{Path, PathBuf};

use rayon::prelude::*;
use verum_nucleus::{Ir, SymbolId};

/// Per-line budget for the line-scanning passes, in bytes.
///
/// A generated or minified blob that slips past the mapper's sampling (its
/// first 64 KiB can look ordinary) presents multi-megabyte single lines, and
/// several scanners do per-occurrence context extraction that is worst-case
/// quadratic in line length - one such line can stall a pass for minutes.
/// Lines longer than this are skipped by the scanners that would otherwise
/// walk them.
///
/// This is a deterministic INPUT-size guard, never a wall-clock timeout: the
/// decision depends only on the bytes of the file, so identical inputs skip
/// identical lines on every machine. The cap is far above hand-written code
/// (which practically never exceeds a few hundred bytes per line) so no
/// legitimate source loses findings.
pub const MAX_SCAN_LINE_BYTES: usize = 10_000;

/// Per-file lines and symbol ids, shared by every line-scanning pass.
#[derive(Debug, Default)]
pub struct ScanContext {
    /// Absent for a file whose lines were not pre-read; [`ScanContext::lines`]
    /// then reads it on demand.
    lines: HashMap<PathBuf, Vec<String>>,
    /// Every file's symbols, in ascending [`SymbolId`] order. Sorting by id
    /// rather than leaving the IR's `HashMap` order is what keeps a pass that
    /// stable-sorts spans by line range byte-identical from run to run.
    symbols: HashMap<PathBuf, Vec<SymbolId>>,
}

impl ScanContext {
    /// Index the IR's symbols by file, without pre-reading any source.
    ///
    /// For the single-pass entry points, where there is no second reader to
    /// amortise a whole-tree read against.
    pub fn index_only(ir: &Ir) -> Self {
        Self {
            lines: HashMap::new(),
            symbols: index_symbols(ir),
        }
    }

    /// Index the IR's symbols by file *and* read and line-split every file in
    /// the IR, in parallel.
    ///
    /// Unreadable files are simply absent; callers treat a missing entry the
    /// same way they treated a failed `read` before.
    pub fn build(ir: &Ir) -> Self {
        let paths: Vec<&PathBuf> = ir.files.keys().collect();
        let lines = paths
            .par_iter()
            .filter_map(|path| read_lines(path).map(|lines| ((*path).clone(), lines)))
            .collect();
        Self {
            lines,
            symbols: index_symbols(ir),
        }
    }

    /// Index the IR's symbols by file and take one file's lines from memory
    /// instead of the filesystem.
    ///
    /// Only for the out-of-tree fuzz targets, which drive the line-scanning
    /// passes over adversarial input without wanting a temp file per case.
    #[cfg(feature = "fuzzing")]
    pub fn with_lines(ir: &Ir, path: &Path, lines: Vec<String>) -> Self {
        let mut ctx = Self::index_only(ir);
        ctx.lines.insert(path.to_path_buf(), lines);
        ctx
    }

    /// The lines of `path`, borrowed when pre-read and read from disk when not.
    /// `None` means the file could not be read.
    pub fn lines(&self, path: &Path) -> Option<Cow<'_, [String]>> {
        match self.lines.get(path) {
            Some(lines) => Some(Cow::Borrowed(lines.as_slice())),
            None => read_lines(path).map(Cow::Owned),
        }
    }

    /// The ids of the symbols declared in `path`, ascending. Empty for a file
    /// with no symbols.
    pub fn symbols(&self, path: &Path) -> &[SymbolId] {
        self.symbols.get(path).map(Vec::as_slice).unwrap_or(&[])
    }
}

/// Bucket every symbol under its file in one pass over the IR, so a per-file
/// loop no longer rescans all symbols per file.
fn index_symbols(ir: &Ir) -> HashMap<PathBuf, Vec<SymbolId>> {
    let mut by_file: HashMap<PathBuf, Vec<SymbolId>> = HashMap::new();
    for (id, symbol) in &ir.symbols {
        by_file.entry(symbol.file.clone()).or_default().push(*id);
    }
    for ids in by_file.values_mut() {
        ids.sort_by_key(|id| id.0);
    }
    by_file
}

/// Split a file into lines exactly the way the passes used to: `std::fs::read`
/// followed by `BufRead::lines`, with an undecodable line becoming empty rather
/// than aborting the file. Keeping this byte-for-byte identical is what makes
/// the context invisible to findings.
fn read_lines(path: &Path) -> Option<Vec<String>> {
    let raw = std::fs::read(path).ok()?;
    Some(raw.lines().map(|l| l.unwrap_or_default()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_read_and_on_demand_lines_match() {
        // `file!()` is workspace-relative but tests run from the crate dir.
        let path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src/scan.rs"));
        let read = read_lines(path).expect("this source file is readable");
        assert!(!read.is_empty());

        let mut lines = HashMap::new();
        lines.insert(path.to_path_buf(), read);
        let warm = ScanContext {
            lines,
            symbols: HashMap::new(),
        };
        let cold = ScanContext::default();

        assert_eq!(
            warm.lines(path).expect("pre-read").into_owned(),
            cold.lines(path).expect("read through").into_owned(),
        );
    }

    #[test]
    fn missing_file_has_no_lines_and_no_symbols() {
        let ctx = ScanContext::default();
        let missing = Path::new("/no/such/verum/file.rs");
        assert!(ctx.lines(missing).is_none());
        assert!(ctx.symbols(missing).is_empty());
    }

    #[test]
    fn symbols_are_grouped_by_file_in_id_order() {
        use verum_nucleus::{Language, Symbol, SymbolKind, Visibility};

        let mut ir = Ir::new();
        // Insert out of id order and across two files; the index must bucket by
        // file and return ascending ids regardless of IR iteration order.
        for (id, file) in [(3u64, "b.rs"), (1, "a.rs"), (2, "a.rs")] {
            ir.symbols.insert(
                SymbolId(id),
                Symbol {
                    id: SymbolId(id),
                    name: format!("s{id}"),
                    fully_qualified: format!("s{id}"),
                    kind: SymbolKind::Function,
                    visibility: Visibility::Public,
                    file: PathBuf::from(file),
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

        let ctx = ScanContext::index_only(&ir);
        assert_eq!(
            ctx.symbols(Path::new("a.rs")),
            &[SymbolId(1), SymbolId(2)][..]
        );
        assert_eq!(ctx.symbols(Path::new("b.rs")), &[SymbolId(3)][..]);
    }
}
