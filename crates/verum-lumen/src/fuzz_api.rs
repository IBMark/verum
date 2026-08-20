//! In-memory entry points for the out-of-tree fuzz targets.
//!
//! The line-scanning passes (`security`, `taint`, `transport`,
//! `crypto_hygiene`, `rust_insights`) all take an [`Ir`] and read the files it
//! names off disk. That shape is right for the analyzer and wrong for a fuzzer,
//! which wants to push millions of adversarial line arrays through the pure
//! detector logic without a temp file per case.
//!
//! This module builds the smallest [`Ir`] plus [`ScanContext`] that makes those
//! passes scan a synthetic file whose lines come straight from the fuzzer, and
//! runs them all. It is compiled only under the off-by-default `fuzzing`
//! feature, so the normal build, the default test run and the published crate
//! are unaffected.

use std::path::{Path, PathBuf};

use verum_nucleus::{FileId, FileInfo, Ir, Language, Symbol, SymbolId, SymbolKind, Visibility};

use crate::scan::ScanContext;
use crate::SecurityConfig;

/// One synthetic file for the line-scanning passes to chew on.
pub struct FuzzFile {
    /// The path the file is attributed to. Never read: [`ScanContext`] serves
    /// the lines from memory. Several passes branch on path substrings
    /// (`/tests/`, `vendor/`, `.blade.php`), so it is worth fuzzing too.
    pub path: PathBuf,
    /// The file's lines, exactly as `ScanContext` would have split them.
    pub lines: Vec<String>,
    /// Which language the file claims to be. Gates several detectors.
    pub language: Language,
    /// `(line_start, line_end)` for the synthetic function symbols declared in
    /// the file. Deliberately unconstrained: a span may be zero-based,
    /// inverted, or point past the end of `lines`, which is exactly the class
    /// of input a truncated or hostile parse can hand the passes.
    pub fn_spans: Vec<(u32, u32)>,
}

/// Run every per-file line-scanning pass over `file`, returning the total
/// number of findings so the work cannot be optimized away.
///
/// Nothing here touches the filesystem.
pub fn run_line_passes(file: &FuzzFile) -> usize {
    let ir = single_file_ir(file);
    let ctx = ScanContext::with_lines(&ir, &file.path, file.lines.clone());

    let config = SecurityConfig::default();
    let mut total = crate::security::analyse_with_context(&ir, &config, &ctx).len();
    total += crate::taint::analyse_with_context(&ir, &ctx).0.len();
    total += crate::transport::analyse_with_context(&ir, &ctx).len();
    total += crate::crypto_hygiene::analyse_with_context(&ir, &ctx).len();
    total += crate::rust_insights::analyse_with_context(&ir, &ctx).len();
    total
}

/// The `#[cfg(test)]` range scanner, which every line pass runs first and which
/// is pure line arithmetic - worth a direct shot from the fuzzer.
pub fn cfg_test_ranges(lines: &[String]) -> Vec<(u32, u32)> {
    crate::rust_insights::cfg_test_ranges(lines)
}

/// An IR holding exactly one file and one function symbol per requested span.
fn single_file_ir(file: &FuzzFile) -> Ir {
    let mut ir = Ir::new();

    let symbols: Vec<SymbolId> = file
        .fn_spans
        .iter()
        .enumerate()
        .map(|(idx, _)| SymbolId(idx as u64 + 1))
        .collect();

    for (id, (start, end)) in symbols.iter().zip(&file.fn_spans) {
        ir.symbols.insert(
            *id,
            Symbol {
                id: *id,
                name: format!("f{}", id.0),
                fully_qualified: format!("f{}", id.0),
                kind: SymbolKind::Function,
                visibility: Visibility::Public,
                file: file.path.clone(),
                line_start: *start,
                line_end: *end,
                col_start: 0,
                col_end: 0,
                language: file.language.clone(),
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

    ir.files.insert(
        file.path.clone(),
        FileInfo {
            id: FileId(1),
            path: file.path.clone(),
            language: file.language.clone(),
            line_count: file.lines.len() as u32,
            size_bytes: file.lines.iter().map(|l| l.len() as u64 + 1).sum(),
            last_modified: 0,
            hash: 0,
            symbols,
        },
    );
    ir.metadata.total_files = 1;
    ir.metadata.total_lines = file.lines.len() as u64;
    ir
}

/// Map a fuzzer byte to a language, so the fuzzer can steer which detectors a
/// case reaches without knowing the enum.
pub fn language_from_byte(b: u8) -> Language {
    match b % 10 {
        0 => Language::Php,
        1 => Language::Rust,
        2 => Language::JavaScript,
        3 => Language::TypeScript,
        4 => Language::Python,
        5 => Language::Go,
        6 => Language::Java,
        7 => Language::Terraform,
        8 => Language::Kubernetes,
        _ => Language::Docker,
    }
}

/// A path for `language` under one of the directory shapes the passes branch
/// on, selected by a fuzzer byte.
///
/// Several passes decide whether to scan a file from its path alone - `/tests/`
/// and `vendor/` are skipped, `fixtures` is deliberately not - so the path is
/// as much an input as the lines are. A fixed table beats a fuzzed string here:
/// every variant is a branch that actually exists, instead of a random name
/// that always takes the same one.
pub fn path_for(language: &Language, variant: u8) -> PathBuf {
    let dir = match variant % 8 {
        0 => "src",
        1 => "tests",
        2 => "vendor",
        3 => "node_modules",
        4 => "tests/fixtures",
        5 => "benchmarks",
        6 => "target/debug",
        _ => "app/Http",
    };
    let ext = match language {
        Language::Php => "php",
        Language::Rust => "rs",
        Language::JavaScript => "js",
        Language::TypeScript => "ts",
        Language::Python => "py",
        Language::Go => "go",
        Language::Java => "java",
        Language::Terraform => "tf",
        Language::Kubernetes => "yaml",
        Language::Docker => "Dockerfile",
        Language::Unknown => "txt",
    };
    // The odd variants out: a Blade template and a `_test.rs`, both of which
    // are skipped by name rather than by directory.
    let stem = match variant % 3 {
        0 => "case",
        1 => "case_test",
        _ => "case.blade",
    };
    Path::new(dir).join(format!("{stem}.{ext}"))
}
