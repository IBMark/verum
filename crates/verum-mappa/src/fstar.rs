//! Fstar front-end (scaffold).
//!
//! Registers the file with its language so the pipeline runs end-to-end;
//! symbol/call extraction is filled in by the language work. Returns a valid
//! single-file IR with zero symbols until then.

use std::path::Path;

use anyhow::{Context, Result};

use verum_nucleus::{FileId, FileInfo, Ir, Language};

/// Parse a Fstar file into a partial IR. Scaffold: file registration only.
pub fn parse_file(path: &Path) -> Result<Ir> {
    let source =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

    let mut ir = Ir::new();
    let line_count = source.lines().count() as u32;
    let size_bytes = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let file_id = FileId(crate::stable_hash(path.to_string_lossy().as_ref()));

    ir.files.insert(
        path.to_path_buf(),
        FileInfo {
            id: file_id,
            path: path.to_path_buf(),
            language: Language::Fstar,
            line_count,
            size_bytes,
            last_modified: 0,
            hash: crate::stable_hash(&source),
            symbols: Vec::new(),
        },
    );
    ir.metadata.total_files = 1;
    ir.metadata.total_lines = line_count as u64;

    Ok(ir)
}
