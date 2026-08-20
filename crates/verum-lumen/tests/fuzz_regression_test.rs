//! Regression cases for crashes found by the fuzz targets in `fuzz/`.
//!
//! The fuzzers need nightly and are not part of the normal gate, so each
//! finding is pinned by a plain test as well as by a seed. The assertion is
//! only "this returns rather than panicking": what a pass makes of a malformed
//! IR is not contractual, but that it survives one is.

use std::path::PathBuf;

use verum_nucleus::{FileId, FileInfo, Ir, Language, Symbol, SymbolId, SymbolKind, Visibility};

/// A one-file, one-symbol IR whose function symbol spans `line_start` to
/// `line_end`, backed by a real file on disk (the passes read it themselves).
fn ir_with_span(name: &str, source: &str, line_start: u32, line_end: u32) -> Ir {
    let dir = std::env::temp_dir().join(format!(
        "verum-lumen-fuzz-regression-{}-{}",
        std::process::id(),
        name
    ));
    std::fs::create_dir_all(&dir).expect("temp dir is creatable");
    let path: PathBuf = dir.join("case.rs");
    std::fs::write(&path, source).expect("temp file is writable");

    let mut ir = Ir::new();
    let id = SymbolId(1);
    ir.symbols.insert(
        id,
        Symbol {
            id,
            name: "f".to_string(),
            fully_qualified: "f".to_string(),
            kind: SymbolKind::Function,
            visibility: Visibility::Public,
            file: path.clone(),
            line_start,
            line_end,
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
    ir.files.insert(
        path.clone(),
        FileInfo {
            id: FileId(1),
            path,
            language: Language::Rust,
            line_count: source.lines().count() as u32,
            size_bytes: source.len() as u64,
            last_modified: 0,
            hash: 0,
            symbols: vec![id],
        },
    );
    ir
}

/// `rust_insights` built its "smallest enclosing span per line" table with a
/// plain `end - start`, which underflows for a symbol whose `line_end`
/// precedes its `line_start`, and sized the table from the largest `line_end`,
/// which a nonsense line number could blow up.
#[test]
fn rust_insights_survives_an_inverted_function_span() {
    let ir = ir_with_span("inverted", "fn f() {}\n", 9, 1);
    let _ = verum_lumen::rust_insights::analyse(&ir);
}

#[test]
fn rust_insights_survives_a_span_past_the_end_of_the_file() {
    let ir = ir_with_span("past-end", "fn f() {}\n", 1, 65535);
    let _ = verum_lumen::rust_insights::analyse(&ir);
}

#[test]
fn rust_insights_survives_a_zero_based_span() {
    let ir = ir_with_span("zero", "fn f() { x.unwrap(); }\n", 0, 0);
    let _ = verum_lumen::rust_insights::analyse(&ir);
}

/// The other per-file line passes take the same spans from the same IR.
#[test]
fn the_other_line_passes_survive_the_same_spans() {
    for (name, start, end) in [
        ("t-inv", 9u32, 1u32),
        ("t-past", 1, 65535),
        ("t-zero", 0, 0),
    ] {
        let ir = ir_with_span(
            name,
            "fn f(sock: &UdpSocket) {\n    let n = sock.recv_from(&mut buf);\n}\n",
            start,
            end,
        );
        let _ = verum_lumen::transport::analyse(&ir);
        let _ = verum_lumen::crypto_hygiene::analyse(&ir);
        let _ = verum_lumen::taint::analyse(&ir);
        let _ = verum_lumen::security::analyse(&ir, &verum_lumen::SecurityConfig::default());
    }
}
