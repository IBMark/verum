#[test]
fn test_parse_rust_verum_nucleus() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let workspace_root = std::path::PathBuf::from(&manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();

    let core_src = workspace_root.join("crates/verum-nucleus/src");

    let config = verum_mappa::AtlasConfig {
        root: core_src,
        language: verum_nucleus::Language::Rust,
        ..Default::default()
    };
    let atlas = verum_mappa::Atlas::new(config);
    let ir = atlas.build().expect("should parse Rust source");

    assert!(
        ir.symbol_count() > 0,
        "should extract symbols from verum-nucleus"
    );

    let has_symbol = ir.symbols.values().any(|s| s.name == "Symbol");
    assert!(has_symbol, "should find Symbol struct");

    let has_ir = ir.symbols.values().any(|s| s.name == "Ir");
    assert!(has_ir, "should find Ir struct");

    let has_score = ir.symbols.values().any(|s| s.name == "Score");
    assert!(has_score, "should find Score struct");

    let has_language = ir.symbols.values().any(|s| s.name == "Language");
    assert!(has_language, "should find Language enum");

    let has_severity = ir.symbols.values().any(|s| s.name == "Severity");
    assert!(has_severity, "should find Severity enum");

    let has_method = ir.symbols.values().any(|s| {
        matches!(
            s.kind,
            verum_nucleus::SymbolKind::Method | verum_nucleus::SymbolKind::StaticMethod
        )
    });
    assert!(has_method, "should find methods in impl blocks");

    assert!(!ir.calls.is_empty(), "should find calls");

    assert!(!ir.files.is_empty(), "should have file info");

    for sym in ir.symbols.values() {
        assert_eq!(
            sym.language,
            verum_nucleus::Language::Rust,
            "all symbols should be Rust"
        );
    }

    println!("Rust parse of verum-nucleus:");
    println!("  Files:   {}", ir.files.len());
    println!("  Lines:   {}", ir.metadata.total_lines);
    println!("  Symbols: {}", ir.symbol_count());
    println!("  Calls:   {}", ir.calls.len());

    let mut symbols: Vec<_> = ir.symbols.values().collect();
    symbols.sort_by_key(|s| (&s.file, s.line_start));
    for sym in symbols.iter().take(20) {
        println!(
            "    {:?} {} ({}) @ {}:{}",
            sym.kind,
            sym.name,
            sym.fully_qualified,
            sym.file.display(),
            sym.line_start
        );
    }
}
