#[test]
fn test_parse_simple_php() {
    let config = verum_mappa::AtlasConfig {
        root: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/php_simple"),
        ..Default::default()
    };
    let atlas = verum_mappa::Atlas::new(config);
    let ir = atlas.build().expect("should parse");

    assert!(ir.symbol_count() > 0, "should extract symbols");

    let has_helper = ir.symbols.values().any(|s| s.name == "UserHelper");
    assert!(has_helper, "should find UserHelper class");

    let has_get_user = ir.symbols.values().any(|s| s.name == "getUserById");
    assert!(has_get_user, "should find getUserById");

    let has_fetch_user = ir.symbols.values().any(|s| s.name == "fetchUser");
    assert!(has_fetch_user, "should find fetchUser");

    let has_calc = ir.symbols.values().any(|s| s.name == "calculateTotal");
    assert!(has_calc, "should find calculateTotal");

    assert!(!ir.files.is_empty(), "should have file info");

    println!("Symbols found: {}", ir.symbol_count());
    for sym in ir.symbols.values() {
        println!(
            "  {} ({:?}) at {}:{}-{}",
            sym.name,
            sym.kind,
            sym.file.display(),
            sym.line_start,
            sym.line_end
        );
    }
    println!("Calls found: {}", ir.calls.len());
    println!("Files: {}", ir.files.len());
}
