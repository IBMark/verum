#[test]
fn test_parse_simple_js() {
    let config = verum_mappa::AtlasConfig {
        root: "../../tests/fixtures/js_simple".into(),
        language: verum_nucleus::Language::JavaScript,
        ..Default::default()
    };
    let atlas = verum_mappa::Atlas::new(config);
    let ir = atlas.build().expect("should parse");

    assert!(ir.symbol_count() > 0, "should extract symbols");

    let has_service = ir.symbols.values().any(|s| s.name == "UserService");
    assert!(has_service, "should find UserService class");

    let has_get_user = ir.symbols.values().any(|s| s.name == "getUserById");
    assert!(has_get_user, "should find getUserById method");

    let has_fetch_user = ir.symbols.values().any(|s| s.name == "fetchUser");
    assert!(has_fetch_user, "should find fetchUser method");

    let has_calc = ir.symbols.values().any(|s| s.name == "calculateTotal");
    assert!(has_calc, "should find calculateTotal function");

    let has_legacy = ir.symbols.values().any(|s| s.name == "legacyHelper");
    assert!(has_legacy, "should find legacyHelper function");

    let has_format = ir.symbols.values().any(|s| s.name == "formatDate");
    assert!(has_format, "should find formatDate method");

    assert!(!ir.files.is_empty(), "should have file info");

    assert!(!ir.calls.is_empty(), "should have found calls");

    println!("Symbols found: {}", ir.symbol_count());
    for sym in ir.symbols.values() {
        println!(
            "  {:?} {} ({}:{}-{})",
            sym.kind,
            sym.name,
            sym.file.display(),
            sym.line_start,
            sym.line_end
        );
    }
    println!("Calls found: {}", ir.calls.len());
    for call in &ir.calls {
        println!(
            "  {:?} -> {:?} (line {})",
            call.caller, call.callee, call.line
        );
    }
    println!("Files: {}", ir.files.len());
}
