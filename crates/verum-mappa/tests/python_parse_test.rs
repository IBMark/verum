#[test]
fn test_parse_simple_python() {
    let config = verum_mappa::AtlasConfig {
        root: "../../tests/fixtures/python_simple".into(),
        language: verum_nucleus::Language::Python,
        ..Default::default()
    };
    let atlas = verum_mappa::Atlas::new(config);
    let ir = atlas.build().expect("should parse");

    assert!(ir.symbol_count() > 0, "should extract symbols");

    let has_class = ir.symbols.values().any(|s| s.name == "UserService");
    assert!(has_class, "should find UserService class");

    let has_get_user = ir.symbols.values().any(|s| s.name == "get_user_by_id");
    assert!(has_get_user, "should find get_user_by_id method");

    let has_fetch = ir.symbols.values().any(|s| s.name == "fetch_user");
    assert!(has_fetch, "should find fetch_user method");

    let has_init = ir.symbols.values().any(|s| s.name == "__init__");
    assert!(has_init, "should find __init__ method");

    let legacy = ir
        .symbols
        .values()
        .find(|s| s.name == "_format_legacy_date");
    assert!(legacy.is_some(), "should find _format_legacy_date");
    assert_eq!(
        legacy.unwrap().visibility,
        verum_nucleus::Visibility::Private,
        "_format_legacy_date should be Private"
    );

    let has_calc = ir.symbols.values().any(|s| s.name == "calculate_total");
    assert!(has_calc, "should find calculate_total function");

    let has_legacy = ir.symbols.values().any(|s| s.name == "legacy_helper");
    assert!(has_legacy, "should find legacy_helper function");

    assert!(!ir.files.is_empty(), "should have file info");

    let init_sym = ir.symbols.values().find(|s| s.name == "__init__").unwrap();
    assert_eq!(
        init_sym.param_count, 1,
        "__init__ should have 1 param (db), got {}",
        init_sym.param_count
    );

    assert!(!ir.calls.is_empty(), "should have extracted calls");

    println!("Symbols found: {}", ir.symbol_count());
    for sym in ir.symbols.values() {
        println!(
            "  {} {:?} {:?} (L{}-L{})",
            sym.name, sym.kind, sym.visibility, sym.line_start, sym.line_end
        );
    }
    println!("Calls found: {}", ir.calls.len());
    println!("Files: {}", ir.files.len());
}
