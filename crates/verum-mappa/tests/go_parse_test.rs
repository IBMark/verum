#[test]
fn test_parse_simple_go() {
    let config = verum_mappa::AtlasConfig {
        root: "../../tests/fixtures/go_simple".into(),
        language: verum_nucleus::Language::Go,
        ..Default::default()
    };
    let atlas = verum_mappa::Atlas::new(config);
    let ir = atlas.build().expect("should parse");

    assert!(ir.symbol_count() > 0, "should extract symbols");

    let has_struct = ir
        .symbols
        .values()
        .any(|s| s.name == "UserService" && s.kind == verum_nucleus::SymbolKind::Class);
    assert!(has_struct, "should find UserService struct");

    let has_get_user = ir
        .symbols
        .values()
        .any(|s| s.name == "GetUserByID" && s.kind == verum_nucleus::SymbolKind::Method);
    assert!(has_get_user, "should find GetUserByID method");

    let has_fetch = ir
        .symbols
        .values()
        .any(|s| s.name == "FetchUser" && s.kind == verum_nucleus::SymbolKind::Method);
    assert!(has_fetch, "should find FetchUser method");

    let legacy = ir.symbols.values().find(|s| s.name == "formatLegacyDate");
    assert!(legacy.is_some(), "should find formatLegacyDate");
    assert_eq!(
        legacy.unwrap().visibility,
        verum_nucleus::Visibility::Private,
        "formatLegacyDate should be Private (lowercase)"
    );

    let calc = ir.symbols.values().find(|s| s.name == "CalculateTotal");
    assert!(calc.is_some(), "should find CalculateTotal");
    assert_eq!(
        calc.unwrap().visibility,
        verum_nucleus::Visibility::Public,
        "CalculateTotal should be Public (uppercase)"
    );

    let helper = ir.symbols.values().find(|s| s.name == "legacyHelper");
    assert!(helper.is_some(), "should find legacyHelper");
    assert_eq!(
        helper.unwrap().visibility,
        verum_nucleus::Visibility::Private,
        "legacyHelper should be Private"
    );

    let has_main = ir
        .symbols
        .values()
        .any(|s| s.name == "main" && s.kind == verum_nucleus::SymbolKind::Function);
    assert!(has_main, "should find main function");

    let user_service_id = ir
        .symbols
        .iter()
        .find(|(_, s)| s.name == "UserService")
        .map(|(id, _)| *id);
    assert!(user_service_id.is_some(), "should have UserService id");

    let get_user = ir
        .symbols
        .values()
        .find(|s| s.name == "GetUserByID")
        .unwrap();
    assert_eq!(
        get_user.parent, user_service_id,
        "GetUserByID should have UserService as parent"
    );

    assert!(!ir.files.is_empty(), "should have file info");

    assert!(!ir.calls.is_empty(), "should have extracted calls");

    assert_eq!(
        get_user.param_count, 1,
        "GetUserByID should have 1 param, got {}",
        get_user.param_count
    );

    println!("Symbols found: {}", ir.symbol_count());
    for sym in ir.symbols.values() {
        println!(
            "  {} {:?} {:?} (L{}-L{}) parent={:?}",
            sym.name, sym.kind, sym.visibility, sym.line_start, sym.line_end, sym.parent
        );
    }
    println!("Calls found: {}", ir.calls.len());
    for call in &ir.calls {
        println!("  {:?} -> {:?} (L{})", call.caller, call.callee, call.line);
    }
    println!("Files: {}", ir.files.len());
}
