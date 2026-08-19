use std::fs;
use std::path::PathBuf;

use verum_faber::{Forge, ForgeConfig};
use verum_lumen::{Prism, Standard};
use verum_mappa::{Atlas, AtlasConfig};
use verum_nucleus::{FindingKind, Language};

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Copy the fixture into a temp dir as helpers.php - atlas treats index.php
/// as an entry point, which would make every symbol reachable.
fn create_test_fixture() -> tempfile::TempDir {
    let src = workspace_root().join("tests/fixtures/php_simple/index.php");
    let tmp = tempfile::tempdir().expect("create temp dir");

    let dest = tmp.path().join("helpers.php");
    fs::copy(&src, dest).expect("copy fixture file");

    tmp
}

#[test]
fn test_forge_dry_run_identifies_dead_code() {
    let tmp = create_test_fixture();

    let config = AtlasConfig {
        root: tmp.path().to_path_buf(),
        language: Language::Php,
        ..Default::default()
    };
    let atlas = Atlas::new(config);
    let ir = atlas.build().expect("should parse");

    let standard = Standard::default();
    let result = Prism::analyse(&ir, &standard).expect("should analyse");

    let dead_findings: Vec<_> = result
        .auto_fixable
        .iter()
        .filter(|f| matches!(f.kind, FindingKind::DeadFunction | FindingKind::DeadClass))
        .collect();

    assert!(
        !dead_findings.is_empty(),
        "should find dead code to auto-fix, got {} total findings",
        result.findings.len()
    );

    let forge = Forge::new(ForgeConfig {
        auto_fix_threshold: 0.85,
        dry_run: true,
    });

    let forge_result = forge
        .execute_findings(&result.auto_fixable, &ir)
        .expect("forge should succeed");

    assert!(
        forge_result.lines_removed > 0,
        "dry run should report lines that would be removed, got {:?}",
        forge_result
    );

    let source = fs::read_to_string(tmp.path().join("helpers.php")).expect("read fixture");
    assert!(
        source.contains("formatLegacyDate"),
        "original file should be unchanged in dry run"
    );
    assert!(
        source.contains("legacyFormat"),
        "original file should be unchanged in dry run"
    );
}

#[test]
fn test_forge_removes_dead_code_on_copy() {
    let tmp = create_test_fixture();

    let config = AtlasConfig {
        root: tmp.path().to_path_buf(),
        language: Language::Php,
        ..Default::default()
    };

    let atlas = Atlas::new(config);
    let ir = atlas.build().expect("should parse");

    let standard = Standard::default();
    let result = Prism::analyse(&ir, &standard).expect("should analyse");

    let forge = Forge::new(ForgeConfig {
        auto_fix_threshold: 0.85,
        dry_run: false,
    });

    let forge_result = forge
        .execute_findings(&result.auto_fixable, &ir)
        .expect("forge should succeed");

    assert!(forge_result.symbols_removed > 0, "should remove symbols");
    assert!(forge_result.lines_removed > 0, "should remove lines");

    // The file may have been deleted outright if everything in it was dead
    let file_path = tmp.path().join("helpers.php");
    if file_path.exists() {
        let modified = fs::read_to_string(&file_path).expect("read modified file");
        println!("Modified file:\n{}", modified);
    } else {
        println!("File was fully deleted (all code was dead)");
    }

    println!("Forge result: {:?}", forge_result);
}

#[test]
fn test_is_safe_to_auto_delete() {
    use verum_nucleus::*;

    let make_symbol = |name: &str, is_entry: bool, file: &str| Symbol {
        id: SymbolId(1),
        name: name.to_string(),
        fully_qualified: name.to_string(),
        kind: SymbolKind::Function,
        visibility: Visibility::Public,
        file: PathBuf::from(file),
        line_start: 1,
        line_end: 5,
        col_start: 0,
        col_end: 0,
        language: Language::Php,
        parent: None,
        hash: 0,
        normalized_hash: 0,
        flow_hash: 0,
        param_count: 0,
        is_entry_point: is_entry,
        doc_comment: None,
    };

    let ir = Ir::new();

    // Normal function: safe
    let sym = make_symbol("myFunc", false, "src/helper.php");
    assert!(verum_faber::dead_code::is_safe_to_auto_delete(&sym, &ir));

    // Magic method: not safe
    let sym = make_symbol("__construct", false, "src/helper.php");
    assert!(!verum_faber::dead_code::is_safe_to_auto_delete(&sym, &ir));

    // Entry point: not safe
    let sym = make_symbol("myFunc", true, "src/helper.php");
    assert!(!verum_faber::dead_code::is_safe_to_auto_delete(&sym, &ir));

    // Vendor file: not safe
    let sym = make_symbol("myFunc", false, "vendor/package/src/file.php");
    assert!(!verum_faber::dead_code::is_safe_to_auto_delete(&sym, &ir));

    // Framework methods: not safe
    for name in &["boot", "register", "handle", "setUp", "tearDown"] {
        let sym = make_symbol(name, false, "src/file.php");
        assert!(
            !verum_faber::dead_code::is_safe_to_auto_delete(&sym, &ir),
            "{} should not be auto-deletable",
            name
        );
    }
}
