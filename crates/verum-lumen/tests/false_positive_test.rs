//! Regression tests for the false-positive filters: auxiliary-path exclusion,
//! Go framework hooks in dead-code analysis, and Go naming.

use std::collections::HashSet;

use verum_lumen::{is_auxiliary_path, is_test_path, Standard};
use verum_nucleus::{FindingKind, Ir, Language};

fn go_hooks_ir() -> Ir {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let fixture = std::path::Path::new(&manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/go_hooks");
    let config = verum_mappa::AtlasConfig {
        root: fixture,
        language: Language::Go,
        ..Default::default()
    };
    verum_mappa::Atlas::new(config)
        .build()
        .expect("parse go fixture")
}

#[test]
fn auxiliary_paths_are_classified() {
    for aux in [
        "app/test/foo.js",
        "src/__tests__/foo.ts",
        "pkg/examples/demo.go",
        "vendor/lib/x.php",
        "web/node_modules/y.js",
        "a/b/foo_test.go",
        "a/b/foo.spec.ts",
        "gen/api.pb.go",
        "assets/app.min.js",
    ] {
        assert!(is_auxiliary_path(aux), "{aux} should be auxiliary");
    }
    for real in [
        "src/lib.rs",
        "app/Http/Controllers/UserController.php",
        "internal/server/handler.go",
        // fixtures are deliberate analysis targets, never auxiliary.
        "tests/fixtures/php_security/vulnerable.php",
    ] {
        assert!(!is_auxiliary_path(real), "{real} should not be auxiliary");
    }
}

#[test]
fn test_paths_are_the_narrow_subset_of_auxiliary_paths() {
    // Seeds the reachability walk: a false positive here would credit a
    // vendored or example file as if it were a test.
    for test in [
        "tests/suite.rs",
        "src/__tests__/foo.ts",
        "app/spec/user_spec.rb",
        "a/b/foo_test.go",
        "a/b/foo.spec.ts",
        "pkg/test_helpers.py",
        "conftest.py",
    ] {
        assert!(is_test_path(test), "{test} should be a test path");
    }
    for not_test in [
        "src/lib.rs",
        // Auxiliary, but not a test suite.
        "pkg/examples/demo.go",
        "vendor/lib/x.php",
        "web/node_modules/y.js",
        "benches/throughput.rs",
        // `latest_*` must not trip pytest's `test_` prefix.
        "src/latest_build.py",
        // Verum's own fixture trees are analysis targets, not a suite.
        "tests/fixtures/php_security/vulnerable.php",
    ] {
        assert!(
            !is_test_path(not_test),
            "{not_test} should not be a test path"
        );
    }
    // Every test path that is not a deliberate fixture target is also
    // auxiliary - the two filters must not disagree about what ships.
    for test in ["tests/suite.rs", "src/__tests__/foo.ts", "a/b/foo_test.go"] {
        assert!(is_auxiliary_path(test), "{test} should also be auxiliary");
    }
}

#[test]
fn go_init_and_interface_methods_are_not_dead() {
    let ir = go_hooks_ir();
    let dead = verum_lumen::dead_code::analyse(&ir, &Standard::default().dead_code);

    let dead_names: HashSet<String> = dead
        .iter()
        .filter_map(|f| f.symbol)
        .filter_map(|id| ir.symbols.get(&id).map(|s| s.name.clone()))
        .collect();

    // Control: a genuinely uncalled, non-hook function is still flagged.
    assert!(
        dead_names.contains("reallyDead"),
        "an uncalled plain function should be dead, got {dead_names:?}"
    );
    // Framework hooks must never be flagged, despite having no direct caller.
    for hook in ["init", "String", "MarshalJSON"] {
        assert!(
            !dead_names.contains(hook),
            "Go framework hook `{hook}` must not be flagged dead, got {dead_names:?}"
        );
    }
}

#[test]
fn go_naming_is_not_flagged() {
    let ir = go_hooks_ir();
    let findings = verum_lumen::naming::analyse(&ir, &verum_lumen::NamingConfig::default());
    let violations: Vec<&String> = findings
        .iter()
        .filter(|f| f.kind == FindingKind::ConventionViolation)
        .map(|f| &f.message)
        .collect();
    assert!(
        violations.is_empty(),
        "Go identifiers should not raise naming violations, got {violations:?}"
    );
}
