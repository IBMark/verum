//! Line counting and static test-reachability over real fixture trees.
//!
//! The unit tests in `loc` and `reachability` drive the counters directly;
//! these check the numbers that come out of a full parse, which is where a
//! mismatch between the parser's view of a tree and the counter's would show.

use std::path::{Path, PathBuf};

use verum_lumen::{loc, reachability, scoring, Prism, Standard};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .parent()
        .expect("workspace root")
        .join("tests/fixtures")
        .join(name)
}

fn ir_for(name: &str) -> verum_nucleus::Ir {
    let config = verum_mappa::AtlasConfig {
        root: fixture(name),
        ..Default::default()
    };
    verum_mappa::Atlas::new(config)
        .build()
        .unwrap_or_else(|e| panic!("should parse the {name} fixture: {e}"))
}

fn file_loc<'a>(report: &'a loc::LocReport, path: &str) -> &'a loc::FileLoc {
    report
        .files
        .iter()
        .find(|f| f.path == path)
        .unwrap_or_else(|| {
            panic!(
                "{path} should be counted; got {:?}",
                report.files.iter().map(|f| &f.path).collect::<Vec<_>>()
            )
        })
}

#[test]
fn counts_rust_lines_by_bucket() {
    let ir = ir_for("loc_untested");
    let ctx = verum_lumen::scan::ScanContext::build(&ir);
    let report = loc::analyse(&ir, &ctx, Some(&fixture("loc_untested")));

    let lib = file_loc(&report, "src/lib.rs");
    // 2 doc/line comments + a 2-line block, 2 blank lines, 7 lines of code -
    // including the one whose string literal contains `//`.
    assert_eq!(
        (lib.total, lib.code, lib.comment, lib.blank),
        (13, 7, 4, 2),
        "src/lib.rs"
    );
    assert_eq!(lib.language, "Rust");
}

#[test]
fn counts_python_lines_with_docstrings_as_code() {
    let ir = ir_for("loc_untested");
    let ctx = verum_lumen::scan::ScanContext::build(&ir);
    let report = loc::analyse(&ir, &ctx, Some(&fixture("loc_untested")));

    let util = file_loc(&report, "src/util.py");
    assert_eq!(
        (util.total, util.code, util.comment, util.blank),
        (10, 6, 1, 3),
        "the docstring counts as code, the `#` line as a comment"
    );
    assert_eq!(util.language, "Python");
}

#[test]
fn rolls_up_by_language_and_directory() {
    let ir = ir_for("loc_untested");
    let ctx = verum_lumen::scan::ScanContext::build(&ir);
    let report = loc::analyse(&ir, &ctx, Some(&fixture("loc_untested")));

    let languages: Vec<&str> = report.by_language.iter().map(|r| r.key.as_str()).collect();
    assert_eq!(languages, vec!["Python", "Rust"], "sorted by language");

    let directories: Vec<&str> = report.by_directory.iter().map(|r| r.key.as_str()).collect();
    assert_eq!(directories, vec!["src"]);

    let total: u32 = report.files.iter().map(|f| f.total).sum();
    assert_eq!(report.totals.total, total);
    assert_eq!(
        report.totals.code + report.totals.comment + report.totals.blank,
        report.totals.total,
        "every line lands in exactly one bucket"
    );
}

#[test]
fn line_counts_are_repeatable() {
    let ir = ir_for("loc_untested");
    let ctx = verum_lumen::scan::ScanContext::build(&ir);
    let root = fixture("loc_untested");
    assert_eq!(
        loc::analyse(&ir, &ctx, Some(&root)),
        loc::analyse(&ir, &ctx, Some(&root))
    );
}

#[test]
fn a_tree_with_no_tests_reaches_nothing_and_scores_zero() {
    let ir = ir_for("loc_untested");
    let root = fixture("loc_untested");
    let result =
        Prism::analyse_at(&ir, &Standard::default(), Some(&root)).expect("analyse the fixture");

    assert_eq!(result.test_reachability.test_roots, 0, "no test suite");
    assert_eq!(result.test_reachability.reachable, 0);
    assert!(result.test_reachability.functions > 0, "there is code here");
    assert_eq!(
        result.score.test_coverage, 0,
        "the dimension used to report 100 for exactly this tree"
    );
    assert!(
        result
            .test_reachability
            .files_without_reachable_functions
            .contains(&"src/lib.rs".to_string()),
        "the file no test reaches is named: {:?}",
        result.test_reachability.files_without_reachable_functions
    );
}

#[test]
fn a_helper_called_from_a_test_file_is_reachable() {
    let ir = ir_for("loc_tested");
    let report = reachability::analyse(&ir, Some(&fixture("loc_tested")));

    assert!(report.test_roots > 0, "the tests/ tree seeds the walk");
    assert!(
        report.reachable > 0,
        "`parse_header` is called from tests/parse_test.rs: {report:?}"
    );
    assert!(
        report.percent > 0.0 && report.percent < 100.0,
        "one of two functions is reached, got {}",
        report.percent
    );
    assert!(
        scoring::reachability_dimension(&report) > 0,
        "a suite that reaches code scores above zero"
    );
}

#[test]
fn test_files_are_outside_the_denominator() {
    let ir = ir_for("loc_tested");
    let report = reachability::analyse(&ir, Some(&fixture("loc_tested")));
    assert!(
        !report.files.iter().any(|f| f.path.starts_with("tests/")),
        "a test cannot test itself: {:?}",
        report.files.iter().map(|f| &f.path).collect::<Vec<_>>()
    );
}
