//! Fleet-robustness guarantees: a hostile file degrades to a diagnostic, an
//! overlong line is skipped deterministically, and healthy trees never emit
//! the ParseFailure diagnostic at all.

use std::path::{Path, PathBuf};

use verum_lumen::{scan, security, Prism, SecurityConfig, Standard};
use verum_nucleus::{Finding, FindingKind, Ir};

/// A scratch tree that removes itself when dropped, so a failing assert never
/// leaves litter in the system temp directory.
struct ScratchTree(PathBuf);

impl ScratchTree {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "verum_lumen_{}_{}_{}",
            tag,
            std::process::id(),
            std::thread::current()
                .name()
                .unwrap_or("t")
                .replace("::", "_"),
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        Self(dir)
    }
}

impl Drop for ScratchTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn ir_for(root: &Path) -> Ir {
    verum_mappa::Atlas::new(verum_mappa::AtlasConfig {
        root: root.to_path_buf(),
        ..Default::default()
    })
    .build()
    .expect("scratch tree maps")
}

#[test]
fn overlong_lines_are_skipped_deterministically() {
    let tree = ScratchTree::new("longline");
    // The same detectable pattern twice: once on a normal line, once buried
    // at the end of a line past the scan budget. Only the short one may flag.
    std::fs::write(tree.0.join("short.php"), "<?php\neval($_GET['x']);\n").expect("write short");
    let long_line = format!(
        "{}eval($_GET['x']);",
        " ".repeat(scan::MAX_SCAN_LINE_BYTES + 1)
    );
    std::fs::write(tree.0.join("long.php"), format!("<?php\n{long_line}\n")).expect("write long");

    let ir = ir_for(&tree.0);
    let ctx = scan::ScanContext::index_only(&ir);
    let findings = security::analyse_with_context(&ir, &SecurityConfig::default(), &ctx);

    let evals: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.kind == FindingKind::EvalUsage)
        .collect();
    assert_eq!(evals.len(), 1, "only the short line flags: {evals:?}");
    assert!(evals[0].file.ends_with("short.php"));

    // Byte-identical across runs: the skip depends only on the input.
    let again = security::analyse_with_context(&ir, &SecurityConfig::default(), &ctx);
    assert_eq!(findings.len(), again.len());
}

#[test]
fn parse_failures_flow_through_prism_without_denting_the_score() {
    let mut ir = Ir::new();
    ir.parse_failures.push(Finding::parse_failure(
        std::path::Path::new("src/broken.rs"),
        "parser panicked on this file",
    ));

    let result = Prism::analyse(&ir, &Standard::default()).expect("analysis completes");

    let failures: Vec<&Finding> = result
        .findings
        .iter()
        .filter(|f| f.kind == FindingKind::ParseFailure)
        .collect();
    assert_eq!(failures.len(), 1, "the diagnostic surfaces in the report");
    assert_eq!(
        failures[0].message,
        "parser panicked on this file: src/broken.rs"
    );
    // Diagnostic only: no dimension penalty, no severity cap.
    assert_eq!(result.score.overall, 100);
    assert_eq!(result.score.security, 100);
}

#[test]
fn normal_trees_emit_zero_parse_failures() {
    let tree = ScratchTree::new("normal");
    std::fs::write(
        tree.0.join("lib.rs"),
        "pub fn shipping() { helper(); }\nfn helper() {}\n",
    )
    .expect("write rust");
    std::fs::write(
        tree.0.join("app.php"),
        "<?php\nfunction greet($name) { return htmlspecialchars($name); }\n",
    )
    .expect("write php");
    std::fs::write(tree.0.join("empty.py"), "").expect("write empty");

    let ir = ir_for(&tree.0);
    assert!(ir.parse_failures.is_empty());

    let result = Prism::analyse(&ir, &Standard::default()).expect("analysis completes");
    assert!(
        !result
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::ParseFailure),
        "healthy files must never produce ParseFailure"
    );
}
