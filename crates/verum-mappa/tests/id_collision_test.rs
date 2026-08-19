//! Regression tests for symbol-ID collisions.
//!
//! Symbol IDs must be namespaced so that (a) multiple inline `<script>`
//! fragments in one HTML file and (b) identically named infra resources in
//! different files never allocate the same SymbolId - a collision makes
//! `HashMap::insert` (directly or via `Ir::merge`) silently drop symbols.

use std::path::PathBuf;

use verum_nucleus::Ir;

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("verum-idcol-{}-{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn html_two_script_blocks_keep_both_symbols() {
    let html = "\
<!doctype html>
<body>
<script>
function alpha() { return 1; }
</script>
<p>between</p>
<script>
function beta() { return 2; }
</script>
</body>";

    let dir = temp_dir("html");
    let file = dir.join("index.html");
    std::fs::write(&file, html).unwrap();

    let ir = verum_mappa::html::parse_file(&file).expect("should parse HTML");
    std::fs::remove_dir_all(&dir).ok();

    let names: Vec<&str> = ir.symbols.values().map(|s| s.name.as_str()).collect();
    assert!(
        names.contains(&"alpha"),
        "alpha() from first <script> missing; got {names:?}"
    );
    assert!(
        names.contains(&"beta"),
        "beta() from second <script> missing (fragment ID collision); got {names:?}"
    );
    assert_eq!(
        ir.symbol_count(),
        2,
        "expected exactly alpha + beta; got {names:?}"
    );
}

#[test]
fn html_fragment_ids_are_deterministic() {
    let html = "<script>\nfunction alpha() {}\n</script>\n<script>\nfunction beta() {}\n</script>";
    let dir = temp_dir("html-det");
    let file = dir.join("page.html");
    std::fs::write(&file, html).unwrap();

    let ir1 = verum_mappa::html::parse_file(&file).expect("parse 1");
    let ir2 = verum_mappa::html::parse_file(&file).expect("parse 2");
    std::fs::remove_dir_all(&dir).ok();

    let mut ids1: Vec<u64> = ir1.symbols.keys().map(|id| id.0).collect();
    let mut ids2: Vec<u64> = ir2.symbols.keys().map(|id| id.0).collect();
    ids1.sort_unstable();
    ids2.sort_unstable();
    assert_eq!(ids1, ids2, "symbol IDs must be identical across runs");
}

#[test]
fn two_single_stage_dockerfiles_survive_merge() {
    let dir = temp_dir("docker");
    let file_a = dir.join("Dockerfile.api");
    let file_b = dir.join("Dockerfile.worker");
    std::fs::write(&file_a, "FROM node:20.11-alpine\nRUN npm ci\nUSER node\n").unwrap();
    std::fs::write(
        &file_b,
        "FROM python:3.12-slim\nRUN pip install -r reqs.txt\nUSER app\n",
    )
    .unwrap();

    let ir_a = verum_mappa::dockerfile::parse_file(&file_a).expect("parse Dockerfile.api");
    let ir_b = verum_mappa::dockerfile::parse_file(&file_b).expect("parse Dockerfile.worker");
    std::fs::remove_dir_all(&dir).ok();

    let count_a = ir_a.symbol_count();
    let count_b = ir_b.symbol_count();
    assert!(count_a > 0, "Dockerfile.api should produce a stage symbol");
    assert!(
        count_b > 0,
        "Dockerfile.worker should produce a stage symbol"
    );

    let mut merged = Ir::new();
    merged.merge(ir_a);
    merged.merge(ir_b);

    assert_eq!(
        merged.symbol_count(),
        count_a + count_b,
        "merged symbol count must equal the sum - unnamed stages ('stage-1') \
         from different Dockerfiles must not share SymbolIds"
    );
}

#[test]
fn same_terraform_resource_name_in_two_files_survives_merge() {
    let tf = "\
resource \"aws_s3_bucket\" \"logs\" {
  bucket = \"my-logs\"
}
";
    let dir = temp_dir("tf");
    let file_a = dir.join("prod.tf");
    let file_b = dir.join("staging.tf");
    std::fs::write(&file_a, tf).unwrap();
    std::fs::write(&file_b, tf).unwrap();

    let ir_a = verum_mappa::terraform::parse_file(&file_a).expect("parse prod.tf");
    let ir_b = verum_mappa::terraform::parse_file(&file_b).expect("parse staging.tf");
    std::fs::remove_dir_all(&dir).ok();

    let logs_a = ir_a.symbols.values().filter(|s| s.name == "logs").count();
    let logs_b = ir_b.symbols.values().filter(|s| s.name == "logs").count();
    assert_eq!(logs_a, 1, "prod.tf should define the logs bucket symbol");
    assert_eq!(logs_b, 1, "staging.tf should define the logs bucket symbol");

    let count_a = ir_a.symbol_count();
    let count_b = ir_b.symbol_count();

    let mut merged = Ir::new();
    merged.merge(ir_a);
    merged.merge(ir_b);

    assert_eq!(
        merged.symbol_count(),
        count_a + count_b,
        "identically named resources in different .tf files must keep distinct SymbolIds"
    );
    let logs_total = merged.symbols.values().filter(|s| s.name == "logs").count();
    assert_eq!(
        logs_total, 2,
        "both aws_s3_bucket.logs symbols must survive the merge"
    );
}
