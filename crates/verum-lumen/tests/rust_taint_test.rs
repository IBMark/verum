//! Rust taint coverage: untrusted input (env, HTTP extractors, socket reads)
//! reaching command / SQL / filesystem sinks.

use verum_nucleus::FindingKind;

fn audit(src: &str) -> Vec<verum_nucleus::Finding> {
    audit_named("lib.rs", src)
}

/// Build + analyse a single Rust file written at `rel_path` (relative to a
/// fresh temp root), so tests can exercise path-based filtering (`build.rs`,
/// `tests/...`).
fn audit_named(rel_path: &str, src: &str) -> Vec<verum_nucleus::Finding> {
    let dir = std::env::temp_dir().join(format!(
        "verum-rust-taint-{}-{}-{}",
        std::process::id(),
        rel_path.replace(['/', '\\'], "_"),
        src.len()
    ));
    let target = dir.join(rel_path);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&target, src).unwrap();

    let config = verum_mappa::AtlasConfig {
        root: dir.clone(),
        language: verum_nucleus::Language::Rust,
        ..Default::default()
    };
    let ir = verum_mappa::Atlas::new(config).build().expect("parse");
    let result =
        verum_lumen::Prism::analyse(&ir, &verum_lumen::Standard::default()).expect("analyse");
    std::fs::remove_dir_all(&dir).ok();
    result.findings
}

#[test]
fn env_var_to_command_is_not_flagged() {
    // Environment variables are trusted build/deploy config, not attacker
    // input. `env::var -> Command::new` on its own must not produce an
    // EvalUsage / command-execution finding (real-world false positive:
    // serde's build.rs spawning `$RUSTC`).
    let findings = audit(
        "fn run() {\n\
             let target = std::env::var(\"TARGET\").unwrap();\n\
             std::process::Command::new(\"ping\").arg(target).status();\n\
         }\n",
    );
    assert!(
        !findings.iter().any(|f| f.kind == FindingKind::EvalUsage),
        "env var alone must not flag command execution: {:#?}",
        findings
            .iter()
            .map(|f| (&f.kind, &f.message))
            .collect::<Vec<_>>()
    );
}

#[test]
fn env_var_os_to_command_in_build_script_is_not_flagged() {
    // serde/build.rs shape: read $RUSTC from the environment and spawn it.
    // A build script is not runtime attack surface - zero findings.
    let findings = audit_named(
        "build.rs",
        "use std::process::Command;\n\
         fn main() {\n\
             let rustc = std::env::var_os(\"RUSTC\").unwrap();\n\
             Command::new(rustc).arg(\"--version\").output().unwrap();\n\
         }\n",
    );
    assert!(
        !findings.iter().any(|f| f.kind == FindingKind::EvalUsage),
        "build.rs Command::new must not flag: {:#?}",
        findings
            .iter()
            .map(|f| (&f.kind, &f.message))
            .collect::<Vec<_>>()
    );
}

#[test]
fn command_in_test_harness_is_not_flagged() {
    // ripgrep/tests/util.rs shape: a test helper spawning the built binary.
    // Test code is excluded from taint sink reporting.
    let findings = audit_named(
        "tests/util.rs",
        "use std::process::Command;\n\
         fn run(bin: String) {\n\
             let arg = std::env::args().nth(1).unwrap();\n\
             Command::new(bin).arg(arg).output().unwrap();\n\
         }\n",
    );
    assert!(
        !findings.iter().any(|f| f.kind == FindingKind::EvalUsage),
        "test-harness Command::new must not flag: {:#?}",
        findings
            .iter()
            .map(|f| (&f.kind, &f.message))
            .collect::<Vec<_>>()
    );
}

#[test]
fn php_taint_regression_still_fires() {
    // PHP taint behaviour must be entirely unaffected by the Rust-only
    // filtering: unsanitized $_GET into a raw SQL query is still Critical.
    let dir = std::env::temp_dir().join(format!("verum-php-taint-regr-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("q.php"),
        "<?php\n\
         function get() {\n\
         \x20   $id = $_GET['id'];\n\
         \x20   return DB::raw(\"SELECT * FROM users WHERE id = \" . $id);\n\
         }\n",
    )
    .unwrap();
    let config = verum_mappa::AtlasConfig {
        root: dir.clone(),
        language: verum_nucleus::Language::Php,
        ..Default::default()
    };
    let ir = verum_mappa::Atlas::new(config).build().expect("parse");
    let findings = verum_lumen::Prism::analyse(&ir, &verum_lumen::Standard::default())
        .expect("analyse")
        .findings;
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        findings.iter().any(|f| f.kind == FindingKind::SqlInjection),
        "PHP $_GET -> DB::raw must still flag SQL injection: {:#?}",
        findings
            .iter()
            .map(|f| (&f.kind, &f.message))
            .collect::<Vec<_>>()
    );
}

#[test]
fn extractor_to_fs_read_is_path_traversal() {
    let findings = audit(
        "async fn get_file(Path(name): Path<String>) -> String {\n\
             std::fs::read_to_string(format!(\"./files/{}\", name)).unwrap()\n\
         }\n",
    );
    assert!(
        findings
            .iter()
            .any(|f| f.kind == FindingKind::PathTraversal),
        "extractor -> fs::read_to_string should flag path traversal: {:#?}",
        findings
            .iter()
            .map(|f| (&f.kind, &f.message))
            .collect::<Vec<_>>()
    );
}

#[test]
fn parse_sanitizer_clears_taint() {
    let findings = audit(
        "async fn get_file(Path(name): Path<String>) -> String {\n\
             let id = name.parse::<u32>().unwrap();\n\
             std::fs::read_to_string(format!(\"./files/{}\", id)).unwrap()\n\
         }\n",
    );
    assert!(
        !findings
            .iter()
            .any(|f| f.kind == FindingKind::PathTraversal),
        "typed parse should clear taint: {:#?}",
        findings
            .iter()
            .map(|f| (&f.kind, f.line_start, &f.message))
            .collect::<Vec<_>>()
    );
}

#[test]
fn socket_read_buffer_to_sql_is_flagged() {
    let findings = audit(
        "async fn serve(sock: &UdpSocket) {\n\
             let mut buf = vec![0u8; 512];\n\
             sock.recv_from(&mut buf).await.unwrap();\n\
             let q = String::from_utf8_lossy(&buf);\n\
             sqlx::query(&format!(\"SELECT * FROM t WHERE k = {}\", q));\n\
         }\n",
    );
    assert!(
        findings.iter().any(|f| f.kind == FindingKind::SqlInjection),
        "socket buffer -> sqlx::query should flag SQL injection: {:#?}",
        findings
            .iter()
            .map(|f| (&f.kind, &f.message))
            .collect::<Vec<_>>()
    );
}

#[test]
fn untainted_rust_code_is_quiet() {
    let findings = audit(
        "fn run() {\n\
             let config = std::fs::read_to_string(\"config.toml\").unwrap();\n\
             std::process::Command::new(\"ls\").status();\n\
         }\n",
    );
    assert!(
        !findings.iter().any(|f| matches!(
            f.kind,
            FindingKind::EvalUsage | FindingKind::PathTraversal | FindingKind::SqlInjection
        )),
        "constant paths and args must not flag: {:#?}",
        findings
            .iter()
            .map(|f| (&f.kind, &f.message))
            .collect::<Vec<_>>()
    );
}
