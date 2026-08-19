//! Precision regressions for security, rbac, and taint passes:
//! weak-crypto allowlist contexts, comment-line suppression on the forbid
//! path, parameterised group auth middleware, and compound-assignment taint.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use verum_lumen::SecurityConfig;
use verum_nucleus::{FindingKind, HttpMethod, Ir, Route, Severity};

/// Tests run in parallel threads sharing one pid, so a per-call sequence
/// number keeps every temp dir unique even if two tests pass the same tag.
static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Parse a PHP snippet with Atlas into an IR rooted at a unique temp dir.
fn php_ir(tag: &str, file_name: &str, src: &str) -> (Ir, PathBuf) {
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "verum-precision-{}-{}-{seq}",
        std::process::id(),
        tag
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(file_name), src).unwrap();

    let config = verum_mappa::AtlasConfig {
        root: dir.clone(),
        language: verum_nucleus::Language::Php,
        ..Default::default()
    };
    let ir = verum_mappa::Atlas::new(config).build().expect("parse");
    (ir, dir)
}

fn md5_forbid_config_with_allowlist() -> SecurityConfig {
    let mut allowlist = HashMap::new();
    allowlist.insert(
        "md5".to_string(),
        HashSet::from([
            "cache_key".to_string(),
            "etag".to_string(),
            "gravatar".to_string(),
        ]),
    );
    SecurityConfig {
        forbid_weak_crypto: vec!["md5".to_string(), "sha1".to_string()],
        weak_crypto_allowlist: allowlist,
    }
}

// security.rs - weak_crypto_allowlist + comment suppression on forbid path
#[test]
fn md5_in_allowlisted_context_is_not_flagged() {
    let (ir, dir) = php_ir(
        "sec-allow",
        "etag.php",
        "<?php\n\
         $etag = md5($content);\n",
    );
    let findings = verum_lumen::security::analyse(&ir, &md5_forbid_config_with_allowlist());
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        !findings.iter().any(|f| f.kind == FindingKind::WeakCrypto),
        "md5 in an allowlisted (etag) context must be skipped: {:#?}",
        findings
            .iter()
            .map(|f| (&f.kind, &f.message))
            .collect::<Vec<_>>()
    );
}

#[test]
fn md5_in_comment_with_forbid_list_is_not_flagged() {
    let (ir, dir) = php_ir(
        "sec-comment",
        "todo.php",
        "<?php\n\
         // TODO: replace md5($password) with password_hash()\n",
    );
    let findings = verum_lumen::security::analyse(&ir, &md5_forbid_config_with_allowlist());
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        !findings.iter().any(|f| f.kind == FindingKind::WeakCrypto),
        "comment-only md5 must never flag even on the forbid list: {:#?}",
        findings
            .iter()
            .map(|f| (&f.kind, &f.message))
            .collect::<Vec<_>>()
    );
}

#[test]
fn md5_live_code_non_allowlisted_is_critical() {
    let (ir, dir) = php_ir(
        "sec-live",
        "sig.php",
        "<?php\n\
         $signature = md5($password . $salt);\n",
    );
    let findings = verum_lumen::security::analyse(&ir, &md5_forbid_config_with_allowlist());
    std::fs::remove_dir_all(&dir).ok();
    let weak: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == FindingKind::WeakCrypto)
        .collect();
    assert_eq!(
        weak.len(),
        1,
        "live non-allowlisted md5 must flag exactly once: {:#?}",
        findings
            .iter()
            .map(|f| (&f.kind, &f.message))
            .collect::<Vec<_>>()
    );
    assert_eq!(weak[0].severity, Severity::Critical);
    assert!((weak[0].confidence - 0.95).abs() < 1e-6);
}

// rbac.rs - parameterised group middleware + auth.basic / auth.session
fn route(file: &Path, line: u32, path: &str, middleware: Vec<String>) -> Route {
    Route {
        method: HttpMethod::Get,
        path: path.to_string(),
        controller: None,
        middleware,
        file: file.to_path_buf(),
        line,
    }
}

/// Write a routes file, register routes at the given lines with no per-route
/// middleware, and return the rbac findings.
fn rbac_on_group_file(
    tag: &str,
    content: &str,
    route_lines: &[u32],
) -> Vec<verum_nucleus::Finding> {
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "verum-precision-rbac-{}-{}-{seq}",
        std::process::id(),
        tag
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("api.php");
    std::fs::write(&file, content).unwrap();

    let mut ir = Ir::default();
    for &line in route_lines {
        ir.routes.push(route(&file, line, "/users", vec![]));
    }
    let findings = verum_lumen::rbac::analyse(&ir);
    std::fs::remove_dir_all(&dir).ok();
    findings
}

#[test]
fn auth_sanctum_group_covers_inner_routes() {
    let content = "<?php\n\
        \n\
        use Illuminate\\Support\\Facades\\Route;\n\
        \n\
        Route::middleware(['auth:sanctum'])->group(function () {\n\
        \x20   Route::get('/users', [UserController::class, 'index']);\n\
        \x20   Route::post('/users', [UserController::class, 'store']);\n\
        });\n";
    let findings = rbac_on_group_file("sanctum", content, &[6, 7]);
    assert!(
        !findings
            .iter()
            .any(|f| f.kind == FindingKind::MissingAuthMiddleware),
        "routes inside an auth:sanctum group must not flag: {:#?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>()
    );
}

#[test]
fn non_auth_group_still_flags_inner_routes() {
    let content = "<?php\n\
        \n\
        use Illuminate\\Support\\Facades\\Route;\n\
        \n\
        Route::middleware(['web'])->group(function () {\n\
        \x20   Route::get('/users', [UserController::class, 'index']);\n\
        });\n";
    let findings = rbac_on_group_file("web", content, &[6]);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == FindingKind::MissingAuthMiddleware),
        "a 'web'-only group must still flag its routes"
    );
}

#[test]
fn auth_session_group_covers_inner_routes() {
    let content = "<?php\n\
        \n\
        Route::group(['middleware' => ['auth.session']], function () {\n\
        \x20   Route::get('/users', [UserController::class, 'index']);\n\
        });\n";
    let findings = rbac_on_group_file("session", content, &[4]);
    assert!(
        !findings
            .iter()
            .any(|f| f.kind == FindingKind::MissingAuthMiddleware),
        "routes inside an auth.session group must not flag: {:#?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>()
    );
}

#[test]
fn auth_basic_route_middleware_counts_as_auth() {
    let mut ir = Ir::default();
    ir.routes.push(route(
        Path::new("/nonexistent/routes/api.php"),
        1,
        "/users",
        vec!["auth.basic".to_string()],
    ));
    let findings = verum_lumen::rbac::analyse(&ir);
    assert!(
        !findings
            .iter()
            .any(|f| f.kind == FindingKind::MissingAuthMiddleware),
        "auth.basic must count as auth middleware: {:#?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>()
    );
}

// taint.rs - compound assignment (`.=`, `+=`) propagation
#[test]
fn php_dot_equals_propagates_taint_to_sql_sink() {
    let (ir, dir) = php_ir(
        "taint-dotequals",
        "query.php",
        "<?php\n\
         function buildQuery() {\n\
         \x20   $q = \"SELECT * FROM users WHERE name = '\";\n\
         \x20   $q .= $_GET['name'];\n\
         \x20   $q .= \"'\";\n\
         \x20   return mysqli_query($GLOBALS['conn'], $q);\n\
         }\n",
    );
    let findings = verum_lumen::taint::analyse(&ir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        findings.iter().any(|f| f.kind == FindingKind::SqlInjection),
        ".= with a tainted RHS must taint the target and flag the sink: {:#?}",
        findings
            .iter()
            .map(|f| (&f.kind, &f.message))
            .collect::<Vec<_>>()
    );
}

#[test]
fn compound_assign_with_clean_rhs_does_not_clear_taint() {
    // `.=` with a sanitized RHS appends - it must NOT clear the taint that
    // `$q` already carries from line 3 (unlike a plain `=` reassignment).
    let (ir, dir) = php_ir(
        "taint-append-clean",
        "append.php",
        "<?php\n\
         function lookup() {\n\
         \x20   $q = $_GET['id'];\n\
         \x20   $q .= intval($_GET['page']);\n\
         \x20   return mysqli_query($GLOBALS['conn'], $q);\n\
         }\n",
    );
    let findings = verum_lumen::taint::analyse(&ir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        findings.iter().any(|f| f.kind == FindingKind::SqlInjection),
        "compound assign with clean RHS must not clear existing taint: {:#?}",
        findings
            .iter()
            .map(|f| (&f.kind, &f.message))
            .collect::<Vec<_>>()
    );
}

#[test]
fn plain_sanitized_reassignment_still_clears_taint() {
    // Regression guard for existing plain-`=` semantics.
    let (ir, dir) = php_ir(
        "taint-plain-clear",
        "safe.php",
        "<?php\n\
         function safeLookup() {\n\
         \x20   $q = $_GET['id'];\n\
         \x20   $q = intval($q);\n\
         \x20   return mysqli_query($GLOBALS['conn'], $q);\n\
         }\n",
    );
    let findings = verum_lumen::taint::analyse(&ir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        !findings.iter().any(|f| f.kind == FindingKind::SqlInjection),
        "plain `=` through a sanitizer must still clear taint: {:#?}",
        findings
            .iter()
            .map(|f| (&f.kind, &f.message))
            .collect::<Vec<_>>()
    );
}
