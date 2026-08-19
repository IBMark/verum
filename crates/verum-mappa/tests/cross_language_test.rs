//! Cross-language seam-linking: a JS `fetch('/api/x')` must connect to the
//! Laravel route handler that serves it, so the call graph spans the boundary.

use verum_nucleus::CallTarget;

fn build(dir: &std::path::Path) -> verum_nucleus::Ir {
    let config = verum_mappa::AtlasConfig {
        root: dir.to_path_buf(),
        ..Default::default()
    };
    verum_mappa::Atlas::new(config).build().expect("build")
}

/// Per-call sequence number: tests in one binary share a pid, so a pid-only
/// temp dir would be a shared path that parallel tests race on.
static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[test]
fn js_fetch_links_to_laravel_controller() {
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("verum_xlang_{}_{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("routes")).unwrap();
    std::fs::create_dir_all(dir.join("app/Http/Controllers")).unwrap();
    std::fs::create_dir_all(dir.join("resources/js")).unwrap();

    std::fs::write(
        dir.join("composer.json"),
        r#"{"require":{"laravel/framework":"^10.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("routes/api.php"),
        "<?php\nuse App\\Http\\Controllers\\UserController;\nRoute::get('/api/users/{id}', [UserController::class, 'show']);\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("app/Http/Controllers/UserController.php"),
        "<?php\nnamespace App\\Http\\Controllers;\nclass UserController {\n  public function show($id) { return $id; }\n}\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("resources/js/api.js"),
        "export async function loadUser(id) {\n  return fetch(`/api/users/${id}`);\n}\n",
    )
    .unwrap();

    let ir = build(&dir);

    // The JS caller of the fetch.
    let load_user = ir
        .symbols
        .values()
        .find(|s| s.name == "loadUser")
        .expect("loadUser symbol");
    // The PHP controller method.
    let show = ir
        .symbols
        .values()
        .find(|s| s.name == "show")
        .expect("show symbol");

    // A cross-language edge: loadUser (JS) -> UserController::show (PHP).
    let linked = ir.calls.iter().any(|c| {
        c.caller == load_user.id && matches!(&c.callee, CallTarget::Resolved(t) if *t == show.id)
    });
    assert!(
        linked,
        "JS fetch must link to the Laravel controller across the language boundary"
    );

    // The client call was extracted.
    assert!(
        ir.http_calls.iter().any(|h| h.path.contains("/api/users")),
        "the fetch URL should be recorded as an http_call"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
