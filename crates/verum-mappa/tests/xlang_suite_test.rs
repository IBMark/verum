//! Cross-language seam-linking suite - one test per backend language.
//!
//! Each test builds a tiny two-file project: a frontend `client.js` that issues
//! `fetch('/api/x')`, plus a backend file that defines a route serving `/api/x`
//! whose handler is a symbol named `show`. After `Atlas::build`, the
//! cross-language linker (`endpoints::link`) should add a *resolved* `Call` edge
//! from the JS caller symbol (`callApi`) to the backend handler symbol (`show`),
//! stitching the frontend/backend boundary into one call graph.
//!
//! All six backends (Laravel/Express/actix/FastAPI/gin/Spring) link today. The
//! suite was authored tolerant of not-yet-landed route extractors (each backend
//! test carried `#[ignore]` with a "un-ignore once the <backend> route agent
//! lands" note); every extractor has since landed and all six pass, so the
//! ignores were removed and these are now active guards on the seam.
//!
//! Run:
//!     cargo test -p verum-mappa --test xlang_suite_test

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use verum_nucleus::{CallTarget, Ir};

/// A process-unique, per-test working directory. Uses the pid plus a global
/// atomic counter so parallel tests never collide and no two builds share state.
fn workdir(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "verum_xlang_suite_{}_{}_{}",
        tag,
        std::process::id(),
        n
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(dir: &std::path::Path, rel: &str, contents: &str) {
    let path = dir.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

fn build(dir: &std::path::Path) -> Ir {
    let config = verum_mappa::AtlasConfig {
        root: dir.to_path_buf(),
        ..Default::default()
    };
    verum_mappa::Atlas::new(config).build().expect("build")
}

/// The frontend half every test shares: a named JS function that fetches
/// `/api/x`. The linker must attribute the `HttpCall` to `callApi` and connect
/// it to whatever backend serves `/api/x`.
const CLIENT_JS: &str = "export async function callApi() {\n  return fetch('/api/x');\n}\n";

/// Assert the full cross-language chain: the client `HttpCall` was extracted,
/// and a resolved `Call` edge runs from `callApi` (JS) to `show` (backend).
fn assert_linked(ir: &Ir, backend: &str) {
    // The frontend call must be recorded regardless of backend language.
    assert!(
        ir.http_calls.iter().any(|h| h.path.contains("/api/x")),
        "[{backend}] the fetch('/api/x') should be recorded as an http_call"
    );

    let call_api = ir
        .symbols
        .values()
        .find(|s| s.name == "callApi")
        .unwrap_or_else(|| panic!("[{backend}] callApi (JS caller) symbol should exist"));
    let show = ir
        .symbols
        .values()
        .find(|s| s.name == "show")
        .unwrap_or_else(|| panic!("[{backend}] show (backend handler) symbol should exist"));

    // A route serving /api/x must have been extracted with a controller.
    assert!(
        !ir.routes.is_empty(),
        "[{backend}] a route serving /api/x should be extracted"
    );

    let linked = ir.calls.iter().any(|c| {
        c.caller == call_api.id && matches!(&c.callee, CallTarget::Resolved(t) if *t == show.id)
    });
    assert!(
        linked,
        "[{backend}] JS fetch('/api/x') must link to the backend handler `show` across the language boundary"
    );
}

// 1. JS -> Laravel (PHP). Works today.
#[test]
fn js_links_to_laravel_php() {
    let dir = workdir("laravel");
    write(
        &dir,
        "composer.json",
        r#"{"require":{"laravel/framework":"^10.0"}}"#,
    );
    write(
        &dir,
        "routes/api.php",
        "<?php\nuse App\\Http\\Controllers\\UserController;\nRoute::get('/api/x', [UserController::class, 'show']);\n",
    );
    write(
        &dir,
        "app/Http/Controllers/UserController.php",
        "<?php\nnamespace App\\Http\\Controllers;\nclass UserController {\n  public function show() { return 'ok'; }\n}\n",
    );
    write(&dir, "resources/js/client.js", CLIENT_JS);

    let ir = build(&dir);
    assert_linked(&ir, "laravel");

    let _ = std::fs::remove_dir_all(&dir);
}

// 2. JS -> Node/Express. Backend is also JS: `app.get('/api/x', show)`.
//    Active guard: JS fetch links to the Express handler.
#[test]
fn js_links_to_express() {
    let dir = workdir("express");
    write(
        &dir,
        "package.json",
        r#"{"name":"x","dependencies":{"express":"^4.18.0"}}"#,
    );
    write(
        &dir,
        "server.js",
        "const express = require('express');\nconst app = express();\nfunction show(req, res) { res.send('ok'); }\napp.get('/api/x', show);\nmodule.exports = app;\n",
    );
    write(&dir, "client.js", CLIENT_JS);

    let ir = build(&dir);
    assert_linked(&ir, "express");

    let _ = std::fs::remove_dir_all(&dir);
}

// 3. JS -> Rust actix. `#[get("/api/x")] async fn show()`.
//    Active guard: JS fetch links to the actix handler.
#[test]
fn js_links_to_rust_actix() {
    let dir = workdir("actix");
    write(
        &dir,
        "Cargo.toml",
        "[package]\nname = \"backend\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nactix-web = \"4\"\n",
    );
    write(
        &dir,
        "src/main.rs",
        "use actix_web::get;\n\n#[get(\"/api/x\")]\nasync fn show() -> String {\n    \"ok\".to_string()\n}\n\nfn main() {}\n",
    );
    write(&dir, "client.js", CLIENT_JS);

    let ir = build(&dir);
    assert_linked(&ir, "actix");

    let _ = std::fs::remove_dir_all(&dir);
}

// 4. JS -> Python FastAPI. `@app.get("/api/x")` on `def show()`.
//    Active guard: JS fetch links to the FastAPI handler.
#[test]
fn js_links_to_python_fastapi() {
    let dir = workdir("fastapi");
    write(&dir, "requirements.txt", "fastapi\nuvicorn\n");
    write(
        &dir,
        "main.py",
        "from fastapi import FastAPI\n\napp = FastAPI()\n\n\n@app.get(\"/api/x\")\ndef show():\n    return {\"ok\": True}\n",
    );
    write(&dir, "client.js", CLIENT_JS);

    let ir = build(&dir);
    assert_linked(&ir, "fastapi");

    let _ = std::fs::remove_dir_all(&dir);
}

// 5. JS -> Go gin. `r.GET("/api/x", show)`.
//    Active guard: JS fetch links to the gin handler.
#[test]
fn js_links_to_go_gin() {
    let dir = workdir("gin");
    write(
        &dir,
        "go.mod",
        "module backend\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.9.1\n",
    );
    write(
        &dir,
        "main.go",
        "package main\n\nimport \"github.com/gin-gonic/gin\"\n\nfunc show(c *gin.Context) {\n\tc.String(200, \"ok\")\n}\n\nfunc main() {\n\tr := gin.Default()\n\tr.GET(\"/api/x\", show)\n\tr.Run()\n}\n",
    );
    write(&dir, "client.js", CLIENT_JS);

    let ir = build(&dir);
    assert_linked(&ir, "gin");

    let _ = std::fs::remove_dir_all(&dir);
}

// 6. JS -> Java Spring. `@RestController @RequestMapping("/api")` class with
//    `@GetMapping("/x")` on `show()` - combined path is `/api/x`.
//    Active guard: JS fetch links to the Spring handler.
#[test]
fn js_links_to_java_spring() {
    let dir = workdir("spring");
    write(
        &dir,
        "pom.xml",
        "<project>\n  <groupId>com.example</groupId>\n  <artifactId>backend</artifactId>\n  <version>1.0</version>\n  <dependencies>\n    <dependency>\n      <groupId>org.springframework.boot</groupId>\n      <artifactId>spring-boot-starter-web</artifactId>\n    </dependency>\n  </dependencies>\n</project>\n",
    );
    write(
        &dir,
        "src/main/java/com/example/UserController.java",
        "package com.example;\n\nimport org.springframework.web.bind.annotation.GetMapping;\nimport org.springframework.web.bind.annotation.RequestMapping;\nimport org.springframework.web.bind.annotation.RestController;\n\n@RestController\n@RequestMapping(\"/api\")\npublic class UserController {\n    @GetMapping(\"/x\")\n    public String show() {\n        return \"ok\";\n    }\n}\n",
    );
    write(&dir, "client.js", CLIENT_JS);

    let ir = build(&dir);
    assert_linked(&ir, "spring");

    let _ = std::fs::remove_dir_all(&dir);
}
