//! Outgoing HTTP client-call extraction from PHP source (php.rs).

use std::io::Write;

use verum_nucleus::HttpMethod;

fn parse_php(src: &str) -> verum_nucleus::Ir {
    let dir = std::env::temp_dir().join(format!("verum_php_http_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!(
        "svc_{}.php",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(src.as_bytes()).unwrap();
    verum_mappa::php::parse_file(&path).expect("parse php")
}

fn method_eq(a: &HttpMethod, b: &HttpMethod) -> bool {
    std::mem::discriminant(a) == std::mem::discriminant(b)
}

fn has_call(ir: &verum_nucleus::Ir, method: HttpMethod, path: &str) -> bool {
    ir.http_calls
        .iter()
        .any(|c| c.path == path && method_eq(&c.method, &method))
}

#[test]
fn laravel_http_facade_get() {
    let src = r#"<?php
class Svc {
    public function load() {
        return Http::get('http://api/users');
    }
}
"#;
    let ir = parse_php(src);
    assert!(
        has_call(&ir, HttpMethod::Get, "/users"),
        "expected GET /users, got {:?}",
        ir.http_calls
    );
}

#[test]
fn guzzle_request_with_explicit_method() {
    let src = r#"<?php
class Svc {
    public function send($client) {
        return $client->request('POST', 'http://h/api/x');
    }
}
"#;
    let ir = parse_php(src);
    assert!(
        has_call(&ir, HttpMethod::Post, "/api/x"),
        "expected POST /api/x, got {:?}",
        ir.http_calls
    );
}

#[test]
fn laravel_withtoken_chain_and_query_stripping() {
    let src = r#"<?php
class Svc {
    public function items() {
        return Http::withToken('tok')->post('http://api/items?q=1');
    }
}
"#;
    let ir = parse_php(src);
    // withToken('tok') must NOT be recorded (not a URL); post URL query stripped.
    assert!(
        has_call(&ir, HttpMethod::Post, "/items"),
        "expected POST /items, got {:?}",
        ir.http_calls
    );
    assert_eq!(
        ir.http_calls.len(),
        1,
        "only the post() should be recorded, got {:?}",
        ir.http_calls
    );
}

#[test]
fn guzzle_verb_root_relative() {
    let src = r#"<?php
class Svc {
    public function go($client) {
        return $client->get('/local/path');
    }
}
"#;
    let ir = parse_php(src);
    assert!(
        has_call(&ir, HttpMethod::Get, "/local/path"),
        "expected GET /local/path, got {:?}",
        ir.http_calls
    );
}

#[test]
fn curl_setopt_url() {
    let src = r#"<?php
class Svc {
    public function fetch($ch) {
        curl_setopt($ch, CURLOPT_URL, 'http://api/things/5');
    }
}
"#;
    let ir = parse_php(src);
    assert!(
        has_call(&ir, HttpMethod::Get, "/things/5"),
        "expected GET /things/5, got {:?}",
        ir.http_calls
    );
}

#[test]
fn non_url_member_calls_ignored() {
    // Ordinary method calls whose args don't look like URLs stay out of http_calls.
    let src = r#"<?php
class Svc {
    public function noise($repo) {
        $repo->get('someKey');
        $repo->post('another', 'thing');
    }
}
"#;
    let ir = parse_php(src);
    assert!(
        ir.http_calls.is_empty(),
        "expected no http_calls, got {:?}",
        ir.http_calls
    );
}

#[test]
fn caller_is_enclosing_method_not_empty() {
    let src = r#"<?php
class Svc {
    public function load() {
        return Http::get('http://api/users');
    }
}
"#;
    let ir = parse_php(src);
    let call = &ir.http_calls[0];
    // Caller must resolve to a real symbol present in the IR.
    assert!(
        ir.symbols.contains_key(&call.caller),
        "http_call caller should be a known symbol"
    );
}
