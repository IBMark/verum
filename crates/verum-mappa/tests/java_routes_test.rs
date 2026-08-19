//! Integration tests for Spring/JAX-RS route extraction (`java_web.rs`),
//! driven through `Atlas` on a temp directory. Because the Java frontend does
//! not yet populate `doc_comment`, these exercise the source-scan fallback
//! path end to end.

use std::io::Write;
use std::path::{Path, PathBuf};

use verum_nucleus::{HttpMethod, Language};

/// Write `source` to `dir/<name>.java`.
fn write_java(dir: &Path, name: &str, source: &str) {
    let path = dir.join(format!("{}.java", name));
    let mut f = std::fs::File::create(&path).expect("create java file");
    f.write_all(source.as_bytes()).expect("write java file");
}

fn build(dir: &Path) -> verum_nucleus::Ir {
    let config = verum_mappa::AtlasConfig {
        root: dir.to_path_buf(),
        language: Language::Java,
        ..Default::default()
    };
    verum_mappa::Atlas::new(config)
        .build()
        .expect("atlas build")
}

fn unique_dir(tag: &str) -> PathBuf {
    // Tests run in parallel threads sharing one pid; the sequence number
    // keeps dirs unique even if two tests ever pass the same tag.
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "verum_java_routes_{}_{}_{seq}",
        tag,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

#[test]
fn spring_rest_controller_class_prefix_plus_method_mapping() {
    let dir = unique_dir("spring");
    write_java(
        &dir,
        "UserController",
        r#"
package com.example;

@RestController
@RequestMapping("/api")
public class UserController {

    @GetMapping("/users/{id}")
    public User getUser(String id) {
        return repo.find(id);
    }

    @PostMapping("/users")
    public User create(User u) {
        return repo.save(u);
    }
}
"#,
    );

    let ir = build(&dir);

    let route = ir
        .routes
        .iter()
        .find(|r| r.path == "/api/users/{id}")
        .expect("expected route /api/users/{id}");
    assert!(
        matches!(route.method, HttpMethod::Get),
        "method should be GET, got {:?}",
        route.method
    );

    // Controller must resolve to the getUser method symbol.
    let controller = route.controller.expect("route should have a controller");
    let handler = ir
        .symbols
        .get(&controller)
        .expect("controller symbol exists");
    assert_eq!(handler.name, "getUser");

    // POST route with the same class prefix.
    let post = ir
        .routes
        .iter()
        .find(|r| r.path == "/api/users" && matches!(r.method, HttpMethod::Post))
        .expect("expected POST /api/users");
    let post_handler = ir.symbols.get(&post.controller.unwrap()).unwrap();
    assert_eq!(post_handler.name, "create");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn spring_request_mapping_with_explicit_method() {
    let dir = unique_dir("reqmap");
    write_java(
        &dir,
        "OrderController",
        r#"
package com.example;

@Controller
@RequestMapping("/orders")
public class OrderController {

    @RequestMapping(value = "/{id}", method = RequestMethod.DELETE)
    public void remove(String id) {
        repo.delete(id);
    }
}
"#,
    );

    let ir = build(&dir);
    let route = ir
        .routes
        .iter()
        .find(|r| r.path == "/orders/{id}")
        .expect("expected /orders/{id}");
    assert!(
        matches!(route.method, HttpMethod::Delete),
        "method should be DELETE, got {:?}",
        route.method
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn jaxrs_class_path_plus_method_path() {
    let dir = unique_dir("jaxrs");
    write_java(
        &dir,
        "ProductResource",
        r#"
package com.example;

@Path("/products")
public class ProductResource {

    @GET
    @Path("/{sku}")
    public Product get(String sku) {
        return repo.find(sku);
    }
}
"#,
    );

    let ir = build(&dir);
    let route = ir
        .routes
        .iter()
        .find(|r| r.path == "/products/{sku}")
        .expect("expected /products/{sku}");
    assert!(
        matches!(route.method, HttpMethod::Get),
        "method should be GET, got {:?}",
        route.method
    );
    let handler = ir.symbols.get(&route.controller.unwrap()).unwrap();
    assert_eq!(handler.name, "get");

    let _ = std::fs::remove_dir_all(&dir);
}
