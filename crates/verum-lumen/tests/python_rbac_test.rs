//! Python MissingAuthMiddleware precision: the gate opens only for
//! decorator-declared routes in a project that demonstrably uses route-level
//! auth. Three properties are pinned here: a guarded route stays silent, an
//! unguarded route in an auth-using project flags, and a project with no auth
//! anywhere stays fully silent (it may sit behind a gateway - false positives
//! cost more than misses).

use std::path::Path;

use verum_nucleus::FindingKind;

/// Map a `tests/fixtures/python_rbac/<name>` fixture into an IR.
fn python_ir(fixture: &str) -> verum_nucleus::Ir {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/python_rbac")
        .join(fixture);
    let config = verum_mappa::AtlasConfig {
        root,
        language: verum_nucleus::Language::Python,
        ..Default::default()
    };
    verum_mappa::Atlas::new(config)
        .build()
        .expect("map python rbac fixtures")
}

#[test]
fn guarded_route_stays_silent() {
    let ir = python_ir("with_auth");
    let findings = verum_lumen::rbac::analyse(&ir);
    assert!(
        !findings
            .iter()
            .any(|f| f.kind == FindingKind::MissingAuthMiddleware
                && f.message.contains("/admin/settings")),
        "a @login_required route must not flag: {:#?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>()
    );
}

#[test]
fn unguarded_route_in_auth_using_project_flags() {
    let ir = python_ir("with_auth");
    let findings = verum_lumen::rbac::analyse(&ir);
    let hit = findings
        .iter()
        .find(|f| f.kind == FindingKind::MissingAuthMiddleware && f.message.contains("/api/orders"))
        .unwrap_or_else(|| {
            panic!(
                "the unguarded route must flag when the project uses auth: {:#?}",
                findings.iter().map(|f| &f.message).collect::<Vec<_>>()
            )
        });
    // Lower confidence than the PHP path: app-level ASGI/WSGI middleware in
    // another module could still be guarding it.
    assert!(
        (hit.confidence - 0.80).abs() < 1e-6,
        "python findings carry 0.80 confidence, got {}",
        hit.confidence
    );
}

#[test]
fn project_with_no_auth_anywhere_stays_fully_silent() {
    let ir = python_ir("no_auth");
    assert!(
        !ir.routes.is_empty(),
        "fixture routes must be extracted for the silence to mean anything"
    );
    let findings = verum_lumen::rbac::analyse(&ir);
    assert!(
        !findings
            .iter()
            .any(|f| f.kind == FindingKind::MissingAuthMiddleware),
        "zero auth in the project means zero MissingAuthMiddleware: {:#?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>()
    );
}
