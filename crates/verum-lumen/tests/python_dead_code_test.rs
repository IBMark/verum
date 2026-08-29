//! Python entry points must actually survive the dead-code pass, not just
//! carry a flag in the IR: Celery tasks, click commands, pytest fixtures, and
//! the verb methods of route-controller classes (Tornado handlers, DRF
//! ViewSets) all have framework-invoked call sites the static graph cannot
//! see. The control case keeps the pass honest - a plain uncalled helper in
//! the same file must still flag.

use std::path::PathBuf;

use verum_lumen::DeadCodeConfig;
use verum_nucleus::{FindingKind, Ir};

/// Tests run in parallel threads sharing one pid, so a per-call sequence
/// number keeps every temp dir unique even if two tests pass the same tag.
static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Parse a Python snippet with Atlas into an IR rooted at a unique temp dir.
fn python_ir(tag: &str, src: &str) -> (Ir, PathBuf) {
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "verum-py-dead-{}-{}-{seq}",
        std::process::id(),
        tag
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("worker.py"), src).unwrap();

    let config = verum_mappa::AtlasConfig {
        root: dir.clone(),
        language: verum_nucleus::Language::Python,
        ..Default::default()
    };
    let ir = verum_mappa::Atlas::new(config).build().expect("parse");
    (ir, dir)
}

fn dead_names(findings: &[verum_nucleus::Finding]) -> Vec<String> {
    findings
        .iter()
        .filter(|f| f.kind == FindingKind::DeadFunction)
        .map(|f| f.message.clone())
        .collect()
}

#[test]
fn framework_entry_points_do_not_read_as_dead() {
    let src = r#"
import click
import pytest


@app.task
def nightly_sync():
    return 1


@click.command()
def import_data():
    return 2


@pytest.fixture
def db_session():
    return 3


def orphan_helper():
    return 4
"#;
    let (ir, dir) = python_ir("entries", src);
    let findings = verum_lumen::dead_code::analyse(&ir, &DeadCodeConfig::default());
    std::fs::remove_dir_all(&dir).ok();

    let dead = dead_names(&findings);
    for kept in ["nightly_sync", "import_data", "db_session"] {
        assert!(
            !dead.iter().any(|m| m.contains(kept)),
            "{kept} is framework-invoked and must not be dead: {dead:?}"
        );
    }
    // Control: the pass still works - an uncalled plain helper flags.
    assert!(
        dead.iter().any(|m| m.contains("orphan_helper")),
        "an uncalled helper must still flag as dead: {dead:?}"
    );
}

#[test]
fn route_controller_class_methods_are_framework_reachable() {
    let src = r#"
import tornado.web


class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.write("home")

    def post(self):
        self.write("created")


def orphan_helper():
    return 1


application = tornado.web.Application([
    (r"/", MainHandler),
])
"#;
    let (ir, dir) = python_ir("tornado", src);
    let findings = verum_lumen::dead_code::analyse(&ir, &DeadCodeConfig::default());
    std::fs::remove_dir_all(&dir).ok();

    let dead = dead_names(&findings);
    assert!(
        !dead
            .iter()
            .any(|m| m.contains("`get`") || m.contains("`post`")),
        "verb methods on a route-controller class are dispatched by the framework: {dead:?}"
    );
    assert!(
        dead.iter().any(|m| m.contains("orphan_helper")),
        "an uncalled helper must still flag as dead: {dead:?}"
    );
}
