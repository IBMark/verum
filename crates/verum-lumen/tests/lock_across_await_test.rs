//! Guard-held-across-await detection: fires when a lock/cell guard spans an
//! `.await`, and must NOT fire when the guard is scoped/dropped first.

use verum_nucleus::FindingKind;

// Tests run in parallel - each needs its own file or they race on the path.
static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn analyse(src: &str) -> Vec<verum_nucleus::Finding> {
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("verum_lockawait_{}_{seq}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("w.rs");
    std::fs::write(&path, src).unwrap();
    let ir = verum_mappa::rust_lang::parse_file(&path).unwrap();
    let f = verum_lumen::rust_insights::analyse(&ir);
    let _ = std::fs::remove_dir_all(&dir);
    f
}

fn await_lines(src: &str) -> Vec<u32> {
    analyse(src)
        .into_iter()
        .filter(|f| f.kind == FindingKind::LockAcrossAwait)
        .map(|f| f.line_start)
        .collect()
}

#[test]
fn guard_held_across_await_fires() {
    let src = r#"async fn bad(state: std::sync::Mutex<u32>) {
    let g = state.lock().unwrap();
    do_thing().await;
    let _ = g;
}
async fn do_thing() {}
"#;
    assert_eq!(
        await_lines(src),
        vec![3],
        "guard g spans the await on line 4"
    );
}

#[test]
fn scoped_guard_dropped_before_await_does_not_fire() {
    let src = r#"async fn good(state: std::sync::Mutex<u32>) {
    {
        let g = state.lock().unwrap();
        let _ = *g;
    }
    do_thing().await;
}
async fn do_thing() {}
"#;
    assert!(
        await_lines(src).is_empty(),
        "guard's block closes before the await"
    );
}

#[test]
fn explicit_drop_before_await_does_not_fire() {
    let src = r#"async fn ok(state: std::sync::Mutex<u32>) {
    let g = state.lock().unwrap();
    let _ = *g;
    drop(g);
    do_thing().await;
}
async fn do_thing() {}
"#;
    assert!(
        await_lines(src).is_empty(),
        "explicit drop(g) clears the guard"
    );
}
