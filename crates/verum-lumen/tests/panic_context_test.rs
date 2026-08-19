//! Context-aware `.unwrap()`/`.expect()` classification in rust_insights.
//! Infallible idioms and cold lock guards are not panic findings; a genuinely
//! fallible unwrap still is.

use verum_nucleus::FindingKind;

static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn panic_lines(source: &str) -> Vec<u32> {
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    // No "test" in the path - rust_insights skips test files.
    let dir = std::env::temp_dir().join(format!("verum_panicctx_{}_{seq}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("worker.rs");
    std::fs::write(&path, source).unwrap();
    let ir = verum_mappa::rust_lang::parse_file(&path).expect("parse");
    let insights = verum_lumen::rust_insights::analyse(&ir);
    let lines = insights
        .iter()
        .filter(|f| f.kind == FindingKind::PanicRisk)
        .map(|f| f.line_start)
        .collect();
    let _ = std::fs::remove_dir_all(&dir);
    lines
}

#[test]
fn infallible_and_guard_unwraps_are_not_flagged_but_fallible_is() {
    // Line numbers are 1-based from the raw string (line 1 is empty).
    let src = r#"
fn cold_worker(items: &[String]) {
    let guard = SHARED.lock().unwrap();
    let re = regex::Regex::new("^[a-z]+$").unwrap();
    write!(BUF, "{}", guard.len()).unwrap();
    let missing = items.first().expect("items must be non-empty");
    let parsed: u32 = items[0].parse().unwrap();
    let _ = (re, missing, parsed);
}
"#;
    let lines = panic_lines(src);
    // Only the genuinely fallible `.parse().unwrap()` (line 7) should remain.
    assert_eq!(
        lines,
        vec![7],
        "guard/regex/write!/cold-expect must be skipped; fallible parse must flag; got {lines:?}"
    );
}

#[test]
fn todo_macro_always_flags() {
    let src = r#"
fn stub() {
    todo!("wire this up");
}
"#;
    assert_eq!(
        panic_lines(src),
        vec![3],
        "todo! is incomplete code, always surfaced"
    );
}
