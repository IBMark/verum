//! Inline `<script>` extraction from HTML.
//!
//! A single-page app can carry all its logic in one `<script type="module">`
//! inside an `index.html`, invisible to every analysis pass because the file
//! has an `.html` extension. This module lifts each inline script's JavaScript
//! into the JS pipeline, attributing symbols to the HTML file at their real
//! line numbers so findings point back to the right place.
//!
//! Scripts with a `src=` attribute (external references, nothing to analyse
//! here) and non-JS `type`s (JSON, importmap, text templates) are skipped.

use std::collections::HashSet;
use std::path::Path;

use anyhow::Result;
use verum_nucleus::{FileId, FileInfo, Ir, Language, SymbolId};

use crate::javascript;

/// One inline script: its JS source and the 0-based line where it starts in
/// the HTML file.
struct InlineScript {
    source: String,
    start_line: u32,
}

/// Parse an HTML file, analysing every inline `<script>` as JavaScript. The
/// returned IR registers the HTML file and all symbols/calls the scripts
/// contain, with line numbers offset to the HTML file.
pub fn parse_file(path: &Path) -> Result<Ir> {
    let source = std::fs::read_to_string(path)?;
    let mut ir = Ir::new();
    let mut all_symbol_ids: Vec<SymbolId> = Vec::new();

    for (index, script) in extract_scripts(&source).into_iter().enumerate() {
        // Each fragment gets its own deterministic ID space seeded from
        // (path, fragment index). Seeding every fragment with hash(path)
        // alone would make fragment N+1 allocate the same SymbolIds as
        // fragment N, silently overwriting its symbols on insert below.
        let seed = crate::stable_hash(&format!("{}::script[{}]", path.display(), index));
        let Ok(mut frag_ir) = javascript::parse_source(&script.source, path, false, Some(seed))
        else {
            continue;
        };
        offset_lines(&mut frag_ir, script.start_line);
        for (id, sym) in frag_ir.symbols.drain() {
            all_symbol_ids.push(id);
            ir.symbols.insert(id, sym);
        }
        ir.calls.append(&mut frag_ir.calls);
    }

    // Functions referenced from HTML event-handler attributes
    // (`onclick="doThing(...)"`) or exported onto `window` are entry points:
    // the browser calls them, so they are not dead even though no in-script
    // call site names them. Mark matching symbols so dead-code analysis skips
    // them - otherwise HTML extraction would manufacture false positives.
    let referenced = referenced_handler_names(&source);
    for sym in ir.symbols.values_mut() {
        if referenced.contains(&sym.name) {
            sym.is_entry_point = true;
        }
    }

    let line_count = source.lines().count() as u32;
    let size_bytes = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let file_id = FileId(crate::stable_hash(path.to_string_lossy().as_ref()));
    ir.files.insert(
        path.to_path_buf(),
        FileInfo {
            id: file_id,
            path: path.to_path_buf(),
            // Report as JS so downstream JS-gated passes (taint, perf) run.
            language: Language::JavaScript,
            line_count,
            size_bytes,
            last_modified: 0,
            hash: 0,
            symbols: all_symbol_ids,
        },
    );
    ir.metadata.total_files = 1;
    ir.metadata.total_lines = line_count as u64;

    Ok(ir)
}

/// Add `offset` lines to every symbol and call in `ir`, mapping fragment-local
/// line numbers back onto the host HTML file.
fn offset_lines(ir: &mut Ir, offset: u32) {
    for sym in ir.symbols.values_mut() {
        sym.line_start += offset;
        sym.line_end += offset;
    }
    for call in &mut ir.calls {
        call.line += offset;
    }
}

/// Find inline `<script>` blocks, returning their JS source and start line.
/// Deliberately small hand-written scanner (no HTML-parser dependency): it
/// matches `<script ...>` ... `</script>`, skips tags carrying `src=` or a
/// non-JS `type`, and is case-insensitive on tag/attribute names.
fn extract_scripts(html: &str) -> Vec<InlineScript> {
    let lower = html.to_ascii_lowercase();
    let bytes = html.as_bytes();
    let mut scripts = Vec::new();
    let mut search = 0usize;

    while let Some(rel) = lower[search..].find("<script") {
        let tag_start = search + rel;
        let Some(gt_rel) = lower[tag_start..].find('>') else {
            break;
        };
        let open_end = tag_start + gt_rel + 1;
        let open_tag = &lower[tag_start..open_end];

        let Some(close_rel) = lower[open_end..].find("</script") else {
            break;
        };
        let content_end = open_end + close_rel;

        let keep = !open_tag.contains(" src=") && type_is_js(open_tag);
        if keep {
            let start_line = bytecount_newlines(&bytes[..open_end]);
            scripts.push(InlineScript {
                source: html[open_end..content_end].to_string(),
                start_line,
            });
        }
        search = content_end + "</script".len();
    }
    scripts
}

/// Collect function names referenced from HTML in ways the JS parser can't
/// see as call sites: event-handler attributes (`onclick="fn(...)"`, any
/// `on*=`) and `window.fn =` / `window.fn=` exports (the function is handed to
/// the host to invoke).
fn referenced_handler_names(html: &str) -> HashSet<String> {
    let mut names = HashSet::new();
    let bytes = html.as_bytes();

    // on<event>="name(...)" or on<event>='name(...)'
    let lower = html.to_ascii_lowercase();
    let mut from = 0;
    while let Some(rel) = lower[from..].find("on") {
        let i = from + rel;
        from = i + 2;
        // Must be an attribute: `on<letters>=` with a quote after `=`.
        let rest = &html[i + 2..];
        let evt_len = rest.chars().take_while(|c| c.is_ascii_alphabetic()).count();
        if evt_len == 0 {
            continue;
        }
        let after = &html[i + 2 + evt_len..];
        let after_trim = after.trim_start();
        if !after_trim.starts_with('=') {
            continue;
        }
        let val = after_trim[1..].trim_start();
        let val = val.strip_prefix(['"', '\'']).unwrap_or(val);
        // First identifier in the handler body is the called function.
        let name: String = val
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
            .collect();
        if !name.is_empty() && name.chars().next().is_some_and(|c| !c.is_ascii_digit()) {
            names.insert(name);
        }
    }

    // window.name = / window.name=
    let mut from = 0;
    while let Some(rel) = html[from..].find("window.") {
        let i = from + rel + "window.".len();
        from = i;
        let name: String = html[i..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
            .collect();
        let after = html[i + name.len()..].trim_start();
        if !name.is_empty() && after.starts_with('=') && !after.starts_with("==") {
            names.insert(name);
        }
    }

    let _ = bytes;
    names
}

/// A script tag runs JavaScript unless its `type` says otherwise. Absent type,
/// `text/javascript`, `application/javascript`, and `module` all count.
fn type_is_js(open_tag: &str) -> bool {
    let Some(pos) = open_tag.find("type=") else {
        return true; // no type attribute -> classic JS
    };
    let rest = open_tag[pos + 5..].trim_start_matches(['"', '\'']);
    let value: String = rest
        .chars()
        .take_while(|c| !matches!(c, '"' | '\'' | ' ' | '>'))
        .collect();
    matches!(
        value.as_str(),
        "" | "text/javascript" | "application/javascript" | "module" | "text/babel"
    )
}

/// Count newlines in a byte slice - the 0-based line index of what follows.
fn bytecount_newlines(bytes: &[u8]) -> u32 {
    bytes.iter().filter(|&&b| b == b'\n').count() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_inline_module_script() {
        let html = "<!doctype html>\n<body>\n<script type=\"module\">\nfunction go() { fetch('/x'); }\n</script>\n</body>";
        let scripts = extract_scripts(html);
        assert_eq!(scripts.len(), 1);
        assert!(scripts[0].source.contains("function go()"));
        // <script> opens on line 3 (0-based index 2); content starts after it.
        assert_eq!(scripts[0].start_line, 2);
    }

    #[test]
    fn skips_external_and_non_js() {
        let html = "\
<script src=\"app.js\"></script>
<script type=\"application/json\">{\"a\":1}</script>
<script type=\"importmap\">{}</script>
<script>let real = 1;</script>";
        let scripts = extract_scripts(html);
        assert_eq!(scripts.len(), 1);
        assert!(scripts[0].source.contains("let real"));
    }

    #[test]
    fn handler_and_window_refs_detected() {
        let html = r#"
<button onclick="applyThing(1, this)">go</button>
<input oninput='updateVal()'>
<script>
function applyThing(i, el) {}
function updateVal() {}
function helper() {}
window.applyThing = applyThing;
</script>"#;
        let names = referenced_handler_names(html);
        assert!(names.contains("applyThing"), "{names:?}");
        assert!(names.contains("updateVal"), "{names:?}");
        assert!(!names.contains("helper"), "{names:?}");
    }

    #[test]
    fn handler_referenced_fn_not_dead() {
        let html = "\
<button onclick=\"go(this)\">x</button>
<script>
function go(el) { doWork(); }
function doWork() {}
</script>";
        let dir = std::env::temp_dir().join(format!("verum-html-live-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("index.html");
        std::fs::write(&file, html).unwrap();
        let ir = parse_file(&file).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        let go = ir.symbols.values().find(|s| s.name == "go").unwrap();
        assert!(
            go.is_entry_point,
            "onclick-referenced fn should be an entry point"
        );
    }

    #[test]
    fn line_offset_maps_to_html() {
        let html = "<html>\n<head></head>\n<body>\n<script>\nfunction handler() {}\n</script>";
        let dir = std::env::temp_dir().join(format!("verum-html-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("index.html");
        std::fs::write(&file, html).unwrap();
        let ir = parse_file(&file).unwrap();
        std::fs::remove_dir_all(&dir).ok();

        let handler = ir
            .symbols
            .values()
            .find(|s| s.name == "handler")
            .expect("found handler");
        // `function handler` is on line 5 of the HTML.
        assert_eq!(handler.line_start, 5);
    }
}
