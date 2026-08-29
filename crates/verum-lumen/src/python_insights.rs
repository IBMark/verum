//! Python correctness line scan - the language-specific traps that survive
//! review because each one reads as reasonable code.
//!
//! Detectors, all local and syntactic, all tuned for precision over recall:
//! - [`FindingKind::BlockingInAsync`]: a blocking call (`time.sleep`, a
//!   synchronous `requests.`/`urllib.request.urlopen`/`socket.` network call,
//!   the `subprocess` family) inside an `async def`. Lines mentioning
//!   `await`, `asyncio.sleep`, `run_in_executor`, or `to_thread` are excluded
//!   as already offloaded. Same kind the Rust pass emits - the defect is
//!   identical, only the executor differs.
//! - [`FindingKind::MutableDefaultArg`]: `def f(x=[])` and friends. The
//!   default is evaluated once at `def` time, so every call shares one
//!   object. Only single-line signatures are scanned - a default on a
//!   continuation line is missed rather than risk matching a call site.
//! - [`FindingKind::SwallowedException`]: a bare `except:` /
//!   `except Exception:` whose entire body is `pass`. A handler that logs,
//!   re-raises, or catches a specific type is never flagged.
//! - [`FindingKind::AssertAsValidation`]: an `assert` on request/input-shaped
//!   identifiers in a non-test function - `python -O` strips asserts, so the
//!   check vanishes in optimized deployments. Test files are skipped
//!   entirely and `is not None` type-narrowing asserts are excluded.

use std::path::{Path, PathBuf};

use crate::scan::ScanContext;
use verum_nucleus::{
    matchable_path, Finding, FindingKind, Ir, Language, Severity, SymbolId, SymbolKind,
};

/// Module-qualified calls that block the event loop. Each pattern is matched
/// only at an identifier boundary (`requests.get(` never matches
/// `grequests.get(`), and only the module-level spellings are listed: a
/// `self.session.get(` is as often an `aiohttp.ClientSession` doing the right
/// thing, so instance calls are deliberately missed.
const PY_BLOCKING_CALLS: &[&str] = &[
    "time.sleep(",
    "requests.get(",
    "requests.post(",
    "requests.put(",
    "requests.patch(",
    "requests.delete(",
    "requests.head(",
    "requests.request(",
    "urllib.request.urlopen(",
    // Only the socket calls that actually block (connect / DNS); creating a
    // socket object or reading a constant does not.
    "socket.create_connection(",
    "socket.gethostbyname(",
    "socket.getaddrinfo(",
    "subprocess.run(",
    "subprocess.call(",
    "subprocess.check_call(",
    "subprocess.check_output(",
    "subprocess.Popen(",
];

/// Markers that mean the line already routes around the event loop - an
/// awaited coroutine or an explicit offload. Their presence anywhere on the
/// line clears every blocking-call pattern.
const ASYNC_SAFE_MARKERS: &[&str] = &["await", "asyncio.sleep", "run_in_executor", "to_thread"];

/// Identifier components that mark an assert's condition as validating
/// external input rather than an internal invariant. Matched against
/// snake/camel word components, never substrings, so the `requests` module
/// does not match `request` and `parameterize` does not match `param`.
const INPUT_WORDS: &[&str] = &["request", "params", "param", "payload", "form"];

struct FnSpan {
    id: SymbolId,
    name: String,
    start: u32,
    end: u32,
    is_async: bool,
}

#[allow(clippy::too_many_arguments)]
fn mk(
    kind: FindingKind,
    severity: Severity,
    confidence: f32,
    path: &Path,
    line: u32,
    symbol: Option<SymbolId>,
    message: String,
    advice: &str,
) -> Finding {
    Finding {
        fingerprint: String::new(),
        id: format!("py-{:?}-{}:{}", kind, path.display(), line),
        kind,
        severity,
        confidence,
        file: path.to_path_buf(),
        line_start: line,
        line_end: line,
        symbol,
        message,
        suggestion: advice.to_string(),
        auto_fixable: false,
        related: Vec::new(),
    }
}

/// Reads every file itself; prefer [`analyse_with_context`] when a pre-read
/// [`ScanContext`] is already available.
pub fn analyse(ir: &Ir) -> Vec<Finding> {
    analyse_with_context(ir, &ScanContext::index_only(ir))
}

/// As [`analyse`], but taking each file's lines and symbols from a context
/// shared with the other line-scanning passes.
pub fn analyse_with_context(ir: &Ir, ctx: &ScanContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    let mut files: Vec<PathBuf> = ir
        .files
        .iter()
        .filter(|(_, info)| info.language == Language::Python)
        .map(|(p, _)| p.clone())
        .collect();
    files.sort();

    for path in &files {
        let path_str = matchable_path(path);
        if path_str.contains("/site-packages/") || path_str.contains("/__pycache__/") {
            continue;
        }
        // Asserts in a test suite are the point of the file, so the
        // validation detector skips test paths outright (the shared helper
        // keeps `tests/fixtures/` analysable, and covers `conftest.py` and
        // the `test_*` naming convention). The other detectors still run:
        // their findings in real test trees are dropped by the auxiliary-path
        // filter downstream.
        let is_test_file = crate::is_test_path(&path_str);

        let Some(lines) = ctx.lines(path) else {
            continue;
        };

        let mut spans: Vec<FnSpan> = ctx
            .symbols(path)
            .iter()
            .filter_map(|id| ir.symbols.get(id))
            .filter(|s| {
                matches!(
                    s.kind,
                    SymbolKind::Function | SymbolKind::Method | SymbolKind::StaticMethod
                )
            })
            .map(|s| {
                // Check the declaration line for `async def`; the mapper's
                // spans start at the `def` line, not at a decorator.
                let decl = lines
                    .get((s.line_start as usize).saturating_sub(1))
                    .map(|l| l.as_str())
                    .unwrap_or("");
                FnSpan {
                    id: s.id,
                    name: s.name.clone(),
                    start: s.line_start,
                    end: s.line_end,
                    is_async: decl.trim_start().starts_with("async def "),
                }
            })
            .collect();
        spans.sort_by_key(|s| (s.start, s.end));

        // Smallest enclosing span per line, precomputed the same way
        // rust_insights does: overwrite only on a strictly smaller width so
        // ties keep the earliest span, and cap the table at the file length
        // so a malformed `line_end` cannot size the allocation.
        let max_end = spans
            .iter()
            .map(|s| s.end as usize)
            .max()
            .unwrap_or(0)
            .min(lines.len());
        let mut encl_idx: Vec<Option<usize>> = vec![None; max_end + 1];
        let mut encl_width: Vec<u32> = vec![u32::MAX; max_end + 1];
        for (i, s) in spans.iter().enumerate() {
            let w = s.end.saturating_sub(s.start);
            for line in (s.start as usize)..=(s.end as usize).min(max_end) {
                if w < encl_width[line] {
                    encl_width[line] = w;
                    encl_idx[line] = Some(i);
                }
            }
        }
        let enclosing = |line: u32| -> Option<&FnSpan> {
            encl_idx
                .get(line as usize)
                .copied()
                .flatten()
                .map(|i| &spans[i])
        };

        for (idx, line) in lines.iter().enumerate() {
            let line_num = (idx + 1) as u32;
            if line.len() > crate::scan::MAX_SCAN_LINE_BYTES {
                continue;
            }
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                continue;
            }
            let code = strip_line_comment(line);
            let code_trimmed = code.trim();

            let encl = enclosing(line_num);
            let sym = encl.map(|s| s.id);
            let in_async = encl.is_some_and(|s| s.is_async);

            if in_async && !ASYNC_SAFE_MARKERS.iter().any(|m| code.contains(m)) {
                if let Some(bc) = PY_BLOCKING_CALLS
                    .iter()
                    .find(|b| contains_module_call(&code, b))
                {
                    findings.push(mk(
                        FindingKind::BlockingInAsync,
                        Severity::Medium,
                        0.7,
                        path,
                        line_num,
                        sym,
                        format!(
                            "blocking call `{}` inside async def `{}`",
                            bc.trim_end_matches('('),
                            encl.map(|s| s.name.as_str()).unwrap_or("?")
                        ),
                        "latency/throughput: blocks the event loop and starves every \
                         other task on it - use the async equivalent (asyncio.sleep, \
                         httpx.AsyncClient, asyncio.create_subprocess_exec) or offload \
                         via loop.run_in_executor / asyncio.to_thread",
                    ));
                }
            }

            if code_trimmed.starts_with("def ") || code_trimmed.starts_with("async def ") {
                if let Some(default) = mutable_default(signature_of(code_trimmed)) {
                    findings.push(mk(
                        FindingKind::MutableDefaultArg,
                        Severity::Medium,
                        0.85,
                        path,
                        line_num,
                        sym,
                        format!("mutable default argument `={default}`"),
                        "the default is created once at def time and shared by every \
                         call - default to None and build the list/dict/set inside \
                         the body (`if x is None: x = []`)",
                    ));
                }
            }

            if let Some(inline_body) = swallowing_except(code_trimmed) {
                let swallowed = match inline_body {
                    // `except: pass` on one line.
                    Some(body) => body == "pass",
                    // Clause ends at the colon: the indented block decides.
                    None => body_is_only_pass(&lines, idx),
                };
                if swallowed {
                    findings.push(mk(
                        FindingKind::SwallowedException,
                        Severity::Medium,
                        0.85,
                        path,
                        line_num,
                        sym,
                        "exception handler swallows every error (`except` + `pass`)".to_string(),
                        "catch the specific exception you expect and at minimum log \
                         it; let everything else propagate so failures surface where \
                         they happen",
                    ));
                }
            }

            if !is_test_file
                && code_trimmed.starts_with("assert ")
                && encl.is_some_and(|s| !s.name.starts_with("test"))
                && is_validation_assert(code_trimmed)
            {
                findings.push(mk(
                    FindingKind::AssertAsValidation,
                    Severity::Low,
                    0.6,
                    path,
                    line_num,
                    sym,
                    format!(
                        "`assert` validates external input in `{}` - stripped under python -O",
                        encl.map(|s| s.name.as_str()).unwrap_or("?")
                    ),
                    "replace with an explicit check that raises (`if not ...: raise \
                     ValueError(...)`) so the validation survives optimized deployments",
                ));
            }
        }
    }

    findings.sort_by(|a, b| (&a.file, a.line_start).cmp(&(&b.file, b.line_start)));
    findings
}

/// True if `code` contains `pattern` starting at an identifier boundary - the
/// character before the match must not be part of an identifier or a dotted
/// path, so `requests.get(` never matches inside `grequests.get(` or
/// `self.requests.get(`.
fn contains_module_call(code: &str, pattern: &str) -> bool {
    let mut from = 0;
    while let Some(pos) = code[from..].find(pattern) {
        let abs = from + pos;
        let prev_ok = code[..abs]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '.');
        if prev_ok {
            return true;
        }
        from = abs + pattern.len();
    }
    false
}

/// The parenthesised parameter list of a single-line `def`, bounded by paren
/// depth so a one-line body after the signature (`def f(): x = {}`) is never
/// scanned. An unclosed signature (parameters continue on the next line)
/// yields what is on this line - later lines are deliberately not joined.
fn signature_of(def_line: &str) -> &str {
    let Some(open) = def_line.find('(') else {
        return "";
    };
    let inner = &def_line[open + 1..];
    let mut depth = 1i32;
    for (i, c) in inner.char_indices() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    return &inner[..i];
                }
            }
            _ => {}
        }
    }
    inner
}

/// The mutable-literal default in a signature slice, if any. The literal must
/// follow a bare `=` directly (a `==` inside a default expression is a
/// comparison) and be followed by a parameter boundary, so `x="{}"` (a string
/// containing braces) and `x=[1]` (a non-empty literal someone may intend as
/// a constant) never match.
fn mutable_default(sig: &str) -> Option<&'static str> {
    const MUTABLE: &[&str] = &["[]", "{}", "set()", "dict()", "list()"];
    let bytes = sig.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b != b'=' {
            continue;
        }
        if i > 0 && matches!(bytes[i - 1], b'=' | b'!' | b'<' | b'>') {
            continue;
        }
        if bytes.get(i + 1) == Some(&b'=') {
            continue;
        }
        let rest = sig[i + 1..].trim_start();
        for m in MUTABLE {
            if let Some(after) = rest.strip_prefix(m) {
                if matches!(
                    after.trim_start().chars().next(),
                    None | Some(',') | Some(')')
                ) {
                    return Some(m);
                }
            }
        }
    }
    None
}

/// If `trimmed` is an `except` clause that catches everything - bare,
/// `Exception`, or `BaseException`, with or without `as name` - return its
/// inline body: `Some(Some(body))` for a one-liner (`except: pass`),
/// `Some(None)` when the block follows on the next lines. A clause naming a
/// specific exception type is a deliberate decision and returns `None`.
fn swallowing_except(trimmed: &str) -> Option<Option<&str>> {
    let rest = trimmed.strip_prefix("except")?;
    let (head, body) = rest.split_once(':')?;
    let head = head.trim();
    let class = head.split(" as ").next().unwrap_or("").trim();
    if !(class.is_empty() || class == "Exception" || class == "BaseException") {
        return None;
    }
    let body = body.trim();
    Some(if body.is_empty() { None } else { Some(body) })
}

/// True when the indented block under line `except_idx` consists of nothing
/// but `pass` statements (at least one). Comment lines are ignored - a
/// comment does not un-swallow the error - and any other statement (a log
/// call, a `raise`, a flag) clears the whole block.
fn body_is_only_pass(lines: &[String], except_idx: usize) -> bool {
    let clause_indent = indent_of(&lines[except_idx]);
    let mut saw_pass = false;
    for line in lines.iter().skip(except_idx + 1) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if indent_of(line) <= clause_indent {
            break;
        }
        let stmt = strip_line_comment(line);
        if stmt.trim() != "pass" {
            return false;
        }
        saw_pass = true;
    }
    saw_pass
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// True for an assert whose condition reads external input - an INPUT_WORDS
/// component among its identifiers - excluding the type-narrowing shape
/// (`assert x is not None`) and `isinstance` checks, which state invariants
/// for a type checker rather than validating anything.
fn is_validation_assert(trimmed: &str) -> bool {
    let condition = trimmed.trim_start_matches("assert ").trim();
    // The message argument often *names* the input ("invalid request") even
    // when the condition does not touch it; judge the condition alone.
    let condition = condition.split_once(',').map_or(condition, |(c, _)| c);
    if condition.ends_with("is not None") || condition.contains("isinstance(") {
        return false;
    }
    has_input_word(condition)
}

/// Word-component match: identifiers are split on `_` and case boundaries, so
/// `request_body` and `formData` match while `requests` and `parameterize`
/// do not.
fn has_input_word(code: &str) -> bool {
    let mut word = String::new();
    let mut words = Vec::new();
    for c in code.chars() {
        if c.is_ascii_alphanumeric() {
            if c.is_ascii_uppercase() && !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
            word.push(c.to_ascii_lowercase());
        } else if !word.is_empty() {
            words.push(std::mem::take(&mut word));
        }
    }
    if !word.is_empty() {
        words.push(word);
    }
    words.iter().any(|w| INPUT_WORDS.contains(&w.as_str()))
}

fn strip_line_comment(line: &str) -> String {
    match line.find('#') {
        Some(pos) => line[..pos].to_string(),
        None => line.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_call_boundary() {
        assert!(contains_module_call(
            "resp = requests.get(url)",
            "requests.get("
        ));
        assert!(!contains_module_call(
            "resp = grequests.get(url)",
            "requests.get("
        ));
        assert!(!contains_module_call(
            "resp = self.requests.get(url)",
            "requests.get("
        ));
    }

    #[test]
    fn signature_stops_at_the_closing_paren() {
        assert_eq!(signature_of("def f(x=[]):"), "x=[]");
        assert_eq!(signature_of("def f(x=(1, 2)) -> dict:"), "x=(1, 2)");
        // One-line body after the signature is out of scope.
        assert_eq!(signature_of("def f(): cache = {}"), "");
    }

    #[test]
    fn mutable_defaults_detected_precisely() {
        assert_eq!(mutable_default("x=[]"), Some("[]"));
        assert_eq!(mutable_default("x = {}"), Some("{}"));
        assert_eq!(mutable_default("x: set = set()"), Some("set()"));
        assert_eq!(mutable_default("a, b=dict(), c=1"), Some("dict()"));
        // Not the trap: immutable, non-empty, string-quoted, or annotated-only.
        assert_eq!(mutable_default("x=None"), None);
        assert_eq!(mutable_default("x=[1]"), None);
        assert_eq!(mutable_default("x=\"{}\""), None);
        assert_eq!(mutable_default("x: list"), None);
        assert_eq!(mutable_default("check=(a == [])"), None);
    }

    #[test]
    fn only_catch_alls_count_as_swallowing() {
        assert_eq!(swallowing_except("except:"), Some(None));
        assert_eq!(swallowing_except("except Exception:"), Some(None));
        assert_eq!(swallowing_except("except Exception as e:"), Some(None));
        assert_eq!(swallowing_except("except: pass"), Some(Some("pass")));
        // A specific type is a decision, not a swallow.
        assert_eq!(swallowing_except("except ValueError:"), None);
        assert_eq!(swallowing_except("except (KeyError, TypeError):"), None);
        assert_eq!(swallowing_except("exception = e"), None);
    }

    #[test]
    fn validation_asserts_are_word_component_matched() {
        assert!(is_validation_assert("assert request.user_id"));
        assert!(is_validation_assert("assert params[\"id\"].isdigit()"));
        assert!(is_validation_assert("assert formData.amount > 0"));
        // The requests *module* is not the request, and narrowing is fine.
        assert!(!is_validation_assert("assert requests.get(url).ok"));
        assert!(!is_validation_assert("assert request is not None"));
        assert!(!is_validation_assert(
            "assert isinstance(request, HttpRequest)"
        ));
        assert!(!is_validation_assert("assert parameterized_query"));
        assert!(!is_validation_assert("assert len(items) > 0"));
    }
}
