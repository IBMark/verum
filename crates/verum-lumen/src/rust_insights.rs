//! Rust systems-code performance map.
//!
//! Maps the constructs that determine how a Rust systems codebase performs -
//! hot-path allocations, unbounded queues, blocking calls on the async
//! executor, locks on latency-sensitive paths, `unsafe`, panic paths. Each is
//! tagged via [`impacts_for`] with how it affects latency, throughput, memory,
//! CPU and determinism, so the map can be lensed by an optimisation goal.
//!
//! Findings are informational and excluded from the security/architecture
//! score. Each `suggestion` states the objective impact and the fix.

use std::path::{Path, PathBuf};

use crate::scan::ScanContext;
use verum_nucleus::{
    Direction, Finding, FindingKind, Ir, Language, Objective, PerfImpact, Severity, SymbolId,
    SymbolKind,
};

/// Which objectives a construct affects and how. Helps = a deliberate
/// trade-off, e.g. an unbounded queue helps throughput at the cost of latency
/// and memory.
pub fn impacts_for(kind: &FindingKind) -> Vec<PerfImpact> {
    use Direction::*;
    use Objective::*;
    let mk = |objective, direction, weight| PerfImpact {
        objective,
        direction,
        weight,
    };
    match kind {
        FindingKind::HotPathAllocation => vec![
            mk(Latency, Hurts, 3),
            mk(Throughput, Hurts, 2),
            mk(Memory, Hurts, 2),
            mk(Cpu, Hurts, 2),
        ],
        FindingKind::UnboundedChannel => vec![
            mk(Latency, Hurts, 3),
            mk(Memory, Hurts, 3),
            mk(Determinism, Hurts, 2),
            mk(Throughput, Helps, 1), // no backpressure stalls - the trade-off
        ],
        FindingKind::BlockingInAsync => vec![
            mk(Latency, Hurts, 3),
            mk(Throughput, Hurts, 3),
            mk(Determinism, Hurts, 2),
        ],
        FindingKind::LockOnHotPath => vec![
            mk(Latency, Hurts, 2),
            mk(Throughput, Hurts, 2),
            mk(Determinism, Hurts, 2),
        ],
        FindingKind::LockAcrossAwait => vec![
            mk(Determinism, Hurts, 3),
            mk(Latency, Hurts, 2),
            mk(Throughput, Hurts, 2),
        ],
        FindingKind::PanicRisk => vec![mk(Determinism, Hurts, 2)],
        // `unsafe` is usually performance-motivated (zero-copy) - surfaced on
        // the map but not ranked under an objective.
        FindingKind::UnsafeUsage => vec![],
        _ => vec![],
    }
}

/// Function-name fragments that mark a latency-sensitive path - allocations
/// and clones here are worth flagging; elsewhere they are noise.
const HOT_FN_HINTS: &[&str] = &[
    "recv",
    "send",
    "poll",
    "handle",
    "process",
    "on_",
    "packetize",
    "depacketize",
    "encode",
    "decode",
    "read_frame",
    "write_frame",
    "forward",
    "relay",
    "dispatch",
    "tick",
    "step",
    "run_loop",
    "hot",
    "fast_path",
    "ingest",
];

const BLOCKING_CALLS: &[&str] = &[
    "std::fs::",
    "std::net::",
    "std::thread::sleep",
    "thread::sleep(",
    "::blocking",
    ".blocking_",
    "std::io::stdin",
    "reqwest::blocking",
];

struct FnSpan {
    id: SymbolId,
    name: String,
    start: u32,
    end: u32,
    is_async: bool,
    is_hot: bool,
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
        id: format!("rust-{:?}-{}:{}", kind, path.display(), line),
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

/// Context classifier for a panic-bearing line. `None` = don't report: the
/// panic is a provably-infallible idiom, or author-acknowledged off the hot
/// path. Otherwise the (severity, confidence) to report. Only `.unwrap()` /
/// `.expect()` are context-judged; explicit `panic!`/`todo!` macros are handled
/// by the caller and always surface.
fn classify_panic(code: &str, pat: &str, in_hot: bool, fn_name: &str) -> Option<(Severity, f32)> {
    // Infallible idioms - a Result that can't be Err in practice.
    if is_infallible_unwrap(code) {
        return None;
    }
    // Lock/borrow guards: unwrap is the idiomatic response to a poisoned lock
    // or already-borrowed cell - pervasive and low-signal off the hot path.
    let is_guard = code.contains(".lock().unwrap")
        || code.contains(".read().unwrap")
        || code.contains(".write().unwrap")
        || code.contains(".borrow().unwrap")
        || code.contains(".borrow_mut().unwrap");
    if is_guard {
        return if in_hot {
            Some((Severity::Low, 0.6))
        } else {
            None
        };
    }
    // `.expect("...")` states a written rationale; surface it only where a panic
    // actually costs - the hot path.
    if pat == ".expect(" && !in_hot {
        return None;
    }
    // A panic in `main` is an error exit, not a mid-flight crash.
    if fn_name == "main" && !in_hot {
        return None;
    }
    Some(if in_hot {
        (Severity::Low, 0.75)
    } else {
        (Severity::Info, 0.6)
    })
}

/// True when an `.unwrap()`/`.expect()` sits on a Result that can't fail in
/// practice: `write!`/`writeln!` into a growable buffer or formatter, and
/// `Regex::new` on a string literal (a constant pattern that compiled once
/// always compiles).
fn is_infallible_unwrap(code: &str) -> bool {
    if (code.contains("write!(") || code.contains("writeln!("))
        && (code.contains(".unwrap") || code.contains(".expect"))
    {
        return true;
    }
    if let Some(rest) = code.split("Regex::new(").nth(1) {
        let t = rest.trim_start();
        if t.starts_with('"') || (t.starts_with('r') && t[1..].starts_with(['"', '#'])) {
            return true;
        }
    }
    false
}

pub fn analyse(ir: &Ir) -> Vec<Finding> {
    analyse_with_context(ir, &ScanContext::index_only(ir))
}

/// As [`analyse`], but taking each file's lines and symbols from a context
/// shared with the other line-scanning passes. Purely a performance split: the
/// context reproduces what this pass used to derive per file, so the findings
/// are identical either way.
pub fn analyse_with_context(ir: &Ir, ctx: &ScanContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    let mut files: Vec<PathBuf> = ir
        .files
        .iter()
        .filter(|(_, info)| info.language == Language::Rust)
        .map(|(p, _)| p.clone())
        .collect();
    files.sort();

    for path in &files {
        let path_str = path.to_string_lossy();
        if path_str.contains("/target/") {
            continue;
        }
        // Skip real test code (unwrap/panic there is idiomatic), but NOT
        // fixtures-under-tests, which are analysis targets.
        let is_test_file = (path_str.ends_with("_test.rs")
            || (path_str.contains("/tests/") && !path_str.contains("fixtures"))
            || path
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("test")))
            && !path_str.contains("fixtures");

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
                // Check the declaration line for `async`.
                let decl = lines
                    .get((s.line_start as usize).saturating_sub(1))
                    .map(|l| l.as_str())
                    .unwrap_or("");
                let lname = s.name.to_ascii_lowercase();
                FnSpan {
                    id: s.id,
                    name: s.name.clone(),
                    start: s.line_start,
                    end: s.line_end,
                    is_async: decl.contains("async fn") || decl.contains("async move"),
                    is_hot: HOT_FN_HINTS.iter().any(|h| lname.contains(h)),
                }
            })
            .collect();
        spans.sort_by_key(|s| (s.start, s.end));

        // Smallest enclosing span for a line, precomputed per line so each
        // query is O(1) instead of a scan over every span. Spans are walked in
        // sorted order and an entry is overwritten only on a STRICTLY smaller
        // width: ties keep the earliest span, exactly reproducing the old
        // min_by_key first-wins tie-break.
        let max_end = spans.iter().map(|s| s.end).max().unwrap_or(0) as usize;
        let mut encl_idx: Vec<Option<usize>> = vec![None; max_end + 1];
        let mut encl_width: Vec<u32> = vec![u32::MAX; max_end + 1];
        for (i, s) in spans.iter().enumerate() {
            let w = s.end - s.start;
            for line in (s.start as usize)..=(s.end as usize) {
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

        // Inline `#[cfg(test)]` module/fn ranges - findings inside are scaffolding.
        let test_ranges = cfg_test_ranges(&lines);
        let file_start = findings.len();

        // Cold (non-hot-path) `.unwrap()`/`panic!` is pervasive and low-signal;
        // reporting every occurrence buries the findings that matter. Keep all
        // hot-path panics, cap cold ones per file, and summarize the remainder.
        let mut cold_panics_shown = 0usize;
        let mut cold_panics_hidden = 0usize;
        const COLD_PANIC_CAP: usize = 5;

        for (idx, line) in lines.iter().enumerate() {
            let line_num = (idx + 1) as u32;
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("///") {
                continue;
            }
            let code = strip_line_comment(line);

            let encl = enclosing(line_num);
            let sym = encl.map(|s| s.id);
            let in_async = encl.is_some_and(|s| s.is_async);
            let in_hot = encl.is_some_and(|s| s.is_hot);

            // `unsafe impl`/`unsafe trait` assert marker-trait invariants at a
            // declaration, not a soundness-bearing block; the SAFETY-comment
            // convention covers `unsafe { ... }` and `unsafe fn`, so scope the
            // checks to those.
            let is_unsafe_block = contains_word(&code, "unsafe")
                && !code.contains("unsafe impl")
                && !code.contains("unsafe trait");
            if is_unsafe_block && !is_test_file {
                findings.push(mk(
                    FindingKind::UnsafeUsage,
                    Severity::Info,
                    0.95,
                    path,
                    line_num,
                    sym,
                    "`unsafe` used here".to_string(),
                    "often a zero-copy/perf optimisation - confirm the soundness \
                     invariant holds and that a safe abstraction (`bytes`, \
                     `zerocopy`, slice methods) wouldn't match its cost",
                ));

                // The SAFETY comment is the reviewable record of why the
                // invariant holds; its absence is a concrete, low-false-positive
                // omission.
                if !has_safety_comment(&lines, idx) {
                    findings.push(mk(
                        FindingKind::MissingSafetyComment,
                        Severity::Low,
                        0.8,
                        path,
                        line_num,
                        sym,
                        "`unsafe` block without a `// SAFETY:` comment".to_string(),
                        "document the invariant that makes this sound: add a \
                         `// SAFETY: ...` comment stating why the guarantees the \
                         compiler can't check actually hold here",
                    ));
                }
            }

            let panic_pat = [
                ".unwrap(",
                ".expect(",
                "panic!(",
                "todo!(",
                "unimplemented!(",
                "unreachable!(",
            ]
            .into_iter()
            .find(|p| code.contains(p));
            if let Some(pat) = panic_pat {
                if !is_test_file {
                    let fn_name = encl.map(|s| s.name.as_str()).unwrap_or("");
                    // `.unwrap()`/`.expect()` are context-judged; explicit
                    // panic/todo/unimplemented/unreachable macros always surface.
                    let verdict = if pat == ".unwrap(" || pat == ".expect(" {
                        classify_panic(&code, pat, in_hot, fn_name)
                    } else {
                        Some(if in_hot {
                            (Severity::Low, 0.75)
                        } else {
                            (Severity::Info, 0.6)
                        })
                    };
                    if let Some((sev, conf)) = verdict {
                        // Cap cold (non-hot) panics per file; hot ones always emit.
                        let mut emit = true;
                        if !in_hot {
                            if cold_panics_shown >= COLD_PANIC_CAP {
                                cold_panics_hidden += 1;
                                emit = false;
                            } else {
                                cold_panics_shown += 1;
                            }
                        }
                        if emit {
                            findings.push(mk(
                                FindingKind::PanicRisk,
                                sev,
                                conf,
                                path,
                                line_num,
                                sym,
                                format!(
                                    "`{}` - panic path{}",
                                    pat.trim_end_matches('('),
                                    if in_hot {
                                        " on a latency-sensitive path"
                                    } else {
                                        ""
                                    }
                                ),
                                "determinism/reliability: a panic here takes the process down; \
                                 degrade gracefully instead - drop the message, not the link",
                            ));
                        }
                    }
                }
            }

            if in_async {
                if let Some(bc) = BLOCKING_CALLS.iter().find(|b| code.contains(**b)) {
                    findings.push(mk(
                        FindingKind::BlockingInAsync,
                        Severity::Medium,
                        0.7,
                        path,
                        line_num,
                        sym,
                        format!(
                            "blocking call `{}` inside async fn `{}`",
                            bc,
                            encl.map(|s| s.name.as_str()).unwrap_or("?")
                        ),
                        "latency/throughput: stalls the executor thread and starves \
                         every other task on it - use spawn_blocking, a dedicated \
                         thread, or an async equivalent",
                    ));
                }
                // A std Mutex held across `.await` is the subtler hazard, but the
                // dedicated `LockAcrossAwait` pass handles it precisely (and, unlike
                // this crude presence check, does not flag tokio's async
                // `.lock().await`, which is the correct pattern).
            }

            if in_hot {
                for pat in [
                    ".lock(",
                    ".read(",
                    ".write(",
                    ".lock_shared(",
                    ".write_arc(",
                ] {
                    if code.contains(pat)
                        && (code.contains("Mutex")
                            || code.contains("RwLock")
                            || code.contains(".lock(")
                            || code.contains("guard"))
                    {
                        findings.push(mk(
                            FindingKind::LockOnHotPath,
                            Severity::Low,
                            0.55,
                            path,
                            line_num,
                            sym,
                            format!(
                                "lock (`{}`) on latency-sensitive fn `{}`",
                                pat.trim_end_matches('('),
                                encl.map(|s| s.name.as_str()).unwrap_or("?")
                            ),
                            "latency/throughput: serializes the hot path under contention; \
                             consider a lock-free structure (atomics, an SPSC ring, \
                             crossbeam) or sharding the state",
                        ));
                        break;
                    }
                }
            }

            // `unbounded_channel()` (tokio), `unbounded::<>()`/`crossbeam...
            // ::unbounded()` are unbounded. std `mpsc::channel()` is unbounded
            // too, but tokio's `mpsc::channel(N)` is BOUNDED (N = capacity) -
            // distinguish by the empty argument list.
            let unbounded_label = if code.contains("mpsc::channel()") {
                Some("mpsc::channel")
            } else {
                [
                    "unbounded_channel(",
                    "unbounded::<",
                    "channel::unbounded(",
                    "crossbeam_channel::unbounded(",
                ]
                .into_iter()
                .find(|p| code.contains(p))
                .map(|p| p.trim_end_matches('('))
            };
            if let Some(label) = unbounded_label {
                findings.push(mk(
                    FindingKind::UnboundedChannel,
                    Severity::Medium,
                    0.7,
                    path,
                    line_num,
                    sym,
                    format!("unbounded channel (`{label}`)"),
                    "latency/memory: under load the queue grows without bound and \
                     buffers latency (helps raw throughput - the trade-off). For \
                     real-time media use a bounded channel with an explicit \
                     drop-oldest policy",
                ));
            }

            // Allocations flagged only inside latency-sensitive handlers;
            // line-based loop detection is too noisy to gate on.
            if in_hot && !is_test_file {
                if let Some(al) = hot_alloc(&code) {
                    findings.push(mk(
                        FindingKind::HotPathAllocation,
                        Severity::Info,
                        0.5,
                        path,
                        line_num,
                        sym,
                        format!("`{}` allocates on a latency-sensitive path", al),
                        "latency/throughput/memory: likely a per-message allocation; \
                         reuse a buffer pool, slice `bytes::Bytes` off one recv buffer, \
                         or use an arena",
                    ));
                }
            }
        }

        // One aggregate finding stands in for the cold panics past the cap, so
        // the tally is visible without one line-item per `.unwrap()`.
        if cold_panics_hidden > 0 {
            findings.push(mk(
                FindingKind::PanicRisk,
                Severity::Info,
                0.6,
                path,
                1,
                None,
                format!(
                    "{} more panic path(s) in this file (unwrap/expect/panic!) beyond the first {}",
                    cold_panics_hidden, COLD_PANIC_CAP
                ),
                "determinism/reliability: audit these individually - degrade instead of \
                 panicking on any path that can run in production",
            ));
        }

        if !is_test_file {
            scan_lock_across_await(&lines, &spans, &mut findings, path);
        }

        // Drop this file's findings that landed inside inline #[cfg(test)] items.
        if !test_ranges.is_empty() {
            let tail: Vec<Finding> = findings.split_off(file_start);
            findings.extend(tail.into_iter().filter(|f| {
                !test_ranges
                    .iter()
                    .any(|(a, b)| f.line_start >= *a && f.line_start <= *b)
            }));
        }
    }

    findings.sort_by(|a, b| (&a.file, a.line_start).cmp(&(&b.file, b.line_start)));
    findings
}

/// Line ranges (1-indexed, inclusive) covered by an inline `#[cfg(test)]` item
/// (a `mod tests { ... }` or a `#[cfg(test)] fn`). Findings inside these are test
/// scaffolding, not production code, and are excluded. Brace-tracked from the
/// item's opening `{` to its matching close; string/char literals aren't parsed
/// but test modules don't put unbalanced braces in strings in practice.
pub(crate) fn cfg_test_ranges(lines: &[String]) -> Vec<(u32, u32)> {
    let mut ranges = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim_start().starts_with("#[cfg(test)]") {
            // First `{` at or after the attribute opens the item body.
            let mut j = i;
            while j < lines.len() && !lines[j].contains('{') {
                j += 1;
            }
            if j >= lines.len() {
                break;
            }
            let mut depth = 0i32;
            let start = (i + 1) as u32;
            let mut k = j;
            let mut end = j;
            'outer: while k < lines.len() {
                for c in lines[k].chars() {
                    if c == '{' {
                        depth += 1;
                    } else if c == '}' {
                        depth -= 1;
                        if depth == 0 {
                            end = k;
                            break 'outer;
                        }
                    }
                }
                k += 1;
            }
            ranges.push((start, (end + 1) as u32));
            i = end + 1;
        } else {
            i += 1;
        }
    }
    ranges
}

/// True if a `// SAFETY:` (or `// Safety:`) comment sits on the `unsafe` line
/// itself or within the three lines above it - where the convention places the
/// justification. Case-insensitive on the marker word.
fn has_safety_comment(lines: &[String], unsafe_idx: usize) -> bool {
    let start = unsafe_idx.saturating_sub(3);
    lines[start..=unsafe_idx].iter().any(|l| {
        let lc = l.to_ascii_lowercase();
        lc.contains("safety:") || lc.contains("// safety")
    })
}

/// Detect an allocating construct on a line, returning the token for the message.
fn hot_alloc(code: &str) -> Option<&'static str> {
    const ALLOCS: &[&str] = &[
        "Vec::new(",
        "vec![",
        "Box::new(",
        ".to_vec(",
        ".to_string(",
        "String::from(",
        "String::new(",
        "format!(",
        ".collect::<Vec",
        ".clone(",
        "Vec::with_capacity(",
    ];
    ALLOCS.iter().find(|a| code.contains(**a)).copied()
}

/// A lock/cell guard held across an `.await` in an async fn - the classic
/// deadlock / `!Send`-future bug. Brace-depth scoped: a guard whose block closes
/// before the await doesn't count, and an explicit `drop(g)` clears it. Only
/// `let`-bound guards are tracked (a temporary is dropped at end of statement,
/// so it can't span an await).
fn scan_lock_across_await(
    lines: &[String],
    spans: &[FnSpan],
    findings: &mut Vec<Finding>,
    path: &Path,
) {
    for span in spans.iter().filter(|s| s.is_async) {
        let start = (span.start.max(1) as usize) - 1;
        let end = (span.end as usize).min(lines.len());
        if start >= end {
            continue;
        }
        let mut depth: i32 = 0;
        // (guard name, declaration depth, declaration line)
        let mut live: Vec<(String, i32, u32)> = Vec::new();
        for (idx, line) in lines[start..end].iter().enumerate() {
            let line_num = (start + idx + 1) as u32;
            let code = strip_line_comment(line);

            if code.contains(".await") && !live.is_empty() {
                for (name, _, decl_line) in &live {
                    findings.push(mk(
                        FindingKind::LockAcrossAwait,
                        Severity::Medium,
                        0.7,
                        path,
                        line_num,
                        None,
                        format!("lock guard `{name}` (from line {decl_line}) held across `.await`"),
                        "deadlock / !Send: the task can suspend here and resume on another \
                         thread while holding the guard - drop it before awaiting, or scope it \
                         in a `{ ... }` block that closes before the await",
                    ));
                }
                // One finding per guard: a fn with many awaits shouldn't emit
                // the same hazard once per await.
                live.clear();
            }
            if code.contains("drop(") {
                live.retain(|(name, _, _)| !code.contains(&format!("drop({name}")));
            }
            if let Some(name) = guard_binding(&code) {
                live.push((name, depth, line_num));
            }
            depth += code.matches('{').count() as i32 - code.matches('}').count() as i32;
            live.retain(|(_, decl_depth, _)| *decl_depth <= depth);
        }
    }
}

/// If `code` is `let [mut] NAME = <expr producing a *sync* lock/cell guard>;`,
/// return NAME. Only sync guards are hazardous across await: `.lock()`
/// (std/parking_lot Mutex) and `RefCell::borrow[_mut]`. tokio's async locks
/// (`.lock().await`, `.read().await`, `.write().await`) are *designed* to be
/// held across await, so they're deliberately excluded.
fn guard_binding(code: &str) -> Option<String> {
    let rest = code.trim_start().strip_prefix("let ")?;
    let rest = rest.strip_prefix("mut ").unwrap_or(rest);
    let eq = rest.find('=')?;
    let name = rest[..eq].trim();
    if name.is_empty() || name == "_" || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return None;
    }
    let rhs = rest[eq + 1..].trim().trim_end_matches(';').trim();
    // The binding must actually BE the guard. `x = m.lock().idle.pop()` binds
    // the pop result - the guard is a temporary dropped at statement end and
    // never spans the await. So after the lock call only guard-preserving tails
    // are allowed: nothing, `?`, `.unwrap()`, `.expect(...)`.
    for call in [".lock()", ".borrow_mut()", ".borrow()"] {
        let Some(pos) = rhs.find(call) else { continue };
        let after = rhs[pos + call.len()..].trim();
        // tokio async lock - designed to be held across await.
        if after.starts_with(".await") {
            return None;
        }
        let after = after.strip_suffix('?').unwrap_or(after).trim();
        let is_the_guard = after.is_empty()
            || after == ".unwrap()"
            || (after.starts_with(".expect(") && after.ends_with(')'));
        return is_the_guard.then(|| name.to_string());
    }
    None
}

fn strip_line_comment(line: &str) -> String {
    match line.find("//") {
        Some(pos) => line[..pos].to_string(),
        None => line.to_string(),
    }
}

/// True if `word` appears as a whole identifier token in `code`.
fn contains_word(code: &str, word: &str) -> bool {
    let mut from = 0;
    while let Some(pos) = code[from..].find(word) {
        let abs = from + pos;
        let end = abs + word.len();
        let prev_ok = code[..abs]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_');
        let next_ok = code[end..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_');
        if prev_ok && next_ok {
            return true;
        }
        from = end;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_boundary() {
        assert!(contains_word("let x = unsafe { 1 };", "unsafe"));
        assert!(!contains_word("let unsafely = 1;", "unsafe"));
    }

    #[test]
    fn hot_alloc_detects() {
        assert_eq!(hot_alloc("let v = Vec::new();"), Some("Vec::new("));
        assert_eq!(hot_alloc("let y = x.clone();"), Some(".clone("));
        assert_eq!(hot_alloc("let z = x + 1;"), None);
    }

    #[test]
    fn safety_comment_detection() {
        let lines: Vec<String> = vec![
            "// SAFETY: ptr is valid for len bytes".into(),
            "unsafe { std::slice::from_raw_parts(ptr, len) }".into(),
        ];
        assert!(has_safety_comment(&lines, 1));

        let undocumented: Vec<String> = vec!["let x = compute();".into(), "unsafe { *ptr }".into()];
        assert!(!has_safety_comment(&undocumented, 1));
    }
}
