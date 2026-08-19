use regex::Regex;

use verum_nucleus::{Finding, FindingKind, Ir, Severity};

pub fn analyse(ir: &Ir) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(detect_n_plus_one(ir));
    findings.extend(detect_missing_hook_deps(ir));
    findings
}

/// Probable N+1: a Fractal transformer / Laravel resource that accesses
/// relationship-like properties inside transform()/toArray()/toResponse()
/// while the file never eager-loads with `->with([`.
fn detect_n_plus_one(ir: &Ir) -> Vec<Finding> {
    let mut findings = Vec::new();

    // $anything->something - potential lazy relationship load.
    let rel_access_re = Regex::new(r"\$\w+->\w+").expect("valid regex");

    let with_re = Regex::new(r"->with\s*\(\s*\[").expect("valid regex");

    let transform_method_re =
        Regex::new(r"(?:public\s+)?function\s+(?:transform|toArray|toResponse)\s*\(")
            .expect("valid regex");

    for path in ir.files.keys() {
        let path_str = path.to_string_lossy();

        if !path_str.ends_with(".php") {
            continue;
        }

        // Path filter first; the base-class check below is the real guard.
        let path_relevant = path_str.contains("Transformer")
            || path_str.contains("Resource")
            || path_str.contains("Presenter");
        if !path_relevant {
            continue;
        }

        if path_str.contains("vendor/") || path_str.contains("node_modules/") {
            continue;
        }

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let is_transformer = content.contains("TransformerAbstract")
            || content.contains("JsonResource")
            || content.contains("Fractal");
        if !is_transformer {
            continue;
        }

        let has_eager_load = with_re.is_match(&content);

        // PHP usually puts the opening `{` on the line after the signature, so
        // this runs as a small state machine: find the signature, wait for the
        // `{`, then count accesses until the body's braces close.
        let mut in_method = false;
        let mut body_entered = false;
        let mut brace_depth: i32 = 0;
        let mut method_start_line: u32 = 0;
        let mut rel_accesses_in_method: u32 = 0;

        for (idx, line) in content.lines().enumerate() {
            let line_num = (idx + 1) as u32;

            if !in_method && transform_method_re.is_match(line) {
                in_method = true;
                body_entered = false;
                method_start_line = line_num;
                brace_depth = 0;
                rel_accesses_in_method = 0;
            }

            if in_method {
                let open_count = line.chars().filter(|&c| c == '{').count() as i32;
                let close_count = line.chars().filter(|&c| c == '}').count() as i32;

                if !body_entered && open_count > 0 {
                    body_entered = true;
                }

                brace_depth += open_count;
                brace_depth -= close_count;

                if body_entered && brace_depth > 0 {
                    rel_accesses_in_method += rel_access_re.find_iter(line).count() as u32;
                }

                if body_entered && brace_depth <= 0 {
                    if rel_accesses_in_method > 0 && !has_eager_load {
                        findings.push(Finding {
                            id: format!("perf-nplusone-{}:{}", path.display(), method_start_line),
                            kind: FindingKind::NPlusOneQuery,
                            severity: Severity::Medium,
                            confidence: 0.65,
                            file: path.clone(),
                            line_start: method_start_line,
                            line_end: line_num,
                            symbol: None,
                            message: format!(
                                "Possible N+1 query: {} relationship accessor(s) in \
                                 transform/toArray without visible eager-loading (`->with([...])`)",
                                rel_accesses_in_method
                            ),
                            suggestion: "Add `->with([...])` when fetching the collection so \
                                         relationships are loaded in bulk, not per-row"
                                .to_string(),
                            auto_fixable: false,
                            related: Vec::new(),
                        });
                    }
                    in_method = false;
                    body_entered = false;
                }
            }
        }
    }

    findings
}

/// `useEffect`/`useCallback`/`useMemo` without a dependency array re-run on
/// every render.
fn detect_missing_hook_deps(ir: &Ir) -> Vec<Finding> {
    let mut findings = Vec::new();

    for path in ir.files.keys() {
        let path_str = path.to_string_lossy();

        let is_js_ts = path_str.ends_with(".js")
            || path_str.ends_with(".jsx")
            || path_str.ends_with(".ts")
            || path_str.ends_with(".tsx");
        if !is_js_ts {
            continue;
        }
        if path_str.contains("node_modules/") || path_str.contains("vendor/") {
            continue;
        }

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        if !content.contains("useEffect")
            && !content.contains("useCallback")
            && !content.contains("useMemo")
        {
            continue;
        }

        scan_hooks_without_deps(&content, path, &mut findings);
    }

    findings
}

/// Byte-level paren-balancing walk so multi-line hook calls work. Commas at
/// call depth 1 separate arguments; a `[` after the first such comma is taken
/// as the dep array.
fn scan_hooks_without_deps(content: &str, path: &std::path::Path, findings: &mut Vec<Finding>) {
    const HOOKS: &[&str] = &["useEffect", "useCallback", "useMemo"];

    let bytes = content.as_bytes();
    let len = bytes.len();

    // Pre-compute line-start byte offsets for O(log n) line-number lookup.
    let mut line_starts: Vec<usize> = vec![0];
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\n' && i + 1 < len {
            line_starts.push(i + 1);
        }
    }

    let byte_to_line = |pos: usize| -> u32 {
        match line_starts.binary_search(&pos) {
            Ok(idx) => (idx + 1) as u32,
            Err(idx) => idx as u32,
        }
    };

    /// True if a `//` appears earlier on the same line.
    fn in_comment(bytes: &[u8], pos: usize) -> bool {
        let line_start = bytes[..pos]
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |p| p + 1);
        let line = &bytes[line_start..pos];
        line.windows(2).any(|w| w == b"//")
    }

    for hook in HOOKS {
        let hbytes = hook.as_bytes();
        let hlen = hbytes.len();

        let mut pos = 0usize;

        while pos + hlen < len {
            if bytes[pos..].get(..hlen) != Some(hbytes) {
                pos += 1;
                continue;
            }

            // Not part of a longer identifier.
            let prev_ok = pos == 0 || {
                let pb = bytes[pos - 1];
                !pb.is_ascii_alphanumeric() && pb != b'_' && pb != b'$'
            };
            let next_pos = pos + hlen;
            let next_ok = next_pos >= len || {
                let nb = bytes[next_pos];
                !nb.is_ascii_alphanumeric() && nb != b'_' && nb != b'$'
            };

            if !prev_ok || !next_ok {
                pos += 1;
                continue;
            }

            let mut after = next_pos;
            while after < len && bytes[after] == b' ' {
                after += 1;
            }

            if after >= len || bytes[after] != b'(' {
                pos += 1;
                continue;
            }

            if in_comment(bytes, pos) {
                pos += 1;
                continue;
            }

            let hook_line = byte_to_line(pos);
            let call_open = after; // index of `(`

            let mut depth: i32 = 0;
            let mut comma_depth1: u32 = 0; // commas seen at depth 1
            let mut has_dep_array = false;
            let mut i = call_open;

            while i < len {
                match bytes[i] {
                    b'\'' => {
                        i += 1;
                        while i < len && bytes[i] != b'\'' {
                            if bytes[i] == b'\\' {
                                i += 1;
                            }
                            i += 1;
                        }
                        i += 1;
                    }
                    b'"' => {
                        i += 1;
                        while i < len && bytes[i] != b'"' {
                            if bytes[i] == b'\\' {
                                i += 1;
                            }
                            i += 1;
                        }
                        i += 1;
                    }
                    b'`' => {
                        i += 1;
                        while i < len && bytes[i] != b'`' {
                            if bytes[i] == b'\\' {
                                i += 1;
                            }
                            i += 1;
                        }
                        i += 1;
                    }
                    b'(' => {
                        depth += 1;
                        i += 1;
                    }
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                        i += 1;
                    }
                    b',' if depth == 1 => {
                        comma_depth1 += 1;
                        i += 1;
                    }
                    b'[' if depth == 1 && comma_depth1 >= 1 => {
                        // `[` at argument level after a comma: the dep array.
                        has_dep_array = true;
                        i += 1;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }

            if !has_dep_array {
                findings.push(Finding {
                    id: format!("perf-hookdeps-{}:{}", path.display(), hook_line),
                    kind: FindingKind::MissingHookDependencies,
                    severity: Severity::Low,
                    confidence: 0.80,
                    file: path.to_path_buf(),
                    line_start: hook_line,
                    line_end: hook_line,
                    symbol: None,
                    message: format!(
                        "`{}` called without a dependency array - runs on every render",
                        hook
                    ),
                    suggestion: "Add a dependency array as the second argument: \
                         `[]` to run once on mount, or `[dep1, dep2]` for specific deps"
                        .to_string(),
                    auto_fixable: false,
                    related: Vec::new(),
                });
            }

            pos = if i > call_open { i + 1 } else { pos + 1 };
        }
    }
}
