use std::io::BufRead;

use rayon::prelude::*;
use regex::Regex;

use verum_nucleus::{Finding, FindingKind, Ir, Severity, TaintSink};

use crate::SecurityConfig;

/// Contexts where md5/sha1 is fine (cache keys, etags, checksums, gravatar).
const BENIGN_CONTEXT_PATTERNS: &[&str] = &[
    "cache",
    "etag",
    "e_tag",
    "gravatar",
    "avatar",
    "hash_file",
    "checksum",
    "fingerprint",
    "content_hash",
    "file_hash",
    "asset",
    "version",
    "unique",
    "identifier",
    "uuid",
    "slug",
    "key(",
    "Cache::",
    "cache(",
    "crc",
    "digest",
    "ETag",
];

/// Contexts where weak crypto is genuinely dangerous.
const SENSITIVE_CONTEXT_PATTERNS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "auth",
    "credential",
    "session",
    "encrypt",
    "decrypt",
    "sign",
    "verify",
    "hmac",
    "certificate",
];

/// True when the quoted value can't be a credential: a status/label word
/// (`"configured"`), or a human message (`"[REDACTED - see logs]"`). Real
/// secrets are single tokens - they never contain spaces - so a value with
/// whitespace is prose, not a key.
fn quoted_value_is_status_word(line: &str) -> bool {
    const STATUS_WORDS: &[&str] = &[
        "configured",
        "unconfigured",
        "enabled",
        "disabled",
        "unset",
        "none",
        "null",
        "empty",
        "missing",
        "present",
        "set",
        "active",
        "inactive",
        "redacted",
        "hidden",
        "todo",
        "tbd",
        "yes",
        "no",
        "on",
        "off",
        "true",
        "false",
        "required",
        "optional",
        "loading",
        "pending",
        "ready",
        "unknown",
    ];
    let after = match line.split_once([':', '=']) {
        Some((_, rhs)) => rhs,
        None => return false,
    };
    if let Some(start) = after.find(['\'', '"']) {
        let quote = after.as_bytes()[start] as char;
        let rest = &after[start + 1..];
        if let Some(end) = rest.find(quote) {
            let value = &rest[..end];
            return value.contains(' ') || STATUS_WORDS.contains(&value.to_lowercase().as_str());
        }
    }
    false
}

/// True when the first quoted literal after `=` looks like a stable identifier
/// (permission ability, config/route key, enum value) rather than a credential:
/// all-lowercase, only `[a-z0-9._-]`, and carries a separator - low entropy, no
/// mixed case or symbols.
/// A quoted value carrying interpolation or format placeholders (`{name}`,
/// `${x}`, `%s`, `<...>`) is a template that produces a secret at runtime, or an
/// editor tokenizer pattern - not a hardcoded credential.
fn quoted_value_is_template(line: &str) -> bool {
    let after = match line.find(['=', ':']) {
        Some(i) => &line[i + 1..],
        None => return false,
    };
    let value = match after.find(['\'', '"']) {
        Some(start) => {
            let quote = after.as_bytes()[start] as char;
            let rest = &after[start + 1..];
            match rest.find(quote) {
                Some(end) => &rest[..end],
                None => return false,
            }
        }
        None => return false,
    };
    value.contains('{') || value.contains('$') || value.contains('%') || value.contains('<')
}

fn quoted_value_is_identifier_like(line: &str) -> bool {
    let after_eq = match line.split_once('=') {
        Some((_, rhs)) => rhs,
        None => return false,
    };
    // Vendor key prefixes are credentials no matter how they're cased.
    const CREDENTIAL_PREFIXES: &[&str] = &[
        "sk-",
        "sk_",
        "pk_",
        "rk_",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "github_pat_",
        "xoxb-",
        "xoxp-",
        "xoxa-",
        "glpat-",
        "akia",
        "asia",
        "aiza",
        "ya29.",
        "sq0",
        "eyj", // JWT header
    ];
    let value = match after_eq.find(['\'', '"']) {
        Some(start) => {
            let quote = after_eq.as_bytes()[start] as char;
            let rest = &after_eq[start + 1..];
            match rest.find(quote) {
                Some(end) => &rest[..end],
                None => return false,
            }
        }
        None => return false,
    };

    if value.len() < 3 {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    if CREDENTIAL_PREFIXES.iter().any(|p| lower.starts_with(p)) {
        return false;
    }
    // A run of 5+ consecutive digits is entropy, not vocabulary.
    let mut digit_run = 0usize;
    for c in value.chars() {
        if c.is_ascii_digit() {
            digit_run += 1;
            if digit_run >= 5 {
                return false;
            }
        } else {
            digit_run = 0;
        }
    }
    let has_separator = value.contains('.') || value.contains('_') || value.contains('-');
    let only_identifier_chars = value
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'));
    has_separator && only_identifier_chars
}

/// True when the line is comment-only (`//`, `*`, `#` after leading whitespace).
/// Comment lines never produce pattern findings.
fn is_comment_line(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with('#')
}

/// True when `pattern` occurs in `line` at a word start (the preceding char is
/// not part of an identifier). Kills `retrieval(` / `medieval(` matching `eval(`.
fn contains_at_word_start(line: &str, pattern: &str) -> bool {
    let mut from = 0;
    while let Some(pos) = line[from..].find(pattern) {
        let abs = from + pos;
        let prev = line[..abs].chars().next_back();
        let is_word_char = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$';
        if prev.is_none_or(|c| !is_word_char(c)) {
            return true;
        }
        from = abs + pattern.len();
    }
    false
}

/// Severity of a weak-crypto hit based on surrounding context on the line.
/// Info means "don't flag".
fn classify_weak_crypto_severity(line: &str) -> Severity {
    let lower = line.to_lowercase();

    for pattern in SENSITIVE_CONTEXT_PATTERNS {
        if lower.contains(pattern) {
            return Severity::Critical;
        }
    }

    for pattern in BENIGN_CONTEXT_PATTERNS {
        if lower.contains(&pattern.to_lowercase()) {
            return Severity::Info;
        }
    }

    if lower.contains("$cache")
        || lower.contains("$etag")
        || lower.contains("$hash")
        || lower.contains("$key")
        || lower.contains("$id")
        || lower.contains("$fingerprint")
    {
        return Severity::Info;
    }

    // Benign idioms the keyword lists miss: gravatar hashing
    // (`md5(strtolower($email))`), a member/key literally named `md5`, or
    // hashing a record id into a stable front-end key.
    if (lower.contains("md5(") && lower.contains("strtolower"))
        || lower.contains("->md5")
        || lower.contains("'md5'")
        || lower.contains("\"md5\"")
        || lower.contains("md5 =>")
        || lower.contains("->id")
        || lower.contains("'id' =>")
        || lower.contains("\"id\" =>")
    {
        return Severity::Info;
    }

    if is_comment_line(line) {
        return Severity::Info;
    }

    // Could be security-relevant; leave for review.
    Severity::Medium
}

/// Pattern-based scan of file contents plus taint-path findings.
pub fn analyse(ir: &Ir, config: &SecurityConfig) -> Vec<Finding> {
    let mut findings = Vec::new();

    // `[:=]` covers PHP/Go/Rust assignments, JS object literals, Python dicts
    // and YAML; a trailing semicolon is deliberately not required.
    let secret_re = Regex::new(
        r#"(?i)(password|passwd|secret|api[_-]?key|token|access[_-]?key|private[_-]?key)\s*[:=]\s*['"][^'"]{8,}['"]"#,
    )
    .expect("valid regex");

    let always_forbid: Vec<&str> = config
        .forbid_weak_crypto
        .iter()
        .map(|s| s.as_str())
        .collect();
    // `name(` call patterns, built once instead of per scanned line.
    let forbid_patterns: Vec<(&str, String)> = always_forbid
        .iter()
        .filter(|f| **f != "md5" && **f != "sha1")
        .map(|f| (*f, format!("{}(", f)))
        .collect();
    const WEAK_FUNCS: &[(&str, &str)] = &[("md5", "md5("), ("sha1", "sha1(")];

    // Deterministic parallel scan: files are sorted, scanned independently,
    // and their results flattened in file order so the output sequence never
    // depends on thread scheduling.
    let mut files: Vec<(&std::path::PathBuf, &verum_nucleus::FileInfo)> = ir.files.iter().collect();
    files.sort_by_key(|(p, _)| *p);

    let per_file: Vec<Vec<Finding>> = files
        .par_iter()
        .map(|(path, file_info)| {
            let mut findings: Vec<Finding> = Vec::new();
            let path = *path;
            // `md5()`/`sha1()`/`eval()` are callable in these languages only.
            // In Rust or Go source those byte sequences can only be data (string
            // literals, pattern tables) - flagging them is pure noise.
            let dynamic_lang = matches!(
                file_info.language,
                verum_nucleus::Language::Php
                    | verum_nucleus::Language::JavaScript
                    | verum_nucleus::Language::TypeScript
                    | verum_nucleus::Language::Python
            );

            let path_str = path.to_string_lossy();

            // Vendored code, compiled views and Blade templates are full of display
            // hashes and generated markup - pure false-positive territory. Test and
            // benchmark corpora are third-party sample *data* (e.g. a numpy file
            // used as a syntax-highlighting benchmark) - a real `eval` there is the
            // sample's, not the project's, and flagging it is noise. Checked
            // before the read: no point loading a file just to skip it.
            if path_str.contains("vendor/")
                || path_str.contains("node_modules/")
                || path_str.contains("storage/framework/")
                || path_str.contains("/benchmarks/")
                || path_str.contains("/testdata/")
                || path_str.contains("/test-data/")
                || path_str.contains("/corpus/")
                || path_str.ends_with(".blade.php")
                // Test setups carry throwaway fixture credentials (`minioadmin`,
                // `test-secret`) - expected, not leaks. Fixtures are analysis
                // targets (Verum's own recall suite), so they're never skipped.
                || (!path_str.contains("fixtures")
                    && (path_str.contains("/tests/") || path_str.ends_with("_test.rs")))
            {
                return findings;
            }

            let content = match std::fs::read(path) {
                Ok(c) => c,
                Err(_) => return findings,
            };

            for (line_idx, line_result) in content.lines().enumerate() {
                let line = match line_result {
                    Ok(l) => l,
                    Err(_) => continue,
                };
                let line_num = (line_idx + 1) as u32;

                // md5 and sha1 are checked independently so a line containing both
                // reports both.
                let weak_funcs: &[(&str, &str)] = if dynamic_lang { WEAK_FUNCS } else { &[] };
                for &(func, pattern) in weak_funcs {
                    if !contains_at_word_start(&line, pattern) {
                        continue;
                    }

                    // Comment-only lines never flag, even when the function is on
                    // the forbid list (`// TODO: replace md5($pw)` is not a call).
                    if is_comment_line(&line) {
                        continue;
                    }

                    // Allowlisted context for this function (e.g. md5 for etags):
                    // skip the finding entirely when the line mentions any of the
                    // allowed context keywords.
                    if let Some(contexts) = config.weak_crypto_allowlist.get(func) {
                        let line_lower = line.to_lowercase();
                        if contexts
                            .iter()
                            .any(|ctx| line_lower.contains(&ctx.to_lowercase()))
                        {
                            continue;
                        }
                    }

                    let is_always_forbidden = always_forbid.contains(&func);

                    let severity = if is_always_forbidden {
                        Severity::Critical
                    } else {
                        classify_weak_crypto_severity(&line)
                    };

                    // Info = benign context, don't flag.
                    if severity == Severity::Info {
                        continue;
                    }

                    let suggestion = if severity == Severity::Critical {
                        "Use password_hash() with PASSWORD_ARGON2ID or bcrypt instead".to_string()
                    } else {
                        format!(
                            "Review: `{}()` detected - if used for security purposes, \
                         switch to a stronger algorithm",
                            func
                        )
                    };

                    let confidence = match severity {
                        Severity::Critical => 0.95,
                        Severity::High => 0.80,
                        Severity::Medium => 0.60,
                        _ => 0.40,
                    };

                    findings.push(Finding {
                        id: format!("sec-weakcrypto-{}-{}:{}", func, path.display(), line_num),
                        kind: FindingKind::WeakCrypto,
                        severity,
                        confidence,
                        file: path.clone(),
                        line_start: line_num,
                        line_end: line_num,
                        symbol: None,
                        message: format!("Weak cryptographic function `{}()` detected", func),
                        suggestion,
                        auto_fixable: false,
                        related: Vec::new(),
                    });
                }

                // Other always-forbidden crypto (des, rc4, ...). Word-boundary check
                // so "des(" inside "includes(" doesn't match.
                for (forbidden, pattern) in forbid_patterns.iter().filter(|_| dynamic_lang) {
                    if is_comment_line(&line) {
                        break;
                    }
                    {
                        if let Some(pos) = line.find(pattern.as_str()) {
                            let is_word_start = pos == 0
                                || !line.as_bytes()[pos - 1].is_ascii_alphanumeric()
                                    && line.as_bytes()[pos - 1] != b'_';
                            if is_word_start {
                                findings.push(Finding {
                                    id: format!(
                                        "sec-forbidden-{}-{}:{}",
                                        forbidden,
                                        path.display(),
                                        line_num
                                    ),
                                    kind: FindingKind::WeakCrypto,
                                    severity: Severity::Critical,
                                    confidence: 0.95,
                                    file: path.clone(),
                                    line_start: line_num,
                                    line_end: line_num,
                                    symbol: None,
                                    message: format!(
                                        "Forbidden cryptographic function `{}()` detected",
                                        forbidden
                                    ),
                                    suggestion: "Use a modern cryptographic algorithm".to_string(),
                                    auto_fixable: false,
                                    related: Vec::new(),
                                });
                            }
                        }
                    }
                }

                if dynamic_lang && contains_at_word_start(&line, "eval(") {
                    if is_comment_line(&line) {
                        continue;
                    }

                    findings.push(Finding {
                        id: format!("sec-eval-{}:{}", path.display(), line_num),
                        kind: FindingKind::EvalUsage,
                        severity: Severity::Critical,
                        confidence: 0.99,
                        file: path.clone(),
                        line_start: line_num,
                        line_end: line_num,
                        symbol: None,
                        message: "eval() usage detected - potential code injection".to_string(),
                        suggestion: "Remove eval() and use a safe alternative".to_string(),
                        auto_fixable: false,
                        related: Vec::new(),
                    });
                }

                if secret_re.is_match(&line) {
                    if is_comment_line(&line) {
                        continue;
                    }

                    // Permission constants and example/placeholder values.
                    let lower = line.to_lowercase();
                    if lower.contains("permission")
                        || lower.contains("example")
                        || lower.contains("placeholder")
                        || lower.contains("default")
                        || lower.contains("::class")
                    {
                        continue;
                    }

                    // Identifier-like literals (permission keys, config/route names)
                    // such as `= 'database.view_password'` aren't credentials.
                    if quoted_value_is_identifier_like(&line) {
                        continue;
                    }

                    // Status/label strings that match the key pattern but report
                    // state rather than a value - `jwt_secret = "configured"`.
                    if quoted_value_is_status_word(&line) {
                        continue;
                    }

                    // Templates / interpolated values (`ADMIN_TOKEN='{hash}'`,
                    // `"${x}"`, `%s`) emit a secret at runtime or are editor
                    // tokenizer patterns, not literal credentials.
                    if quoted_value_is_template(&line) {
                        continue;
                    }

                    findings.push(Finding {
                        id: format!("sec-secret-{}:{}", path.display(), line_num),
                        kind: FindingKind::HardcodedSecret,
                        severity: Severity::Critical,
                        confidence: 0.80,
                        file: path.clone(),
                        line_start: line_num,
                        line_end: line_num,
                        symbol: None,
                        message: "Hardcoded secret detected".to_string(),
                        suggestion: "Move secrets to environment variables or a secrets manager"
                            .to_string(),
                        auto_fixable: false,
                        related: Vec::new(),
                    });
                }
            }
            findings
        })
        .collect();
    for file_findings in per_file {
        findings.extend(file_findings);
    }

    for taint in &ir.taint_paths {
        if taint.sanitized {
            continue;
        }

        let (kind, message) = match &taint.sink {
            TaintSink::SqlQuery => (
                FindingKind::SqlInjection,
                "Unsanitized user input flows to SQL query".to_string(),
            ),
            TaintSink::HtmlOutput => (
                FindingKind::XssVulnerability,
                "Unsanitized user input flows to HTML output".to_string(),
            ),
            TaintSink::CommandExec => (
                FindingKind::EvalUsage,
                "Unsanitized user input flows to command execution".to_string(),
            ),
            TaintSink::EvalExec => (
                FindingKind::EvalUsage,
                "Unsanitized user input flows to eval".to_string(),
            ),
            _ => continue,
        };

        findings.push(Finding {
            id: format!(
                "sec-taint-{}:{}",
                taint.sink_file.display(),
                taint.sink_line
            ),
            kind,
            severity: Severity::Critical,
            confidence: 0.90,
            file: taint.sink_file.clone(),
            line_start: taint.sink_line,
            line_end: taint.sink_line,
            symbol: None,
            message,
            suggestion: "Sanitize or validate user input before use".to_string(),
            auto_fixable: false,
            related: taint
                .hops
                .iter()
                .map(|hop| verum_nucleus::Location {
                    file: hop.file.clone(),
                    line: hop.line,
                    description: format!("Taint flows through: {:?}", hop.transforms),
                })
                .collect(),
        });
    }

    findings
}
