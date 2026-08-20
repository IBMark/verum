//! Application-security line scan for Python, JavaScript, and TypeScript -
//! the languages where the classic security pass (`security.rs`, PHP-first)
//! historically under-fired.
//!
//! Detectors, all local and syntactic, all tuned for near-zero false
//! positives over recall:
//! - [`FindingKind::HardcodedSecret`]: provider-shaped token literals
//!   (`sk_live_`, `AKIA`, `ghp_`, `github_pat_`, `xoxb-`/`xoxp-`, `glpat-`,
//!   PEM private-key blocks with key material) regardless of the variable
//!   name. Name-based secret assignments are the older pass's job; this one
//!   catches `const stripe = "sk_live_..."` where the name says nothing.
//! - [`FindingKind::WeakCrypto`]: `crypto.createHash('md5'|'sha1')` on a
//!   line whose identifiers say password/token/secret/auth - cache keys and
//!   etags stay silent because the sensitive-word signal is required, never
//!   inferred.
//! - [`FindingKind::WeakRandom`]: `Math.random()` / `random.random()` and
//!   friends feeding a value whose name says secret/token/password/otp.
//! - [`FindingKind::TlsVerificationDisabled`]: `rejectUnauthorized: false`,
//!   `NODE_TLS_REJECT_UNAUTHORIZED=0`, `verify=False` on an HTTP client
//!   call, `ssl._create_unverified_context`, `verify_mode = ssl.CERT_NONE`.
//! - [`FindingKind::UnsafeDeserialization`]: `pickle.load(s)` on a
//!   non-literal, `yaml.load` without a safe loader, `new Function` built
//!   from non-literal text.
//! - [`FindingKind::EvalUsage`]: bare Python `exec(` on a non-literal
//!   argument (method calls like PyQt's `dialog.exec()` are excluded).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use rayon::prelude::*;
use regex::Regex;

use verum_nucleus::{matchable_path, Finding, FindingKind, Ir, Language, Severity};

/// Identifier words that mark a line as handling a security value. Matched
/// against camel/snake-split word components, never substrings, so `tokens`
/// (a parser's) does not match `token` and `saltwater` does not match `salt`.
const SENSITIVE_VALUE_WORDS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "otp",
    "csrf",
    "nonce",
    "salt",
    "credential",
    "auth",
];

/// Provider-shaped credential patterns: distinctive prefixes with enough
/// mandatory entropy tail that prose, identifiers, and short placeholders
/// cannot match. Each entry is (regex, provider label).
fn provider_token_patterns() -> &'static [(Regex, &'static str)] {
    static PATTERNS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            // Stripe live secret/restricted keys. Test keys (`sk_test_`) are
            // still credentials but are the standard fixture placeholder, so
            // only live-mode keys are flagged.
            (r"\bsk_live_[0-9a-zA-Z]{16,}", "Stripe live secret key"),
            (r"\brk_live_[0-9a-zA-Z]{16,}", "Stripe live restricted key"),
            (r"\bAKIA[0-9A-Z]{16}\b", "AWS access key id"),
            (r"\bghp_[0-9A-Za-z]{36}\b", "GitHub personal access token"),
            (
                r"\bgithub_pat_[0-9A-Za-z_]{36,}",
                "GitHub fine-grained token",
            ),
            (r"\bxox[bp]-[0-9A-Za-z]{8,}[0-9A-Za-z-]*", "Slack token"),
            (
                r"\bglpat-[0-9A-Za-z_-]{20,}",
                "GitLab personal access token",
            ),
        ]
        .into_iter()
        .map(|(re, label)| (Regex::new(re).expect("valid regex"), label))
        .collect()
    })
}

fn tls_reject_unauthorized_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"rejectUnauthorized\s*[:=]\s*false").expect("valid regex"))
}

fn node_tls_env_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"NODE_TLS_REJECT_UNAUTHORIZED\S*\s*\]?\s*=\s*['"]?0['"]?"#)
            .expect("valid regex")
    })
}

fn python_verify_false_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bverify\s*=\s*False\b").expect("valid regex"))
}

/// Reads every file itself; prefer [`analyse_with_context`] when a pre-read
/// [`ScanContext`](crate::scan::ScanContext) is already available.
pub fn analyse(ir: &Ir) -> Vec<Finding> {
    analyse_with_context(ir, &crate::scan::ScanContext::index_only(ir))
}

/// Detector run over the shared [`ScanContext`](crate::scan::ScanContext)
/// lines, so the tree is read once for all line-scanning passes.
pub fn analyse_with_context(ir: &Ir, ctx: &crate::scan::ScanContext) -> Vec<Finding> {
    let mut files: Vec<(PathBuf, Language)> = ir
        .files
        .iter()
        .filter(|(_, info)| {
            matches!(
                info.language,
                Language::Python | Language::JavaScript | Language::TypeScript
            )
        })
        .map(|(p, info)| (p.clone(), info.language.clone()))
        .collect();
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let per_file: Vec<Vec<Finding>> = files
        .par_iter()
        .map(|(path, language)| {
            let path_str = matchable_path(path);
            // Same skip set as the classic security pass: vendored and
            // generated trees are display-hash and sample-data territory, and
            // test suites carry deliberate throwaway credentials. Verum's own
            // fixture trees stay analysable.
            if path_str.contains("vendor/")
                || path_str.contains("node_modules/")
                || path_str.contains("/benchmarks/")
                || path_str.contains("/testdata/")
                || path_str.contains("/test-data/")
                || path_str.contains("/corpus/")
                || (!path_str.contains("fixtures") && path_str.contains("/tests/"))
            {
                return Vec::new();
            }
            let Some(lines) = ctx.lines(path) else {
                return Vec::new();
            };
            match verum_nucleus::panic_guard::catch(|| {
                let mut findings = Vec::new();
                scan_file(path, language, lines.as_ref(), &mut findings);
                findings
            }) {
                Some(f) => f,
                None => vec![Finding::parse_failure(
                    path,
                    "analysis panicked on this file",
                )],
            }
        })
        .collect();

    let mut findings: Vec<Finding> = per_file.into_iter().flatten().collect();
    findings.sort_by(|a, b| (&a.file, a.line_start, &a.id).cmp(&(&b.file, b.line_start, &b.id)));
    findings
}

fn scan_file(path: &Path, language: &Language, lines: &[String], findings: &mut Vec<Finding>) {
    let is_python = matches!(language, Language::Python);
    let is_js = matches!(language, Language::JavaScript | Language::TypeScript);

    for (idx, line) in lines.iter().enumerate() {
        let line_num = (idx + 1) as u32;
        if line.len() > crate::scan::MAX_SCAN_LINE_BYTES {
            continue;
        }
        if is_comment_line(line, is_python) {
            continue;
        }

        detect_provider_token(path, line, line_num, findings);
        detect_pem_private_key(path, line, lines, idx, findings);

        if is_js {
            detect_create_hash(path, line, line_num, findings);
            detect_js_tls_disabled(path, line, line_num, findings);
            detect_new_function(path, line, line_num, findings);
            detect_weak_random(path, line, line_num, "Math.random(", findings);
        }

        if is_python {
            detect_python_tls_disabled(path, line, line_num, findings);
            detect_pickle(path, line, line_num, findings);
            detect_yaml_load(path, line, line_num, findings);
            detect_python_exec(path, line, line_num, findings);
            for source in [
                "random.random(",
                "random.randint(",
                "random.getrandbits(",
                "random.randbytes(",
            ] {
                detect_weak_random(path, line, line_num, source, findings);
            }
        }
    }
}

// --- HardcodedSecret: provider-shaped tokens -------------------------------

fn detect_provider_token(path: &Path, line: &str, line_num: u32, findings: &mut Vec<Finding>) {
    // Detection-tool code carries these prefixes as *patterns*; skip lines
    // that are visibly building or matching a pattern rather than holding a
    // value. `${`/`{}`/`%s` mark templates that mint the value at runtime,
    // and env reads mean the literal is a fallback shape, not the secret.
    let lower = line.to_ascii_lowercase();
    if lower.contains("regex")
        || lower.contains("re.compile")
        || lower.contains("pattern")
        || lower.contains("example")
        || lower.contains("placeholder")
        || lower.contains("sample")
        || line.contains("${")
        || line.contains("process.env")
        || line.contains("os.environ")
        || line.contains("getenv")
    {
        return;
    }
    for (re, label) in provider_token_patterns() {
        if let Some(m) = re.find(line) {
            let token = m.as_str();
            // Redacted / elided values ("sk_live_xxxx...", "sk_live_1234...")
            // read as placeholders, not leaks.
            let tl = token.to_ascii_lowercase();
            if tl.contains("xxxx") || tl.contains("0000000000") || tl.contains("1234567890") {
                continue;
            }
            findings.push(mk(
                FindingKind::HardcodedSecret,
                (Severity::Critical, 0.9),
                path,
                line_num,
                format!("hardcoded credential with a known provider shape ({label})"),
                "move the secret to an environment variable or a secrets manager, then rotate \
                 it - a committed credential is compromised from the moment of the commit",
                &format!("provider-{label}"),
            ));
            return;
        }
    }
}

/// A PEM private-key header is only a finding when actual key material
/// follows it: either base64 on the same literal (with `\n` escapes) or a
/// base64-only next line (a Python triple-quoted / JS template block).
/// Parsers and serializers mention the bare header all the time; embedded
/// keys carry the payload.
fn detect_pem_private_key(
    path: &Path,
    line: &str,
    lines: &[String],
    idx: usize,
    findings: &mut Vec<Finding>,
) {
    let Some(pos) = line.find("-----BEGIN ") else {
        return;
    };
    let after = &line[pos..];
    if !after.contains("PRIVATE KEY-----") {
        return;
    }
    let tail = &after[after.find("PRIVATE KEY-----").unwrap() + "PRIVATE KEY-----".len()..];
    let same_line_material = base64_run_len(tail) >= 40;
    let next_line_material = lines
        .get(idx + 1)
        .map(|next| {
            let trimmed = next.trim().trim_end_matches(['\\', '"', '\'', ',']);
            trimmed.len() >= 40
                && trimmed
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
        })
        .unwrap_or(false);
    if !(same_line_material || next_line_material) {
        return;
    }
    findings.push(mk(
        FindingKind::HardcodedSecret,
        (Severity::Critical, 0.9),
        path,
        (idx + 1) as u32,
        "a private key is embedded in source".to_string(),
        "remove the key from source, load it from a secret store or file outside the \
         repository, and rotate it - committed key material is compromised",
        "pem-private-key",
    ));
}

/// Length of the longest run of base64-alphabet characters in `s`, counting
/// through literal `\n` escape sequences so a single-line embedded PEM
/// (`"-----BEGIN...-----\nMIIEvQ..."`) measures its key material.
fn base64_run_len(s: &str) -> usize {
    let mut best = 0usize;
    let mut cur = 0usize;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=') {
            cur += 1;
            best = best.max(cur);
            i += 1;
        } else if c == '\\' && i + 1 < bytes.len() && matches!(bytes[i + 1] as char, 'n' | 'r') {
            i += 2; // an escaped newline inside the literal does not break the run
        } else {
            cur = 0;
            i += 1;
        }
    }
    best
}

// --- WeakCrypto: createHash('md5'|'sha1') ----------------------------------

fn detect_create_hash(path: &Path, line: &str, line_num: u32, findings: &mut Vec<Finding>) {
    let Some(pos) = line.find("createHash(") else {
        return;
    };
    let arg = &line[pos + "createHash(".len()..];
    let algo = if arg.starts_with("'md5'") || arg.starts_with("\"md5\"") {
        "md5"
    } else if arg.starts_with("'sha1'") || arg.starts_with("\"sha1\"") {
        "sha1"
    } else {
        return;
    };
    // The sensitive-name signal is required, mirroring HASH_SECRET_PREFIXES:
    // md5 etags, cache keys, and content fingerprints must stay silent.
    let words = word_components(line, true);
    const HASH_SENSITIVE: &[&str] = &[
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "auth",
        "credential",
        "session",
        "signature",
        "hmac",
    ];
    if !words.iter().any(|w| HASH_SENSITIVE.contains(&w.as_str())) {
        return;
    }
    findings.push(mk(
        FindingKind::WeakCrypto,
        (Severity::Critical, 0.9),
        path,
        line_num,
        format!("`createHash('{algo}')` used for a security-sensitive value"),
        "use a password KDF (bcrypt, scrypt, argon2) for passwords, or SHA-256 and above \
         for security digests - MD5 and SHA-1 are broken for security purposes",
        &format!("createhash-{algo}"),
    ));
}

// --- WeakRandom -------------------------------------------------------------

fn detect_weak_random(
    path: &Path,
    line: &str,
    line_num: u32,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    if !contains_at_word_start(line, source) {
        return;
    }
    // numpy's `np.random.random(...)` is simulation, not secrets.
    if line.contains("np.random") || line.contains("numpy") {
        return;
    }
    let words = word_components(line, true);
    if !words
        .iter()
        .any(|w| SENSITIVE_VALUE_WORDS.contains(&w.as_str()))
    {
        return;
    }
    let source_name = source.trim_end_matches('(');
    findings.push(mk(
        FindingKind::WeakRandom,
        (Severity::High, 0.8),
        path,
        line_num,
        format!("`{source_name}()` feeds a security-sensitive value"),
        "use a cryptographically secure source for security values: crypto.randomBytes / \
         crypto.randomUUID in JavaScript, the `secrets` module in Python",
        &format!("weakrandom-{source_name}"),
    ));
}

// --- TlsVerificationDisabled ------------------------------------------------

fn detect_js_tls_disabled(path: &Path, line: &str, line_num: u32, findings: &mut Vec<Finding>) {
    if tls_reject_unauthorized_regex().is_match(line) {
        findings.push(mk(
            FindingKind::TlsVerificationDisabled,
            (Severity::High, 0.9),
            path,
            line_num,
            "`rejectUnauthorized: false` disables TLS certificate verification".to_string(),
            "remove `rejectUnauthorized: false`; for a self-signed endpoint pin its \
             certificate via the `ca` option instead of disabling verification",
            "tls-reject-unauthorized",
        ));
        return;
    }
    if node_tls_env_regex().is_match(line) {
        findings.push(mk(
            FindingKind::TlsVerificationDisabled,
            (Severity::High, 0.9),
            path,
            line_num,
            "`NODE_TLS_REJECT_UNAUTHORIZED=0` disables TLS certificate verification \
             process-wide"
                .to_string(),
            "remove the NODE_TLS_REJECT_UNAUTHORIZED override; it silently disables \
             verification for every TLS connection the process makes",
            "tls-node-env",
        ));
    }
}

fn detect_python_tls_disabled(path: &Path, line: &str, line_num: u32, findings: &mut Vec<Finding>) {
    if line.contains("ssl._create_unverified_context") {
        findings.push(mk(
            FindingKind::TlsVerificationDisabled,
            (Severity::High, 0.9),
            path,
            line_num,
            "`ssl._create_unverified_context()` disables TLS certificate verification".to_string(),
            "use `ssl.create_default_context()`; for a self-signed endpoint load its CA with \
             `context.load_verify_locations(...)` instead of disabling verification",
            "tls-unverified-context",
        ));
        return;
    }
    if line.contains("verify_mode") && line.contains("CERT_NONE") {
        findings.push(mk(
            FindingKind::TlsVerificationDisabled,
            (Severity::High, 0.85),
            path,
            line_num,
            "`verify_mode = ssl.CERT_NONE` disables TLS certificate verification".to_string(),
            "keep `verify_mode` at `ssl.CERT_REQUIRED` and trust the specific CA via \
             `load_verify_locations` for self-signed endpoints",
            "tls-cert-none",
        ));
        return;
    }
    if python_verify_false_regex().is_match(line) {
        // `verify=False` is only a TLS switch on an HTTP client call;
        // require client evidence on the same line so unrelated keyword
        // arguments named `verify` stay silent.
        const CLIENT_MARKERS: &[&str] = &[
            "requests.",
            "httpx.",
            "urllib3",
            "aiohttp",
            ".get(",
            ".post(",
            ".put(",
            ".patch(",
            ".delete(",
            ".head(",
            ".request(",
            "Session(",
            "Client(",
            "AsyncClient(",
        ];
        if !CLIENT_MARKERS.iter().any(|m| line.contains(m)) {
            return;
        }
        findings.push(mk(
            FindingKind::TlsVerificationDisabled,
            (Severity::High, 0.9),
            path,
            line_num,
            "`verify=False` disables TLS certificate verification on this HTTP call".to_string(),
            "drop `verify=False`; for a self-signed endpoint pass the CA bundle path \
             (`verify=\"/path/to/ca.pem\"`) instead of disabling verification",
            "tls-verify-false",
        ));
    }
}

// --- UnsafeDeserialization --------------------------------------------------

fn detect_pickle(path: &Path, line: &str, line_num: u32, findings: &mut Vec<Finding>) {
    for pattern in [
        "pickle.loads(",
        "pickle.load(",
        "cPickle.loads(",
        "cPickle.load(",
    ] {
        if !contains_at_word_start(line, pattern) {
            continue;
        }
        let pos = find_at_word_start(line, pattern).expect("checked above");
        let arg = line[pos + pattern.len()..].trim_start();
        if arg_is_string_literal(arg) {
            continue;
        }
        findings.push(mk(
            FindingKind::UnsafeDeserialization,
            (Severity::High, 0.75),
            path,
            line_num,
            "pickle deserialization of non-literal data - loading a pickle executes \
             arbitrary code embedded in it"
                .to_string(),
            "use a data-only format (json, msgpack) for anything that crosses a trust \
             boundary; pickle is only safe on bytes the application itself wrote and stored \
             securely",
            "pickle",
        ));
        return;
    }
}

fn detect_yaml_load(path: &Path, line: &str, line_num: u32, findings: &mut Vec<Finding>) {
    if contains_at_word_start(line, "yaml.unsafe_load(") {
        findings.push(mk(
            FindingKind::UnsafeDeserialization,
            (Severity::High, 0.85),
            path,
            line_num,
            "`yaml.unsafe_load()` instantiates arbitrary Python objects from the document"
                .to_string(),
            "use `yaml.safe_load()`; it parses the same data documents without the \
             object-construction feature that makes untrusted YAML code execution",
            "yaml-unsafe-load",
        ));
        return;
    }
    if !contains_at_word_start(line, "yaml.load(") {
        return;
    }
    // `Loader=SafeLoader`/`FullLoader` on the same call is fine, and
    // ruamel.yaml's `.load(` is safe by default.
    if line.contains("SafeLoader")
        || line.contains("FullLoader")
        || line.contains("safe_load")
        || line.contains("ruamel")
    {
        return;
    }
    findings.push(mk(
        FindingKind::UnsafeDeserialization,
        (Severity::High, 0.8),
        path,
        line_num,
        "`yaml.load()` without a safe loader instantiates arbitrary Python objects".to_string(),
        "use `yaml.safe_load(...)` or pass `Loader=yaml.SafeLoader`; the default full \
         loader turns untrusted YAML into code execution",
        "yaml-load",
    ));
}

fn detect_new_function(path: &Path, line: &str, line_num: u32, findings: &mut Vec<Finding>) {
    let Some(pos) = find_at_word_start(line, "new Function(") else {
        return;
    };
    // All-literal arguments (`new Function('return this')`) are a codegen
    // idiom; only non-literal text reaching the constructor is dynamic code.
    let args = argument_text(&line[pos + "new Function(".len()..]);
    if !strip_string_literals(&args)
        .chars()
        .any(|c| c.is_ascii_alphabetic())
    {
        return;
    }
    findings.push(mk(
        FindingKind::UnsafeDeserialization,
        (Severity::High, 0.8),
        path,
        line_num,
        "`new Function(...)` compiles non-literal text into executable JavaScript".to_string(),
        "replace the dynamic Function constructor with explicit logic or a real parser; \
         compiling strings at runtime is eval by another name",
        "new-function",
    ));
}

fn detect_python_exec(path: &Path, line: &str, line_num: u32, findings: &mut Vec<Finding>) {
    // Bare builtin `exec(` only: `dialog.exec()` (PyQt) and other methods
    // named exec are unrelated.
    let Some(pos) = find_at_word_start(line, "exec(") else {
        return;
    };
    if line[..pos].ends_with('.') {
        return;
    }
    let arg = line[pos + "exec(".len()..].trim_start();
    if arg_is_string_literal(arg) || arg.starts_with(')') {
        return;
    }
    findings.push(mk(
        FindingKind::EvalUsage,
        (Severity::Critical, 0.85),
        path,
        line_num,
        "`exec()` on a non-literal argument executes dynamically assembled code".to_string(),
        "replace exec with explicit dispatch or importlib for plugin loading; executing \
         assembled strings is remote code execution the moment input reaches them",
        "exec",
    ));
}

// --- shared helpers ---------------------------------------------------------

fn mk(
    kind: FindingKind,
    (severity, confidence): (Severity, f32),
    path: &Path,
    line: u32,
    message: String,
    suggestion: &str,
    tag: &str,
) -> Finding {
    Finding {
        fingerprint: String::new(),
        id: format!("appsec-{}-{}:{}", tag, path.display(), line),
        kind,
        severity,
        confidence,
        file: path.to_path_buf(),
        line_start: line,
        line_end: line,
        symbol: None,
        message,
        suggestion: suggestion.to_string(),
        auto_fixable: false,
        related: Vec::new(),
    }
}

/// True when the line is comment-only for the file's language.
fn is_comment_line(line: &str, is_python: bool) -> bool {
    let trimmed = line.trim_start();
    if is_python {
        trimmed.starts_with('#')
    } else {
        trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*")
    }
}

/// True when `pattern` occurs in `line` at a word start (the preceding char
/// is not part of an identifier).
fn contains_at_word_start(line: &str, pattern: &str) -> bool {
    find_at_word_start(line, pattern).is_some()
}

/// Byte offset of the first word-start occurrence of `pattern` in `line`.
fn find_at_word_start(line: &str, pattern: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(pos) = line[from..].find(pattern) {
        let abs = from + pos;
        let prev = line[..abs].chars().next_back();
        let is_word_char = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$';
        if prev.is_none_or(|c| !is_word_char(c)) {
            return Some(abs);
        }
        from = abs + pattern.len();
    }
    None
}

/// True when the argument text starts with a plain string/bytes literal -
/// the "literal input" shape the deserialization checks exclude. An f-string
/// is interpolation, so it does not count as literal.
fn arg_is_string_literal(arg: &str) -> bool {
    arg.starts_with('"')
        || arg.starts_with('\'')
        || arg.starts_with("b'")
        || arg.starts_with("b\"")
        || arg.starts_with("r'")
        || arg.starts_with("r\"")
}

/// The argument text up to the matching close paren (or line end), tracking
/// nesting but not quotes - callers strip string literals separately.
fn argument_text(rest: &str) -> String {
    let mut depth = 0i32;
    let mut out = String::new();
    for c in rest.chars() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                if depth == 0 {
                    break;
                }
                depth -= 1;
            }
            _ => {}
        }
        out.push(c);
    }
    out
}

/// `s` with every single-, double-, and backtick-quoted span removed.
fn strip_string_literals(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_quote: Option<char> = None;
    let mut escaped = false;
    for c in s.chars() {
        match in_quote {
            Some(q) => {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == q {
                    in_quote = None;
                }
            }
            None => {
                if matches!(c, '\'' | '"' | '`') {
                    in_quote = Some(c);
                } else {
                    out.push(c);
                }
            }
        }
    }
    out
}

/// Lowercased word components of the line's identifiers: split on
/// non-alphanumerics and, when `camel` is set, on lower-to-upper camelCase
/// boundaries, so `sessionToken` yields `session`/`token` but `tokens` stays
/// one word.
fn word_components(line: &str, camel: bool) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in line.chars() {
        if c.is_ascii_alphanumeric() {
            if camel && c.is_ascii_uppercase() && prev_lower && !cur.is_empty() {
                words.push(std::mem::take(&mut cur));
            }
            prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
            cur.push(c.to_ascii_lowercase());
        } else {
            prev_lower = false;
            if !cur.is_empty() {
                words.push(std::mem::take(&mut cur));
            }
        }
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(lang: Language, src: &str) -> Vec<Finding> {
        let lines: Vec<String> = src.lines().map(str::to_string).collect();
        let mut findings = Vec::new();
        scan_file(Path::new("app.src"), &lang, &lines, &mut findings);
        findings
    }

    fn kinds(findings: &[Finding]) -> Vec<&FindingKind> {
        findings.iter().map(|f| &f.kind).collect()
    }

    // --- provider tokens --------------------------------------------------

    #[test]
    fn stripe_live_key_in_config_is_flagged() {
        let f = scan(
            Language::TypeScript,
            r#"export const stripe = new Stripe("sk_live_a1B2c3D4e5F6g7H8");"#,
        );
        assert_eq!(kinds(&f), vec![&FindingKind::HardcodedSecret], "{f:?}");
        assert_eq!(f[0].severity, Severity::Critical);
    }

    #[test]
    fn aws_and_github_and_slack_tokens_are_flagged() {
        // The Slack line is assembled at runtime: hosting providers scan
        // pushed source for token-shaped literals, and a contiguous one here
        // blocks the push even though it is fabricated.
        let slack = format!(
            r#"slack_token = "xoxb-{}""#,
            "2179157893-ABcdEFghIJklMNopQRstUVwx"
        );
        for line in [
            r#"aws_key = "AKIAIOSFODNN7REALKEY"#.to_string(),
            r#"const gh = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789""#.to_string(),
            slack,
        ] {
            let f = scan(Language::Python, &line);
            assert_eq!(kinds(&f), vec![&FindingKind::HardcodedSecret], "{line}");
        }
    }

    #[test]
    fn env_fallbacks_placeholders_and_patterns_are_clean() {
        for line in [
            // env read on the same expression
            r#"const key = process.env.STRIPE_KEY ?? "sk_live_a1B2c3D4e5F6g7H8";"#,
            "key = os.environ.get('STRIPE_KEY', 'sk_live_a1B2c3D4e5F6g7H8')",
            // template interpolation
            "const key = `sk_live_${suffix}`;",
            // redacted placeholder
            r#"shown = "sk_live_xxxxxxxxxxxxxxxxxxxx""#,
            // a scanner's own pattern table
            r#"const SECRET_PATTERN = /sk_live_[0-9a-zA-Z]{16,}/; // regex"#,
            // test-mode key is the documented fixture placeholder
            r#"stripe_key = "sk_test_a1B2c3D4e5F6g7H8i9J0""#,
        ] {
            let f = scan(Language::TypeScript, line);
            assert!(f.is_empty(), "{line}: {f:?}");
        }
    }

    #[test]
    fn embedded_pem_key_with_material_is_flagged() {
        let f = scan(
            Language::Python,
            "KEY = \"\"\"-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n-----END RSA PRIVATE KEY-----\"\"\"",
        );
        assert_eq!(kinds(&f), vec![&FindingKind::HardcodedSecret], "{f:?}");
    }

    #[test]
    fn pem_header_in_parser_code_is_clean() {
        let f = scan(
            Language::Python,
            "if text.startswith('-----BEGIN RSA PRIVATE KEY-----'):\n    return parse_pem(text)",
        );
        assert!(f.is_empty(), "{f:?}");
    }

    // --- createHash -------------------------------------------------------

    #[test]
    fn md5_password_hash_is_flagged() {
        let f = scan(
            Language::JavaScript,
            "const passwordHash = crypto.createHash('md5').update(password).digest('hex');",
        );
        assert_eq!(kinds(&f), vec![&FindingKind::WeakCrypto], "{f:?}");
        assert_eq!(f[0].severity, Severity::Critical);
    }

    #[test]
    fn md5_etag_and_cache_key_are_clean() {
        for line in [
            "const etag = crypto.createHash('md5').update(body).digest('hex');",
            "const cacheKey = crypto.createHash('sha1').update(url).digest('hex');",
            "const sum = crypto.createHash('sha256').update(secret).digest('hex');",
        ] {
            let f = scan(Language::JavaScript, line);
            assert!(f.is_empty(), "{line}: {f:?}");
        }
    }

    // --- weak random ------------------------------------------------------

    #[test]
    fn math_random_token_is_flagged() {
        let f = scan(
            Language::JavaScript,
            "const resetToken = Math.random().toString(36).substring(2);",
        );
        assert_eq!(kinds(&f), vec![&FindingKind::WeakRandom], "{f:?}");
    }

    #[test]
    fn python_randint_otp_is_flagged() {
        let f = scan(
            Language::Python,
            "otp = str(random.randint(100000, 999999))",
        );
        assert_eq!(kinds(&f), vec![&FindingKind::WeakRandom], "{f:?}");
    }

    #[test]
    fn non_secret_randomness_is_clean() {
        for (lang, line) in [
            (Language::JavaScript, "const jitter = Math.random() * 100;"),
            (Language::Python, "if random.random() < sample_rate:"),
            (Language::Python, "delay = random.randint(1, 5)"),
            // plural `tokens` (a parser's) must not match `token`
            (
                Language::Python,
                "shuffled_tokens = [t for t in tokens if random.random() < 0.5]",
            ),
            (Language::Python, "x = np.random.random(size)"),
        ] {
            let f = scan(lang, line);
            assert!(f.is_empty(), "{line}: {f:?}");
        }
    }

    // --- TLS --------------------------------------------------------------

    #[test]
    fn tls_disabled_shapes_are_flagged() {
        for (lang, line) in [
            (
                Language::TypeScript,
                "const agent = new https.Agent({ rejectUnauthorized: false });",
            ),
            (
                Language::JavaScript,
                "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';",
            ),
            (
                Language::Python,
                "resp = requests.post(url, json=payload, verify=False)",
            ),
            (Language::Python, "client = httpx.Client(verify=False)"),
            (Language::Python, "ctx = ssl._create_unverified_context()"),
            (Language::Python, "context.verify_mode = ssl.CERT_NONE"),
        ] {
            let f = scan(lang.clone(), line);
            assert_eq!(
                kinds(&f),
                vec![&FindingKind::TlsVerificationDisabled],
                "{line}: {f:?}"
            );
            assert_eq!(f[0].severity, Severity::High, "{line}");
        }
    }

    #[test]
    fn verified_tls_and_unrelated_verify_kwargs_are_clean() {
        for (lang, line) in [
            (Language::Python, "resp = requests.post(url, json=payload)"),
            (
                Language::Python,
                "resp = requests.get(url, verify='/etc/ssl/ca.pem')",
            ),
            // a `verify` kwarg that is not an HTTP client call
            (Language::Python, "result = validate(schema, verify=False)"),
            (
                Language::TypeScript,
                "const agent = new https.Agent({ keepAlive: true });",
            ),
            // comment, not code
            (
                Language::JavaScript,
                "// never set rejectUnauthorized: false in production",
            ),
        ] {
            let f = scan(lang.clone(), line);
            assert!(f.is_empty(), "{line}: {f:?}");
        }
    }

    // --- deserialization --------------------------------------------------

    #[test]
    fn unsafe_deserialization_shapes_are_flagged() {
        for (lang, line) in [
            (Language::Python, "obj = pickle.loads(request.data)"),
            (Language::Python, "cfg = pickle.load(fh)"),
            (Language::Python, "doc = yaml.load(stream)"),
            (Language::Python, "doc = yaml.unsafe_load(stream)"),
            (
                Language::JavaScript,
                "const fn = new Function('ctx', userCode);",
            ),
        ] {
            let f = scan(lang.clone(), line);
            assert_eq!(
                kinds(&f),
                vec![&FindingKind::UnsafeDeserialization],
                "{line}: {f:?}"
            );
        }
    }

    #[test]
    fn safe_deserialization_idioms_are_clean() {
        for (lang, line) in [
            (Language::Python, "doc = yaml.safe_load(stream)"),
            (
                Language::Python,
                "doc = yaml.load(stream, Loader=yaml.SafeLoader)",
            ),
            (
                Language::Python,
                "doc = yaml.load(stream, Loader=yaml.FullLoader)",
            ),
            (Language::Python, "obj = pickle.loads(b'\\x80\\x04K\\x01.')"),
            (Language::Python, "data = json.loads(request.data)"),
            (
                Language::JavaScript,
                "const returnThis = new Function('return this');",
            ),
        ] {
            let f = scan(lang.clone(), line);
            assert!(f.is_empty(), "{line}: {f:?}");
        }
    }

    #[test]
    fn python_exec_on_non_literal_is_flagged_and_methods_are_not() {
        let f = scan(Language::Python, "exec(compiled_code)");
        assert_eq!(kinds(&f), vec![&FindingKind::EvalUsage], "{f:?}");

        for line in [
            "dialog.exec()",    // PyQt method, not the builtin
            "exec('print(1)')", // literal codegen
            "app.exec()",
        ] {
            let f = scan(Language::Python, line);
            assert!(f.is_empty(), "{line}: {f:?}");
        }
    }

    // --- language gating ---------------------------------------------------

    #[test]
    fn js_only_shapes_do_not_fire_in_python_and_vice_versa() {
        // `verify=False` shape in a JS file is meaningless.
        let f = scan(
            Language::JavaScript,
            "resp = requests.post(url, verify=False)",
        );
        assert!(f.is_empty(), "{f:?}");
        // Math.random in Python cannot occur; random.random in JS is not the
        // stdlib module.
        let f = scan(Language::Python, "const t = Math.random(); // token");
        assert!(f.is_empty(), "{f:?}");
    }
}
