//! Crypto hygiene: two local, syntactic checks for classic AEAD/MAC misuses.
//!
//! Detectors:
//! - [`FindingKind::NonConstantTimeComparison`]: `==`/`!=` used to compare a
//!   security-sensitive value (an HMAC, signature, secret, digest, or a
//!   compound like `auth_tag`/`access_token`) instead of a constant-time
//!   comparison. A
//!   naive `==` on a byte value short-circuits at the first mismatching byte,
//!   leaking timing information an attacker can use to forge the value
//!   byte-by-byte.
//! - [`FindingKind::StaticAeadNonce`]: a constant/hardcoded nonce or IV
//!   reaching an AEAD `.encrypt(`/`.seal(` call, or a `Nonce` built directly
//!   from a literal byte array. Reusing a nonce under the same key breaks
//!   confidentiality (and, for most AEAD modes, integrity) of every message
//!   encrypted under it.
//!
//! Both are heuristic string/regex matching over the IR's Rust files, tuned
//! to stay quiet on the idiomatic-safe forms: `ct_eq`/`subtle::ConstantTimeEq`
//! comparisons, and a nonce buffer filled from a CSPRNG before use.

use std::collections::HashSet;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use rayon::prelude::*;
use regex::Regex;

use verum_nucleus::{Finding, FindingKind, Ir, Language, Severity};

/// Whole-word identifier fragments that mark a security-sensitive value.
/// Matched against `.`/`_`/`:`-delimited components of an identifier, so a
/// one-word type name like `HmacKey` does not match `hmac`, but
/// `hmac_result` and `self.signature` do.
///
/// Deliberately narrow: corpus runs showed the generic single words `tag`,
/// `token`, `sig`, `mac`, `auth` and `session` are dominated by non-secret
/// uses on real code (serde's enum `tag`, nom/tree-sitter parser `token`s,
/// DNSSEC's public `key_tag`/`sig_input`, `mac_addr`, auth modes, session
/// ids), so those only count in the specific compounds listed in
/// [`SENSITIVE_PAIRS`].
const SENSITIVE_WORDS: &[&str] = &["hmac", "cmac", "signature", "secret", "digest", "verifier"];

/// Adjacent component pairs that are security-sensitive together even though
/// the individual words are too generic on their own: `auth_tag == expected`
/// is a MAC check, while serde's `self.tag == field` or mio's event `token`
/// are not.
const SENSITIVE_PAIRS: &[(&str, &str)] = &[
    ("auth", "tag"),
    ("mac", "tag"),
    ("gcm", "tag"),
    ("poly1305", "tag"),
    ("expected", "mac"),
    ("computed", "mac"),
    ("access", "token"),
    ("auth", "token"),
    ("api", "token"),
    ("csrf", "token"),
    ("bearer", "token"),
    ("refresh", "token"),
    ("session", "token"),
    ("secret", "token"),
];

/// Extra components that make a `*_hash` identifier a *secret* hash (e.g.
/// `password_hash`) rather than a content hash (`file_hash`, `etag_hash`,
/// left unflagged).
const HASH_SECRET_PREFIXES: &[&str] = &["password", "pwd", "pass", "credential", "secret", "key"];

/// Substrings that mark a line as already doing a constant-time comparison -
/// the whole line is skipped when present.
const SAFE_COMPARISON_MARKERS: &[&str] = &[
    "ct_eq(",
    "ConstantTimeEq",
    "constant_time_eq",
    "subtle::",
    "ring::constant_time",
];

/// Sinks where a nonce/IV value is consumed by an AEAD encrypt operation, or
/// where a `Nonce` is constructed directly from bytes.
const NONCE_SINKS: &[&str] = &[".encrypt(", ".seal(", "Nonce::from_slice("];

/// Markers that show a nonce/IV buffer is filled from a CSPRNG rather than
/// hardcoded - anywhere between a tracked variable's declaration and its use
/// at a sink, on a line that also mentions the variable, suppresses the
/// finding for that variable.
const RNG_MARKERS: &[&str] = &[
    "fill_bytes(",
    "generate_nonce(",
    "OsRng",
    "ThreadRng",
    "thread_rng(",
    "rand::",
    "getrandom(",
    "SystemRandom",
    ".fill(",
];

const NONCE_SUGGESTION: &str = "generate a fresh nonce per encryption from a CSPRNG (e.g. \
     OsRng::fill_bytes, an AEAD crate's generate_nonce, or a 24-byte XChaCha random nonce) - \
     reusing or hardcoding an AEAD nonce under the same key breaks confidentiality, and for \
     most modes integrity, of every message encrypted under it";

const COMPARISON_SUGGESTION: &str = "use a constant-time comparison for security-sensitive \
     values - subtle::ConstantTimeEq (`.ct_eq(...)`) or the constant_time_eq crate - instead \
     of `==`/`!=`; a naive comparison short-circuits on the first mismatched byte and leaks \
     timing information an attacker can use to forge the value byte-by-byte";

pub fn analyse(ir: &Ir) -> Vec<Finding> {
    let mut findings = Vec::new();

    let mut files: Vec<PathBuf> = ir
        .files
        .iter()
        .filter(|(_, info)| info.language == Language::Rust)
        .map(|(p, _)| p.clone())
        .collect();
    files.sort();

    // Each file is analysed independently; results are collected per file and
    // flattened in the pre-sorted file order so the output sequence never
    // depends on thread scheduling (the trailing sort then normalizes fully).
    let per_file: Vec<Vec<Finding>> = files
        .par_iter()
        .map(|path| {
            let mut file_findings = Vec::new();
            let path_str = path.to_string_lossy();
            if path_str.contains("/target/")
                || path_str.contains("vendor/")
                || path_str.contains("node_modules/")
            {
                return file_findings;
            }
            // Real test code exercises fixtures deliberately; skip it (but not
            // fixtures-under-tests, which are analysis targets).
            if (path_str.contains("/tests/") || path_str.ends_with("_test.rs"))
                && !path_str.contains("fixtures")
            {
                return file_findings;
            }

            let Ok(raw) = std::fs::read(path) else {
                return file_findings;
            };
            let lines: Vec<String> = raw.lines().map(|l| l.unwrap_or_default()).collect();

            analyse_file(path, &lines, &mut file_findings);
            file_findings
        })
        .collect();
    for file_findings in per_file {
        findings.extend(file_findings);
    }

    findings.sort_by(|a, b| (&a.file, a.line_start, &a.id).cmp(&(&b.file, b.line_start, &b.id)));
    findings
}

fn analyse_file(path: &Path, lines: &[String], findings: &mut Vec<Finding>) {
    // Inline #[cfg(test)] items are test scaffolding - and, in this crate's
    // own source, hold fixture source text as string literals that would
    // otherwise self-trigger these detectors. Blank them out before scanning.
    let test_ranges = crate::rust_insights::cfg_test_ranges(lines);
    let code_lines: Vec<String> = lines
        .iter()
        .enumerate()
        .map(|(idx, l)| {
            let line_num = (idx + 1) as u32;
            if test_ranges
                .iter()
                .any(|(a, b)| line_num >= *a && line_num <= *b)
            {
                String::new()
            } else {
                strip_line_comment(l)
            }
        })
        .collect();

    detect_non_constant_time_comparison(path, &code_lines, findings);
    detect_static_nonce(path, &code_lines, findings);
}

/// Detector 1: `==`/`!=` comparing a security-sensitive identifier, outside
/// the recognized safe (constant-time) forms.
fn detect_non_constant_time_comparison(
    path: &Path,
    code_lines: &[String],
    findings: &mut Vec<Finding>,
) {
    let mut flagged_lines: HashSet<u32> = HashSet::new();

    for (idx, line) in code_lines.iter().enumerate() {
        if line.is_empty() {
            continue;
        }
        if SAFE_COMPARISON_MARKERS.iter().any(|m| line.contains(m)) {
            continue;
        }
        let line_num = (idx + 1) as u32;

        for (op_pos, op) in comparison_ops(line) {
            let left = operand_before(line, op_pos);
            let right = operand_after(line, op_pos + op.len());

            if left.is_empty() && right.is_empty() {
                continue;
            }
            if preceding_is_string_literal(line, op_pos)
                || following_is_string_literal(line, op_pos + op.len())
            {
                continue;
            }
            if left == "None" || right == "None" {
                continue;
            }
            if is_some_pattern(&left) || is_some_pattern(&right) {
                continue;
            }
            if is_bool_literal(&left) || is_bool_literal(&right) {
                continue;
            }
            if is_enum_variant_path(&left) || is_enum_variant_path(&right) {
                continue;
            }
            if left.contains("is_empty") || right.contains("is_empty") {
                continue;
            }
            if !identifier_is_sensitive(&left) && !identifier_is_sensitive(&right) {
                continue;
            }

            if flagged_lines.insert(line_num) {
                findings.push(mk(
                    FindingKind::NonConstantTimeComparison,
                    Severity::Medium,
                    0.65,
                    path,
                    line_num,
                    format!(
                        "`{left} {op} {right}` compares a security-sensitive value with a \
                         non-constant-time operator"
                    ),
                    COMPARISON_SUGGESTION,
                ));
            }
        }
    }
}

/// Detector 2: a constant nonce/IV array literal reaching an AEAD encrypt
/// call or a `Nonce::from_slice`, without evidence it was RNG-filled first.
fn detect_static_nonce(path: &Path, code_lines: &[String], findings: &mut Vec<Finding>) {
    let literal_re = nonce_literal_regex();
    let decl_re = nonce_decl_regex();

    // (variable name, declaration line) for every `let|const|static NAME =
    // [LIT; 12|16|24];` binding in the file.
    let mut tracked: Vec<(String, u32)> = Vec::new();
    for (idx, line) in code_lines.iter().enumerate() {
        if let Some(cap) = decl_re.captures(line) {
            tracked.push((cap[1].to_string(), (idx + 1) as u32));
        }
    }

    let mut flagged_lines: HashSet<u32> = HashSet::new();

    for (idx, line) in code_lines.iter().enumerate() {
        let line_num = (idx + 1) as u32;
        if !NONCE_SINKS.iter().any(|s| line.contains(s)) {
            continue;
        }

        // A literal array written directly at the sink call.
        if literal_re.is_match(line) && !RNG_MARKERS.iter().any(|m| line.contains(m)) {
            if flagged_lines.insert(line_num) {
                findings.push(mk(
                    FindingKind::StaticAeadNonce,
                    Severity::High,
                    0.8,
                    path,
                    line_num,
                    "a constant nonce/IV literal reaches an AEAD encrypt/seal call".to_string(),
                    NONCE_SUGGESTION,
                ));
            }
            continue;
        }

        // A variable traced back to a literal-array declaration, with no RNG
        // fill evidence for it between the declaration and this use.
        for (name, decl_line) in &tracked {
            if *decl_line > line_num || !contains_word(line, name) {
                continue;
            }
            let window = &code_lines[(*decl_line as usize - 1)..line_num as usize];
            let rng_guarded = window
                .iter()
                .any(|l| contains_word(l, name) && RNG_MARKERS.iter().any(|m| l.contains(m)));
            if rng_guarded {
                continue;
            }
            if flagged_lines.insert(line_num) {
                findings.push(mk(
                    FindingKind::StaticAeadNonce,
                    Severity::High,
                    0.75,
                    path,
                    line_num,
                    format!(
                        "`{name}` (declared at line {decl_line} as a constant literal array) \
                         reaches an AEAD encrypt/seal call as the nonce"
                    ),
                    NONCE_SUGGESTION,
                ));
            }
            break;
        }
    }
}

fn nonce_literal_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\[\s*(?:0x[0-9a-fA-F]+|\d+)(?:u8)?\s*;\s*(?:12|16|24)\s*\]")
            .expect("valid regex")
    })
}

fn nonce_decl_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?:let\s+(?:mut\s+)?|const\s+|static\s+(?:mut\s+)?)([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]+)?=\s*\[\s*(?:0x[0-9a-fA-F]+|\d+)(?:u8)?\s*;\s*(?:12|16|24)\s*\]",
        )
        .expect("valid regex")
    })
}

/// Byte positions and text of every `==`/`!=` in `line`.
fn comparison_ops(line: &str) -> Vec<(usize, &'static str)> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'=' && bytes[i + 1] == b'=' {
            out.push((i, "=="));
            i += 2;
        } else if bytes[i] == b'!' && bytes[i + 1] == b'=' {
            out.push((i, "!="));
            i += 2;
        } else {
            i += 1;
        }
    }
    out
}

/// The identifier-ish token immediately before byte offset `pos` in `line`.
fn operand_before(line: &str, pos: usize) -> String {
    let head = line[..pos].trim_end();
    let bytes = head.as_bytes();
    let mut start = bytes.len();
    while start > 0 {
        let c = bytes[start - 1] as char;
        if c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == ':' {
            start -= 1;
        } else {
            break;
        }
    }
    head[start..].to_string()
}

/// The identifier-ish token immediately after byte offset `pos` in `line`.
fn operand_after(line: &str, pos: usize) -> String {
    let tail = line[pos..].trim_start();
    let bytes = tail.as_bytes();
    let mut end = 0;
    while end < bytes.len() {
        let c = bytes[end] as char;
        if c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == ':' {
            end += 1;
        } else {
            break;
        }
    }
    tail[..end].to_string()
}

fn preceding_is_string_literal(line: &str, pos: usize) -> bool {
    let head = line[..pos].trim_end();
    head.ends_with('"') || head.ends_with('\'')
}

fn following_is_string_literal(line: &str, pos: usize) -> bool {
    let tail = line[pos..].trim_start();
    tail.starts_with('"') || tail.starts_with("b\"") || tail.starts_with('\'')
}

fn is_some_pattern(token: &str) -> bool {
    token == "Some" || token.starts_with("Some(")
}

fn is_bool_literal(token: &str) -> bool {
    token == "true" || token == "false"
}

/// True for a path like `Status::Active` or `crate::Status::Active` - a
/// state/enum comparison, not a byte-level value comparison.
fn is_enum_variant_path(token: &str) -> bool {
    if !token.contains("::") {
        return false;
    }
    token
        .rsplit("::")
        .next()
        .and_then(|last| last.chars().next())
        .is_some_and(|c| c.is_ascii_uppercase())
}

/// True when `token` names a security-sensitive value: one of its
/// `.`/`_`/`:`-delimited components is a whole-word match against
/// [`SENSITIVE_WORDS`], two adjacent components form a [`SENSITIVE_PAIRS`]
/// compound, or it is a `*_hash` identifier of a secret (e.g.
/// `password_hash`) rather than a content hash.
fn identifier_is_sensitive(token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    let lower = token.to_ascii_lowercase();
    let words: Vec<&str> = lower
        .split(['.', '_', ':'])
        .filter(|w| !w.is_empty())
        .collect();
    if words.iter().any(|w| SENSITIVE_WORDS.contains(w)) {
        return true;
    }
    if words
        .windows(2)
        .any(|pair| SENSITIVE_PAIRS.contains(&(pair[0], pair[1])))
    {
        return true;
    }
    words.last() == Some(&"hash") && words.iter().any(|w| HASH_SECRET_PREFIXES.contains(w))
}

fn mk(
    kind: FindingKind,
    severity: Severity,
    confidence: f32,
    path: &Path,
    line: u32,
    message: String,
    suggestion: &str,
) -> Finding {
    Finding {
        id: format!("crypto-{:?}-{}:{}", kind, path.display(), line),
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

    fn lines(src: &str) -> Vec<String> {
        src.lines().map(strip_line_comment).collect()
    }

    // --- NonConstantTimeComparison ---------------------------------------

    #[test]
    fn sensitive_equality_is_flagged() {
        let src = "\
fn verify(hmac_result: &[u8], expected: &[u8]) -> bool {
    hmac_result == expected
}
";
        let code = lines(src);
        let mut findings = Vec::new();
        detect_non_constant_time_comparison(Path::new("lib.rs"), &code, &mut findings);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(matches!(
            findings[0].kind,
            FindingKind::NonConstantTimeComparison
        ));
        assert_eq!(findings[0].line_start, 2);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn secret_hash_equality_is_flagged() {
        let src = "\
fn check(password_hash: &str, input_hash: &str) -> bool {
    password_hash == input_hash
}
";
        let code = lines(src);
        let mut findings = Vec::new();
        detect_non_constant_time_comparison(Path::new("lib.rs"), &code, &mut findings);
        assert_eq!(findings.len(), 1, "{findings:?}");
    }

    #[test]
    fn sensitive_compound_equality_is_flagged() {
        let src = "\
fn verify(auth_tag: &[u8], expected: &[u8], access_token: &str, presented: &str) -> bool {
    auth_tag == expected && access_token == presented
}
";
        let code = lines(src);
        let mut findings = Vec::new();
        detect_non_constant_time_comparison(Path::new("lib.rs"), &code, &mut findings);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].line_start, 2);
    }

    #[test]
    fn generic_tag_and_token_words_are_clean() {
        // The corpus false-positive shapes that forced the narrow word list:
        // serde's enum tag, nom/mio-style parser/event tokens, and DNSSEC's
        // public key_tag / sig_input record metadata.
        let src = "\
fn check(field: &str, tag: &str, i: Input, token: Input, rrsig: &Rrsig, ksk_tag: u16) -> bool {
    field == tag
        || i == token
        || rrsig.key_tag == ksk_tag
        || sig_input.type_covered == key.record_type
        || mac_addr == other.mac_addr
        || session.id == current
}
";
        let code = lines(src);
        let mut findings = Vec::new();
        detect_non_constant_time_comparison(Path::new("lib.rs"), &code, &mut findings);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn constant_time_compare_is_clean() {
        let src = "\
use subtle::ConstantTimeEq;
fn verify(hmac_result: &[u8], expected: &[u8]) -> bool {
    hmac_result.ct_eq(expected).into()
}
";
        let code = lines(src);
        let mut findings = Vec::new();
        detect_non_constant_time_comparison(Path::new("lib.rs"), &code, &mut findings);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn option_and_enum_comparisons_are_clean() {
        let src = "\
fn check(session: Option<&Session>, kind: TokenKind) -> bool {
    session == None || kind == TokenKind::Bearer
}
";
        let code = lines(src);
        let mut findings = Vec::new();
        detect_non_constant_time_comparison(Path::new("lib.rs"), &code, &mut findings);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn string_literal_comparison_is_clean() {
        let src = "\
fn check(token: &str) -> bool {
    token == \"expected-token\"
}
";
        let code = lines(src);
        let mut findings = Vec::new();
        detect_non_constant_time_comparison(Path::new("lib.rs"), &code, &mut findings);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn non_sensitive_equality_is_clean() {
        let src = "\
fn same(a: &User, b: &User) -> bool {
    a.id == b.id
}
";
        let code = lines(src);
        let mut findings = Vec::new();
        detect_non_constant_time_comparison(Path::new("lib.rs"), &code, &mut findings);
        assert!(findings.is_empty(), "{findings:?}");
    }

    // --- StaticAeadNonce ---------------------------------------------------

    #[test]
    fn hardcoded_nonce_reaching_encrypt_is_flagged() {
        let src = "\
fn encrypt(cipher: &Aes256Gcm, data: &[u8]) -> Vec<u8> {
    let nonce = [0u8; 12];
    cipher.encrypt(Nonce::from_slice(&nonce), data).unwrap()
}
";
        let code = lines(src);
        let mut findings = Vec::new();
        detect_static_nonce(Path::new("lib.rs"), &code, &mut findings);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(matches!(findings[0].kind, FindingKind::StaticAeadNonce));
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn inline_literal_nonce_at_seal_is_flagged() {
        let src = "\
fn seal(sealer: &Sealer, data: &[u8]) -> Vec<u8> {
    sealer.seal(&[0u8; 24], data).unwrap()
}
";
        let code = lines(src);
        let mut findings = Vec::new();
        detect_static_nonce(Path::new("lib.rs"), &code, &mut findings);
        assert_eq!(findings.len(), 1, "{findings:?}");
    }

    #[test]
    fn rng_filled_nonce_is_clean() {
        let src = "\
fn encrypt(cipher: &Aes256Gcm, data: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    cipher.encrypt(Nonce::from_slice(&nonce), data).unwrap()
}
";
        let code = lines(src);
        let mut findings = Vec::new();
        detect_static_nonce(Path::new("lib.rs"), &code, &mut findings);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn random_xchacha_nonce_is_clean() {
        let src = "\
fn encrypt(cipher: &XChaCha20Poly1305, data: &[u8]) -> Vec<u8> {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    cipher.encrypt(&nonce, data).unwrap()
}
";
        let code = lines(src);
        let mut findings = Vec::new();
        detect_static_nonce(Path::new("lib.rs"), &code, &mut findings);
        assert!(findings.is_empty(), "{findings:?}");
    }
}
