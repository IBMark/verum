//! Transport / protocol correctness.
//!
//! Targets bugs where every line is locally fine and the defect lives in how
//! messages map onto the transport underneath. The canonical failure (seen in
//! real UDP video pipelines) is length-prefixed framing written to a datagram
//! transport as several writes - one lost datagram shears a message and
//! permanently desynchronizes every downstream `[len][payload]` parser.
//!
//! Detectors: `SplitDatagramMessage` (one logical message emitted as multiple
//! writes on a datagram transport), `OversizedDatagram` (chunk size above the
//! safe MTU, so one lost IP fragment kills the whole datagram), and
//! `UnvalidatedLengthPrefix` (wire-parsed integer used as an allocation/read
//! size with no bound check - a hostile peer controls it).
//!
//! All heuristic: high-signal string/structure matching over the IR's function
//! spans, tuned to be quiet on healthy code.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use rayon::prelude::*;

use crate::scan::ScanContext;
use verum_nucleus::Severity;
use verum_nucleus::{matchable_path, Finding, FindingKind, Ir, SymbolId, SymbolKind};

/// Largest UDP payload that fits a 1500-byte Ethernet MTU with IPv4 + UDP
/// headers. Anything above this fragments.
const MTU_SAFE_PAYLOAD: usize = 1472;

/// Tokens that mark a file as touching a datagram transport.
const DGRAM_TOKENS: &[&str] = &[
    "UdpSocket",
    "UdpStream",
    "UdpFramed",
    "SOCK_DGRAM",
    "node:dgram",
    "dgram.createSocket",
    "DatagramSocket",
    "ListenUDP",
    "DialUDP",
    "UDPConn",
];

/// Write-style calls that emit bytes onto a transport.
const WRITE_CALLS: &[&str] = &[
    ".write_all(",
    ".write(",
    ".write_buf(",
    ".send(",
    ".send_to(",
    ".sendto(",
    ".poll_send",
];

/// An integer being parsed out of raw wire bytes.
const LEN_PARSES: &[&str] = &[
    "from_be_bytes",
    "from_le_bytes",
    "read_u16",
    "read_u32",
    "read_u64",
    "getUint16(",
    "getUint32(",
    "readUInt16",
    "readUInt32",
];

/// Sinks where an attacker-controlled integer does damage.
const LEN_SINKS: &[&str] = &[
    "with_capacity(",
    "read_exact(",
    "readExact(",
    "vec![0",
    ".take(",
    ".reserve(",
    "new Uint8Array(",
    "Buffer.alloc(",
    "split_to(",
    "copy_to_bytes(",
];

/// True when a line *checks* a value's magnitude rather than merely using it:
/// an explicit clamp, or a conditional/assert containing a comparison. Return
/// arrows (`->`) and generics (`Vec<u8>`) must not read as comparisons - a
/// naive `<`/`>` scan marks every function signature as a bound check.
fn is_bound_check(line: &str) -> bool {
    if [".min(", ".max(", "clamp", "MAX"]
        .iter()
        .any(|t| line.contains(t))
    {
        return true;
    }
    // Validation helpers and macros that check a value before it is used:
    // `ensure_size!(...)`, `validate_remaining(...)`, `verify_len(...)`,
    // `require_*`, `assert!`, `bail!`. These bound the value without a literal
    // `<`/`>` on the line, so recognize them directly.
    if ["ensure", "validate", "verify", "require", "assert", "bail!"]
        .iter()
        .any(|t| line.contains(t))
    {
        return true;
    }
    let conditional = ["if ", "if(", "while ", "while(", "&&", "||"]
        .iter()
        .any(|t| line.contains(t));
    if !conditional {
        return false;
    }
    let stripped = line.replace("->", "");
    stripped.contains('<') || stripped.contains('>')
}

/// Readers that yield an integer of 16 bits or fewer. Such a value is capped at
/// 65535, so using it as an allocation size is not an *unbounded* risk (at most
/// a small over-allocation) - the length-prefix detector skips these to avoid
/// false positives on the many protocols whose counts are `u16`.
const NARROW_PARSES: &[&str] = &[
    "read_u16",
    "read_u8",
    "read_i16",
    "read_i8",
    "getUint16",
    "getUint8",
    "readUInt16",
    "readUInt8",
    "u16::from",
    "u8::from",
    "i16::from",
    "i8::from",
];

struct FnSpan {
    id: SymbolId,
    name: String,
    start: u32,
    end: u32,
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

    let mut files: Vec<PathBuf> = ir.files.keys().cloned().collect();
    files.sort();

    // Each file is analysed independently; results are collected per file and
    // flattened in the pre-sorted file order so the output sequence never
    // depends on thread scheduling (the trailing sort then normalizes fully).
    let per_file: Vec<Vec<Finding>> = files
        .par_iter()
        .map(|path| {
            let file_findings = Vec::new();
            let path_str = matchable_path(path);
            if path_str.contains("/target/")
                || path_str.contains("node_modules/")
                || path_str.contains("vendor/")
            {
                return file_findings;
            }
            // Real test code exercises protocols deliberately; skip it (but not
            // fixtures-under-tests, which are analysis targets).
            if (path_str.contains("/tests/") || path_str.ends_with("_test.rs"))
                && !path_str.contains("fixtures")
            {
                return file_findings;
            }

            let Some(lines) = ctx.lines(path) else {
                return file_findings;
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
                .map(|s| FnSpan {
                    id: s.id,
                    name: s.name.clone(),
                    start: s.line_start,
                    end: s.line_end,
                })
                .collect();
            spans.sort_by_key(|s| (s.start, s.end));

            // One hostile file must not panic the whole pass: analyse under
            // the panic guard and downgrade a panic to a diagnostic finding.
            match verum_nucleus::panic_guard::catch(|| {
                let mut file_findings = Vec::new();
                analyse_file(path, &lines, &spans, &mut file_findings);
                file_findings
            }) {
                Some(file_findings) => file_findings,
                None => vec![Finding::parse_failure(
                    path,
                    "analysis panicked on this file",
                )],
            }
        })
        .collect();
    for file_findings in per_file {
        findings.extend(file_findings);
    }

    findings.sort_by(|a, b| (&a.file, a.line_start).cmp(&(&b.file, b.line_start)));
    findings
}

fn analyse_file(path: &Path, lines: &[String], spans: &[FnSpan], findings: &mut Vec<Finding>) {
    // Blank out inline #[cfg(test)] items (and their string fixtures) before
    // scanning - protocol patterns inside tests are scaffolding, not code.
    let test_ranges = crate::rust_insights::cfg_test_ranges(lines);
    let code_lines: Vec<String> = lines
        .iter()
        .enumerate()
        .map(|(idx, l)| {
            let line_num = (idx + 1) as u32;
            // Overlong lines are generated blobs; the detectors below do
            // per-occurrence context extraction, so skip them (deterministic
            // input-size guard, see `scan::MAX_SCAN_LINE_BYTES`).
            if l.len() > crate::scan::MAX_SCAN_LINE_BYTES
                || test_ranges
                    .iter()
                    .any(|(a, b)| line_num >= *a && line_num <= *b)
            {
                String::new()
            } else {
                strip_line_comment(l)
            }
        })
        .collect();
    let is_dgram_file = code_lines
        .iter()
        .any(|l| DGRAM_TOKENS.iter().any(|t| l.contains(t)));

    if is_dgram_file {
        detect_split_messages(path, &code_lines, spans, findings);
        detect_oversized_datagrams(path, &code_lines, findings);
    }
    detect_unvalidated_length(path, &code_lines, findings);
}

/// Detector 1: a length/header write plus further writes inside one function
/// on a datagram transport - the message does not survive datagram loss.
fn detect_split_messages(
    path: &Path,
    code_lines: &[String],
    spans: &[FnSpan],
    findings: &mut Vec<Finding>,
) {
    for span in spans {
        let mut write_lines: Vec<(u32, &str)> = Vec::new();
        for idx in span.start.max(1)..=span.end.min(code_lines.len() as u32) {
            let line = &code_lines[(idx - 1) as usize];
            if WRITE_CALLS.iter().any(|w| line.contains(w)) {
                write_lines.push((idx, line));
            }
        }
        if write_lines.len() < 2 {
            continue;
        }
        // One of the writes must look like a header / length prefix - that is
        // what makes the split a framing hazard rather than independent
        // messages.
        let header_write = write_lines.iter().find(|(_, l)| {
            l.contains("to_be_bytes") || l.contains("to_le_bytes") || l.contains("header")
        });
        let Some((header_line, _)) = header_write else {
            continue;
        };

        findings.push(mk(
            FindingKind::SplitDatagramMessage,
            Severity::High,
            0.75,
            path,
            *header_line,
            Some(span.id),
            format!(
                "`{}` writes one logical message as {} separate writes on a datagram \
                 transport (each write is its own datagram)",
                span.name,
                write_lines.len()
            ),
            "datagram transports have no byte-stream continuity: if any piece is \
             lost the message shears mid-frame and a downstream length-prefix \
             parser desynchronizes permanently. Emit each complete message as \
             exactly one write <= the MTU, chunking at the application layer with \
             per-chunk headers instead",
        ));
    }
}

/// Detector 2: a compile-time chunk size above the MTU used in a datagram
/// file - datagrams will rely on IP fragmentation.
fn detect_oversized_datagrams(path: &Path, code_lines: &[String], findings: &mut Vec<Finding>) {
    static CONST_RE: OnceLock<regex::Regex> = OnceLock::new();
    let const_re = CONST_RE.get_or_init(|| {
        regex::Regex::new(r"const\s+([A-Z_][A-Z0-9_]*)\s*(?::\s*\w+)?\s*=\s*(\d[\d_]*)")
            .expect("valid regex")
    });
    let mut consts: Vec<(String, usize)> = Vec::new();
    for line in code_lines {
        if let Some(cap) = const_re.captures(line) {
            if let Ok(v) = cap[2].replace('_', "").parse::<usize>() {
                consts.push((cap[1].to_string(), v));
            }
        }
    }

    static CHUNKS_RE: OnceLock<regex::Regex> = OnceLock::new();
    let chunks_re = CHUNKS_RE.get_or_init(|| {
        regex::Regex::new(r"\.chunks\(\s*([A-Za-z0-9_]+)\s*\)").expect("valid regex")
    });
    for (idx, line) in code_lines.iter().enumerate() {
        let Some(cap) = chunks_re.captures(line) else {
            continue;
        };
        let arg = &cap[1];
        let value = arg
            .parse::<usize>()
            .ok()
            .or_else(|| consts.iter().find(|(n, _)| n == arg).map(|(_, v)| *v));
        let Some(value) = value else { continue };
        if value <= MTU_SAFE_PAYLOAD {
            continue;
        }
        let fragments = value.div_ceil(MTU_SAFE_PAYLOAD);
        findings.push(mk(
            FindingKind::OversizedDatagram,
            Severity::Medium,
            0.7,
            path,
            (idx + 1) as u32,
            None,
            format!(
                "{value}-byte chunks written to a datagram transport travel as ~{fragments} \
                 IP fragments each at a 1500-byte MTU"
            ),
            "losing any fragment loses the whole datagram, multiplying the effective \
             loss rate (5% packet loss ~ half of multi-fragment datagrams damaged). \
             A receiver-side buffer size is not a network limit - keep datagrams \
             <= ~1200 bytes so they never fragment",
        ));
    }
}

/// Detector 3: an integer parsed from wire bytes reaching an allocation /
/// read-length sink with no visible bound check anywhere in the file.
fn detect_unvalidated_length(path: &Path, code_lines: &[String], findings: &mut Vec<Finding>) {
    // `let frame_len = u32::from_be_bytes(...)`, `frameLen: view.getUint32(12)`, ...
    static ASSIGN_RE: OnceLock<regex::Regex> = OnceLock::new();
    let assign_re = ASSIGN_RE.get_or_init(|| {
        regex::Regex::new(
            r"(?:let\s+(?:mut\s+)?|const\s+|var\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*[:=][^=]",
        )
        .expect("valid regex")
    });

    let mut wire_vars: Vec<(String, u32)> = Vec::new();
    for (idx, line) in code_lines.iter().enumerate() {
        if !LEN_PARSES.iter().any(|p| line.contains(p)) {
            continue;
        }
        // 16-bit-or-narrower reads are capped at 65535 - not unbounded.
        if NARROW_PARSES.iter().any(|p| line.contains(p)) {
            continue;
        }
        if let Some(cap) = assign_re.captures(line) {
            let name = cap[1].to_string();
            // Loop/index variables and obvious non-lengths are noise.
            if name.len() > 1 {
                wire_vars.push((name, (idx + 1) as u32));
            }
        }
    }

    for (var, parse_line) in wire_vars {
        let used_at_sink = code_lines
            .iter()
            .enumerate()
            .find(|(_, l)| contains_word(l, &var) && LEN_SINKS.iter().any(|s| l.contains(s)));
        let Some((sink_idx, _)) = used_at_sink else {
            continue;
        };

        let bounded = code_lines
            .iter()
            .any(|l| contains_word(l, &var) && is_bound_check(l));
        if bounded {
            continue;
        }

        findings.push(mk(
            FindingKind::UnvalidatedLengthPrefix,
            Severity::Medium,
            0.65,
            path,
            (sink_idx + 1) as u32,
            None,
            format!(
                "`{var}` is parsed from wire bytes (line {parse_line}) and used as a \
                 length/allocation size with no visible bound check"
            ),
            "a corrupted stream or hostile peer controls this value: cap it against \
             a protocol maximum before allocating or reading, and fail loudly on \
             implausible values instead of stalling on garbage",
        ));
    }
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
    suggestion: &str,
) -> Finding {
    Finding {
        fingerprint: String::new(),
        id: format!("transport-{:?}-{}:{}", kind, path.display(), line),
        kind,
        severity,
        confidence,
        file: path.to_path_buf(),
        line_start: line,
        line_end: line,
        symbol,
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

    fn span(name: &str, start: u32, end: u32) -> FnSpan {
        FnSpan {
            id: SymbolId(start as u64),
            name: name.to_string(),
            start,
            end,
        }
    }

    #[test]
    fn split_message_on_datagram_is_flagged() {
        let src = "\
use udp_stream::UdpStream;
async fn send_frame(data: &[u8]) {
    self.inner.write_all(&len.to_be_bytes()).await?;
    for chunk in data.chunks(8192) {
        self.inner.write_all(chunk).await?;
    }
}
";
        let code = lines(src);
        let spans = vec![span("send_frame", 2, 7)];
        let mut findings = Vec::new();
        detect_split_messages(Path::new("lib.rs"), &code, &spans, &mut findings);
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].kind,
            FindingKind::SplitDatagramMessage
        ));
        assert_eq!(findings[0].line_start, 3);
    }

    #[test]
    fn single_write_per_message_is_clean() {
        let src = "\
use udp_stream::UdpStream;
async fn send_message(data: &[u8]) {
    let mut packet = Vec::with_capacity(4 + data.len());
    packet.extend_from_slice(&(data.len() as u32).to_be_bytes());
    packet.extend_from_slice(data);
    self.inner.write_all(&packet).await?;
}
";
        let code = lines(src);
        let spans = vec![span("send_message", 2, 7)];
        let mut findings = Vec::new();
        detect_split_messages(Path::new("lib.rs"), &code, &spans, &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn oversized_chunk_const_is_flagged() {
        let src = "\
use udp_stream::UdpStream;
const CHUNK_SIZE: usize = 8192;
fn send(data: &[u8]) {
    for chunk in data.chunks(CHUNK_SIZE) {}
}
";
        let code = lines(src);
        let mut findings = Vec::new();
        detect_oversized_datagrams(Path::new("lib.rs"), &code, &mut findings);
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].kind, FindingKind::OversizedDatagram));
        assert!(findings[0].message.contains("8192"));
    }

    #[test]
    fn mtu_safe_chunks_are_clean() {
        let src = "\
use udp_stream::UdpStream;
const CHUNK_DATA_BYTES: usize = 1180;
fn send(data: &[u8]) {
    for chunk in data.chunks(CHUNK_DATA_BYTES) {}
}
";
        let code = lines(src);
        let mut findings = Vec::new();
        detect_oversized_datagrams(Path::new("lib.rs"), &code, &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn unvalidated_wire_length_is_flagged() {
        let src = "\
fn parse(buf: &[u8]) {
    let frame_len = u32::from_be_bytes(buf[0..4].try_into().unwrap());
    let mut payload = Vec::with_capacity(frame_len as usize);
}
";
        let code = lines(src);
        let mut findings = Vec::new();
        detect_unvalidated_length(Path::new("lib.rs"), &code, &mut findings);
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].kind,
            FindingKind::UnvalidatedLengthPrefix
        ));
    }

    #[test]
    fn bounded_wire_length_is_clean() {
        let src = "\
fn parse(buf: &[u8]) {
    let frame_len = u32::from_be_bytes(buf[0..4].try_into().unwrap());
    if frame_len > MAX_FRAME_LEN { return; }
    let mut payload = Vec::with_capacity(frame_len as usize);
}
";
        let code = lines(src);
        let mut findings = Vec::new();
        detect_unvalidated_length(Path::new("lib.rs"), &code, &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn validation_helper_counts_as_bound() {
        // A `validate_*` / `ensure_size!` guard bounds the value even without a
        // literal `<`/`>` on the line (IronRDP / Akmot9 pattern).
        let src = "\
fn parse(cur: &mut Cursor) {
    let frame_len = u32::from_be_bytes(cur.read4());
    ensure_size!(in: cur, size: frame_len * 4);
    let mut payload = Vec::with_capacity(frame_len as usize);
}
";
        let code = lines(src);
        let mut findings = Vec::new();
        detect_unvalidated_length(Path::new("lib.rs"), &code, &mut findings);
        assert!(
            findings.is_empty(),
            "validation helper should count as a bound"
        );
    }

    #[test]
    fn u16_count_is_not_flagged() {
        // A count read as `u16` is capped at 65535 - not an unbounded allocation.
        let src = "\
fn parse(cur: &mut Cursor) {
    let count = cur.read_u16() as usize;
    let mut items = Vec::with_capacity(count);
}
";
        let code = lines(src);
        let mut findings = Vec::new();
        detect_unvalidated_length(Path::new("lib.rs"), &code, &mut findings);
        assert!(findings.is_empty(), "u16-bounded count must not be flagged");
    }

    #[test]
    fn fn_signature_arrows_and_generics_are_not_bound_checks() {
        // The value flows through a helper whose signature contains `->` and
        // `Vec<u8>` - that must not count as validation.
        let src = "\
fn parse(buf: &[u8]) {
    let frame_len = u32::from_be_bytes(buf[0..4].try_into().unwrap());
    let payload = build(frame_len);
}
fn build(frame_len: u32) -> Vec<u8> {
    Vec::with_capacity(frame_len as usize)
}
";
        let code = lines(src);
        let mut findings = Vec::new();
        detect_unvalidated_length(Path::new("lib.rs"), &code, &mut findings);
        assert_eq!(
            findings.len(),
            1,
            "signature `->`/generics must not mask the finding"
        );
    }

    #[test]
    fn js_getuint32_alloc_is_flagged() {
        let src = "\
function parseChunk(bytes) {
  const frameLen = view.getUint32(12);
  const payload = new Uint8Array(frameLen);
}
";
        let code = lines(src);
        let mut findings = Vec::new();
        detect_unvalidated_length(Path::new("decoder.js"), &code, &mut findings);
        assert_eq!(findings.len(), 1);
    }
}
