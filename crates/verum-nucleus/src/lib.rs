use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The documentation for every [`FindingKind`], in data: what each detector
/// looks for, why it matters, a flagged and a fixed example, and when
/// ignoring it is reasonable. `verum explain` and `docs/detectors.md` both
/// render from this one table.
pub mod reference;

/// `path`'s lossy string with backslashes normalized to `/`, for matching
/// against hardcoded `/`-separated patterns (`"/tests/"`, `"/vendor/"`, file
/// extensions, ...).
///
/// `Path::to_string_lossy` returns the OS-native separator, so a call site
/// written against `/`-separated literals silently stops matching on
/// Windows (a path like `src\tests\foo.rs` never contains the substring
/// `"/tests/"`). This is a no-op on Unix, where paths are already
/// `/`-separated, so it never changes Linux output.
///
/// Not for display: printed/report paths go through the analysis crate's own
/// `relative_display`, which additionally strips the analysis root.
pub fn matchable_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SymbolId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Language {
    Php,
    Rust,
    JavaScript,
    TypeScript,
    Python,
    Go,
    Java,
    Terraform,
    Kubernetes,
    Docker,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Framework {
    Laravel,
    Symfony,
    WordPress,
    Django,
    Rails,
    Express,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolKind {
    Function,
    Class,
    Method,
    StaticMethod,
    Interface,
    Trait,
    Enum,
    Constant,
    Variable,
    Property,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Visibility {
    Public,
    Protected,
    Private,
    Global,
}

/// A code symbol, always pinned to a file and line range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    pub id: SymbolId,
    pub name: String,
    pub fully_qualified: String,
    pub kind: SymbolKind,
    pub visibility: Visibility,
    pub file: PathBuf,
    pub line_start: u32,
    pub line_end: u32,
    pub col_start: u32,
    pub col_end: u32,
    pub language: Language,
    pub parent: Option<SymbolId>,
    pub hash: u64,
    pub normalized_hash: u64,
    pub flow_hash: u64,
    pub param_count: u8,
    pub is_entry_point: bool,
    pub doc_comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CallTarget {
    Resolved(SymbolId),
    Unresolved(String),
    Dynamic(String),
    Magic(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Call {
    pub caller: SymbolId,
    pub callee: CallTarget,
    pub file: PathBuf,
    pub line: u32,
    pub col: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaintSource {
    GetParam(String),
    PostParam(String),
    RequestParam(String),
    CookieParam(String),
    ServerVar(String),
    FileUpload,
    EnvVar(String),
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaintSink {
    SqlQuery,
    CommandExec,
    EvalExec,
    FileInclude,
    HtmlOutput,
    HttpHeader,
    FileWrite,
    ExternalRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintHop {
    pub symbol: SymbolId,
    pub file: PathBuf,
    pub line: u32,
    pub transforms: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPath {
    pub source: TaintSource,
    pub hops: Vec<TaintHop>,
    pub sink: TaintSink,
    pub sink_file: PathBuf,
    pub sink_line: u32,
    pub sanitized: bool,
    pub sanitizer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Any,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub method: HttpMethod,
    pub path: String,
    pub controller: Option<SymbolId>,
    pub middleware: Vec<String>,
    pub file: PathBuf,
    pub line: u32,
}

/// A client-side HTTP call to a URL path - `fetch('/api/users')`,
/// `axios.get(...)`, `reqwest` - the *caller* side of a route. Linking these to
/// `Route`s stitches the call graph across the frontend/backend language
/// boundary (and flags a frontend call to a route that doesn't exist).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpCall {
    pub method: HttpMethod,
    pub path: String,
    pub caller: SymbolId,
    pub file: PathBuf,
    pub line: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub id: FileId,
    pub path: PathBuf,
    pub language: Language,
    pub line_count: u32,
    pub size_bytes: u64,
    pub last_modified: u64,
    pub hash: u64,
    pub symbols: Vec<SymbolId>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Ir {
    pub symbols: HashMap<SymbolId, Symbol>,
    pub calls: Vec<Call>,
    pub files: HashMap<PathBuf, FileInfo>,
    pub taint_paths: Vec<TaintPath>,
    pub routes: Vec<Route>,
    pub http_calls: Vec<HttpCall>,
    /// Names of functions that wrap `fetch`/`axios` (e.g. a project's own
    /// `request()` / `apiFetch()` client). A literal-path call to one of these
    /// is really an HTTP call - resolved in the wrapper-promotion pass.
    pub http_wrappers: Vec<String>,
    /// `(callee_name, call)` for calls that *look* like HTTP requests through a
    /// wrapper (a literal URL path passed to a non-fetch function). Promoted to
    /// real `http_calls` when `callee_name` turns out to be an `http_wrapper`.
    pub http_call_candidates: Vec<(String, HttpCall)>,
    pub entry_points: Vec<SymbolId>,
    pub framework: Framework,
    pub metadata: IrMetadata,
    /// Infrastructure findings produced by infra parsers (K8s, Docker, Terraform).
    /// These are collected by Prism during analysis.
    pub infra_findings: Vec<Finding>,
    /// [`FindingKind::ParseFailure`] diagnostics for files whose parse
    /// panicked and was isolated (see [`panic_guard`]). Collected by Prism
    /// during analysis. `serde(default)` so IR snapshots written before this
    /// field existed still load.
    #[serde(default)]
    pub parse_failures: Vec<Finding>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct IrMetadata {
    pub total_files: usize,
    pub total_lines: u64,
    pub total_symbols: usize,
    pub language: Language,
    pub build_time_ms: u64,
    pub verum_version: String,
}

impl Ir {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn symbol_count(&self) -> usize {
        self.symbols.len()
    }

    pub fn merge(&mut self, other: Ir) {
        self.symbols.extend(other.symbols);
        self.calls.extend(other.calls);
        self.files.extend(other.files);
        self.taint_paths.extend(other.taint_paths);
        self.routes.extend(other.routes);
        self.http_calls.extend(other.http_calls);
        self.http_wrappers.extend(other.http_wrappers);
        self.http_call_candidates.extend(other.http_call_candidates);
        self.entry_points.extend(other.entry_points);
        self.infra_findings.extend(other.infra_findings);
        self.parse_failures.extend(other.parse_failures);
        self.metadata.total_files += other.metadata.total_files;
        self.metadata.total_lines += other.metadata.total_lines;
        self.metadata.total_symbols += other.metadata.total_symbols;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingKind {
    DeadFunction,
    DeadClass,
    DeadFile,
    UnreachableCode,
    ExactDuplicate,
    RenamedDuplicate,
    SemanticDuplicate,
    SqlInjection,
    XssVulnerability,
    WeakCrypto,
    HardcodedSecret,
    EvalUsage,
    MissingAuthMiddleware,
    MissingRoleCheck,
    PotentialIdor,
    WeakRandom,
    OpenRedirect,
    GodClass,
    CircularDependency,
    HighComplexity,
    LongFunction,
    TooManyParams,
    DeepNesting,
    NPlusOneQuery,
    StringConcatInLoop,
    ObjectInstantiationInLoop,
    /// React hook called without a dependency array - re-runs on every render.
    MissingHookDependencies,
    NamingInconsistency,
    ConventionViolation,
    OpenSecurityGroup,
    UnencryptedStorage,
    PublicResource,
    IamOverPermission,
    RunningAsRoot,
    PrivilegedContainer,
    MissingResourceLimits,
    MissingHealthProbes,
    UnpinnedImage,
    NoNetworkPolicy,
    SecretInEnvVar,
    HardcodedCredential,
    PciViolation,
    GdprViolation,
    Soc2Violation,
    /// A multi-hop "daisychain" through the call graph: an entry point that
    /// reaches a dangerous sink, optionally without an authorization/validation
    /// gate or while crossing a trust boundary.
    DangerousChain,
    // Rust systems insights - informational, not scored.
    /// `unsafe` block or `unsafe fn` - worth a SAFETY comment justifying
    /// why the invariants hold and why a safe abstraction wasn't enough.
    UnsafeUsage,
    /// `.unwrap()` / `.expect()` / `panic!` / `todo!` / `unimplemented!` /
    /// `unreachable!` - a panic path; in a hot loop it takes the process down.
    PanicRisk,
    /// A blocking call inside an `async fn` - stalls the executor thread and
    /// destroys tail latency; the canonical async foot-gun.
    BlockingInAsync,
    /// An unbounded channel/queue - grows without backpressure under load and
    /// silently adds latency; bounded-vs-unbounded is a standard probe.
    UnboundedChannel,
    /// Allocation or clone in a latency-sensitive path (per-packet / per-frame
    /// handler or a loop body) - the per-message-allocation anti-pattern.
    HotPathAllocation,
    /// A blocking lock (`Mutex`/`RwLock` `.lock`/`.read`/`.write`) taken on a
    /// latency-sensitive path - serializes the hot path and adds contention.
    LockOnHotPath,
    /// A lock guard (`Mutex`/`RwLock`/`RefCell`) held across an `.await` point -
    /// the classic async deadlock / `!Send` future bug: the task can be
    /// suspended and resumed on another thread while holding the guard.
    LockAcrossAwait,
    // Transport / protocol correctness - scored.
    /// One logical message emitted as multiple write calls on a datagram
    /// transport (e.g. a length prefix and payload written separately).
    /// Datagrams have no byte-stream continuity: losing any piece shears the
    /// message and permanently desynchronizes downstream length-prefix
    /// parsers.
    SplitDatagramMessage,
    /// A buffer above a safe MTU written to a datagram transport - it travels
    /// as multiple IP fragments, and one lost fragment loses the whole
    /// datagram, multiplying the effective loss rate.
    OversizedDatagram,
    /// An integer parsed from wire bytes used as an allocation size or read
    /// length with no visible bound check - a corrupted or hostile peer can
    /// stall the reader or force huge allocations.
    UnvalidatedLengthPrefix,
    /// User-controlled data reaches a filesystem path operation without
    /// sanitization - classic `../` traversal surface.
    PathTraversal,
    // Dependency audit - offline advisory match.
    /// A locked dependency version matches a known security advisory.
    VulnerableDependency,
    /// A locked dependency is flagged unmaintained/abandoned.
    UnmaintainedDependency,
    /// A crate is present at multiple major versions - build/binary bloat.
    DuplicateDependency,
    /// An `unsafe` block with no `// SAFETY:` comment documenting its invariant.
    MissingSafetyComment,
    /// A call that misuses a known crate's documented behaviour (e.g. tokio
    /// `interval` first-tick-immediate, udp-stream one-write-one-datagram).
    CrateApiMisuse,
    // Crypto hygiene - scored.
    /// `==`/`!=` used to compare a security-sensitive value (a MAC, tag,
    /// signature, token, secret, digest, or session/auth identifier) instead
    /// of a constant-time comparison - a naive comparison short-circuits on
    /// the first mismatched byte, leaking timing information an attacker can
    /// use to forge the value byte-by-byte.
    NonConstantTimeComparison,
    /// A constant/hardcoded nonce or IV reaches an AEAD `.encrypt(`/`.seal(`
    /// call, or a `Nonce` is built from a literal byte array - reusing a
    /// nonce with the same key breaks confidentiality (and, for most AEAD
    /// modes, integrity) of every message encrypted under it.
    StaticAeadNonce,
    /// Per-file parse or analysis work panicked on this file and was isolated;
    /// the rest of the run continued without it. Diagnostic only - it carries
    /// no score penalty and never gates a deploy. The message is a fixed
    /// phrase plus the file path, never the panic payload: payloads embed
    /// source locations and formatting that vary across rustc versions, and
    /// identical inputs must produce byte-identical findings.
    ParseFailure,
}

/// A performance objective a codebase can be optimised for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Objective {
    Latency,
    Throughput,
    Memory,
    Cpu,
    Determinism,
}

impl Objective {
    pub fn label(self) -> &'static str {
        match self {
            Objective::Latency => "latency",
            Objective::Throughput => "throughput",
            Objective::Memory => "memory",
            Objective::Cpu => "cpu",
            Objective::Determinism => "determinism",
        }
    }
}

/// Whether a construct helps or hurts an objective.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Hurts,
    Helps,
}

/// How a detected construct affects one performance objective.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfImpact {
    pub objective: Objective,
    pub direction: Direction,
    /// Relative magnitude, 1 (minor) ... 3 (major).
    pub weight: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub file: PathBuf,
    pub line: u32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub kind: FindingKind,
    pub severity: Severity,
    pub confidence: f32,
    pub file: PathBuf,
    pub line_start: u32,
    pub line_end: u32,
    pub symbol: Option<SymbolId>,
    pub message: String,
    pub suggestion: String,
    pub auto_fixable: bool,
    pub related: Vec<Location>,
}

impl Finding {
    /// The diagnostic emitted when per-file work on `path` panicked and was
    /// isolated by [`panic_guard::catch`].
    ///
    /// `what` must be a FIXED phrase (the mapper uses "parser panicked on
    /// this file", the analysis passes "analysis panicked on this file").
    /// Nothing from the panic payload is ever included: payloads carry
    /// source locations, addresses and formatting that differ across rustc
    /// versions and builds, and identical inputs must produce byte-identical
    /// findings.
    pub fn parse_failure(path: &std::path::Path, what: &str) -> Finding {
        Finding {
            id: format!("parse-failure-{}", path.display()),
            kind: FindingKind::ParseFailure,
            severity: Severity::Low,
            confidence: 1.0,
            file: path.to_path_buf(),
            line_start: 0,
            line_end: 0,
            symbol: None,
            message: format!("{what}: {}", path.display()),
            suggestion: "the file was skipped after the panic was isolated; the rest of the \
                         scan is complete - inspect the file by hand and report it as a \
                         parser bug"
                .to_string(),
            auto_fixable: false,
            related: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SimilarityKind {
    Exact,
    Renamed,
    Semantic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateGroup {
    pub canonical: SymbolId,
    pub duplicates: Vec<SymbolId>,
    pub similarity: SimilarityKind,
    pub call_sites_to_remap: Vec<Location>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Score {
    pub security: u8,
    pub architecture: u8,
    pub performance: u8,
    pub naming: u8,
    pub complexity: u8,
    pub test_coverage: u8,
    pub ui_consistency: u8,
    pub journey_coverage: u8,
    pub visual_accuracy: u8,
    pub infrastructure: u8,
    pub compliance: u8,
    pub overall: u8,
}

impl Score {
    pub fn compute_overall(&mut self) {
        self.compute_overall_masked(true, true, true);
    }

    /// Weighted overall over the dimensions that were actually measured.
    /// Unmeasured dimensions sit at their initial 100 - including them would
    /// inflate the overall, so callers mask out what their pipeline didn't run.
    /// Weights renormalize over the included set.
    pub fn compute_overall_masked(
        &mut self,
        include_ui: bool,
        include_journey: bool,
        include_compliance: bool,
    ) {
        let mut scored: Vec<(f32, f32)> = vec![
            (self.security as f32, 0.25),
            (self.architecture as f32, 0.15),
            (self.performance as f32, 0.10),
            (self.naming as f32, 0.08),
            (self.complexity as f32, 0.10),
            (self.infrastructure as f32, 0.12),
        ];
        if include_compliance {
            scored.push((self.compliance as f32, 0.10));
        }
        if include_ui {
            scored.push((self.ui_consistency as f32, 0.05));
        }
        if include_journey {
            scored.push((self.journey_coverage as f32, 0.05));
        }
        let total_weight: f32 = scored.iter().map(|(_, w)| w).sum();
        self.overall = (scored.iter().map(|(s, w)| s * w).sum::<f32>() / total_weight) as u8;
    }

    /// Cap the overall so a serious finding cannot be averaged away. A weighted
    /// mean lets one CRITICAL in a small, otherwise-clean codebase still score
    /// in the high 90s - the exact failure that let a fatally-broken repo read
    /// as 99/100. The headline number should never say "healthy" while a
    /// must-fix finding stands, so any CRITICAL forces overall <= 79 and any
    /// HIGH <= 89. Lower actual scores are left untouched.
    pub fn apply_severity_cap(&mut self, has_critical: bool, has_high: bool) {
        let cap = if has_critical {
            79
        } else if has_high {
            89
        } else {
            return;
        };
        self.overall = self.overall.min(cap);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRequest {
    pub id: String,
    pub kind: FindingKind,
    pub confidence: f32,
    pub finding: Finding,
    pub source_context: String,
    pub options: Vec<String>,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionResponse {
    pub id: String,
    pub action: String,
    pub reasoning: String,
    pub confidence: f32,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PipelineResult {
    pub score_before: Score,
    pub score_after: Score,
    pub lines_before: u64,
    pub lines_after: u64,
    pub passes: usize,
    pub findings: Vec<Finding>,
    pub auto_fixed: usize,
    pub ai_decisions: usize,
    pub human_review: usize,
    pub duplicate_groups: Vec<DuplicateGroup>,
    pub duration_ms: u64,
    pub deploy_gate_passed: bool,
    pub deploy_gate_reasons: Vec<String>,
}

/// Panic isolation for per-file work.
///
/// A fleet scan over tens of thousands of untrusted repositories must never
/// let one pathological file abort a run: the mapper's parse loop and the
/// per-file analysis loops wrap each file's work in [`panic_guard::catch`],
/// which converts a panic into `None` so the caller can record a
/// [`FindingKind::ParseFailure`] diagnostic and continue with every other
/// file's results intact.
///
/// The default panic hook prints its report to stderr the moment a panic
/// starts unwinding - long before `catch_unwind` ever sees it - which would
/// interleave spurious backtraces into parallel output for panics that are
/// fully handled. [`catch`] therefore marks its thread as silenced for the
/// duration of the closure; a process-wide hook (installed once, delegating
/// to whatever hook was set before it) drops the report for silenced threads
/// and behaves exactly as before everywhere else, so an *unexpected* panic
/// outside the guard still reports normally.
pub mod panic_guard {
    use std::cell::Cell;
    use std::panic::{self, AssertUnwindSafe};
    use std::sync::Once;

    thread_local! {
        /// True while THIS thread is inside [`catch`]; consulted by the
        /// process-wide hook. Thread-local rather than global so concurrent
        /// guarded and unguarded work never silence each other.
        static SILENCED: Cell<bool> = const { Cell::new(false) };
    }

    static INSTALL_HOOK: Once = Once::new();

    fn install_hook() {
        INSTALL_HOOK.call_once(|| {
            let previous = panic::take_hook();
            panic::set_hook(Box::new(move |info| {
                if !SILENCED.with(Cell::get) {
                    previous(info);
                }
            }));
        });
    }

    /// Run `f`, converting a panic into `None` and suppressing the default
    /// panic-hook stderr report for it. The previously installed hook is
    /// preserved (the silencing hook delegates to it), so panics outside a
    /// guarded section report exactly as before.
    ///
    /// The panic payload is deliberately discarded: payloads embed source
    /// locations and formatting that vary across rustc versions and builds,
    /// and anything derived from them would leak nondeterminism into
    /// findings. Callers emit [`crate::Finding::parse_failure`] with a fixed
    /// phrase instead.
    ///
    /// On the `AssertUnwindSafe`: every call site runs a closure that builds
    /// a fresh per-file result from shared *read-only* inputs (`&Ir`, config,
    /// pre-read lines). On panic that partial result is dropped wholesale, so
    /// no half-mutated state survives to be observed.
    pub fn catch<R>(f: impl FnOnce() -> R) -> Option<R> {
        install_hook();
        SILENCED.with(|s| s.set(true));
        let result = panic::catch_unwind(AssertUnwindSafe(f));
        SILENCED.with(|s| s.set(false));
        result.ok()
    }
}

#[cfg(test)]
mod panic_guard_tests {
    use super::*;

    #[test]
    fn catch_returns_the_value_when_nothing_panics() {
        assert_eq!(panic_guard::catch(|| 41 + 1), Some(42));
    }

    #[test]
    fn catch_converts_a_panic_into_none() {
        let caught: Option<()> = panic_guard::catch(|| panic!("deliberate test panic"));
        assert!(caught.is_none());
    }

    #[test]
    fn catch_recovers_for_subsequent_work_on_the_same_thread() {
        // A caught panic must leave the thread fully usable: the silencing
        // flag is cleared and later guarded work still returns values.
        let _: Option<()> = panic_guard::catch(|| panic!("first"));
        assert_eq!(panic_guard::catch(|| "still fine"), Some("still fine"));
    }

    #[test]
    fn parse_failure_finding_is_fixed_and_deterministic() {
        let path = std::path::Path::new("src/broken.rs");
        let a = Finding::parse_failure(path, "parser panicked on this file");
        let b = Finding::parse_failure(path, "parser panicked on this file");
        assert_eq!(a.id, b.id);
        assert_eq!(a.message, "parser panicked on this file: src/broken.rs");
        assert_eq!(a.kind, FindingKind::ParseFailure);
        assert_eq!(a.severity, Severity::Low);
        // The message must never embed panic payload text, which varies
        // across rustc versions; only the fixed phrase and the path appear.
        assert!(!a.message.contains("panicked at"));
    }
}
