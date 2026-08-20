//! `verum check` - the machine verdict.
//!
//! The cargo-check-shaped verification command a coding agent runs after every
//! edit: analyse the tree, print one verdict object, exit 0/1/2. Nothing else
//! goes to stdout; logs go to stderr.
//!
//! ## JSON contract (`--format json`, the default)
//!
//! ```json
//! {
//!   "pass": bool,
//!   "counts": { "critical": n, "high": n, "medium": n, "low": n },
//!   "findings": [
//!     {
//!       "kind": "SqlInjection",
//!       "severity": "critical",
//!       "file": "src/user.php",
//!       "line": 8,
//!       "message": "...",
//!       "why": "one sentence of consequence",
//!       "fix_hint": "the actionable next edit",
//!       "suggestion": "the detector's own suggestion text",
//!       "confidence": 0.95
//!     }
//!   ],
//!   "duration_ms": n
//! }
//! ```
//!
//! Fields are additive-only: consumers must tolerate new fields, and existing
//! fields never change meaning. `file` is relative to the analysed root with
//! `/` separators. `severity` is one of `critical|high|medium|low`.
//! Findings are sorted by severity (highest first), then file, line, kind,
//! and message, so identical input yields byte-identical `findings`.
//!
//! Info-level findings and `DangerousChain` mapping aids are excluded from
//! the verdict: they are exploratory surfaces the deploy gate also ignores,
//! and a machine verdict is about must-look findings. `counts` always sums
//! to `findings.len()`.
//!
//! ## Exit codes (stable)
//!
//! - `0` - pass: no finding at or above the `--fail-on` threshold.
//! - `1` - fail: at least one finding at or above the threshold.
//! - `2` - operational error: bad arguments, missing path, or the analysis
//!   itself failed. (clap also exits 2 on usage errors.)
//!
//! ## `--files` is a view, not a partial analysis
//!
//! Analysis is always whole-program - cross-file detectors (dead code,
//! duplicates, taint chains) stay correct. `--files a.php,b.rs` only filters
//! which findings appear in the verdict, and `pass`/`counts` follow the
//! filtered view so an agent gets a verdict scoped to its edit.
//!
//! ## Opt-in local stats
//!
//! When the environment variable `VERUM_STATS=1` is set, one JSON line per
//! invocation is appended to `$VERUM_STATS_FILE` (default
//! `~/.verum/stats.jsonl`): `{ts_ms, cmd, duration_ms, pass, counts}`.
//! No file contents or code text are recorded, and the stats write never
//! affects the verdict bytes or the exit code. Off by default.

use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::ValueEnum;
use serde::Serialize;

use verum_lumen::Prism;
use verum_mappa::Atlas;
use verum_nucleus::{DuplicateGroup, Finding, FindingKind, Ir, Severity};

use crate::{finding_kind_label, is_chain};

const CHECK_LONG_HELP: &str = "\
Runs the standard whole-program analysis and prints a single machine-readable
verdict to stdout (logs go to stderr).

JSON contract:
  {\"pass\": bool,
   \"counts\": {\"critical\": n, \"high\": n, \"medium\": n, \"low\": n},
   \"findings\": [{\"kind\", \"severity\", \"file\", \"line\", \"message\",
                 \"why\", \"fix_hint\", \"suggestion\", \"confidence\"}],
   \"duration_ms\": n}
Fields are additive-only. `file` is relative to the analysed root. Findings
are sorted (severity desc, file, line, kind, message) so identical input
yields identical output. Info-level findings and DangerousChain mapping aids
are excluded; counts always sum to findings.len().

Exit codes (stable):
  0  pass - no finding at or above --fail-on
  1  fail - at least one finding at or above --fail-on
  2  operational error (bad arguments, missing path, analysis failure)

--files is a VIEW filter: analysis is still whole-program so cross-file
detectors stay correct; only the verdict is narrowed to those files, and
pass/counts follow the filtered view.

Opt-in local stats: with VERUM_STATS=1 in the environment, one JSON line
per invocation ({ts_ms, cmd, duration_ms, pass, counts}) is appended to
$VERUM_STATS_FILE (default ~/.verum/stats.jsonl). No code text or file
contents are recorded; the verdict bytes and exit code are unaffected.";

#[derive(clap::Args)]
#[command(after_long_help = CHECK_LONG_HELP)]
pub(crate) struct CheckArgs {
    /// Path to analyse
    pub path: PathBuf,

    /// Output format for the verdict
    #[arg(long, value_enum, default_value_t = CheckFormat::Json)]
    pub format: CheckFormat,

    /// Lowest severity that makes the check fail (exit 1)
    #[arg(long, value_enum, default_value_t = FailOn::High)]
    pub fail_on: FailOn,

    /// Only show findings in these files (comma-separated; matched against
    /// the root-relative path, a path suffix on a component boundary, or the
    /// bare file name). A view filter - analysis stays whole-program.
    #[arg(long, value_delimiter = ',')]
    pub files: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum CheckFormat {
    Json,
    Text,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum FailOn {
    Critical,
    High,
    Medium,
    Low,
}

impl FailOn {
    fn rank(self) -> u8 {
        match self {
            FailOn::Critical => 4,
            FailOn::High => 3,
            FailOn::Medium => 2,
            FailOn::Low => 1,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct Verdict {
    pub pass: bool,
    pub counts: Counts,
    pub findings: Vec<VerdictFinding>,
    pub duration_ms: u64,
}

#[derive(Serialize, Default)]
pub(crate) struct Counts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

#[derive(Serialize)]
pub(crate) struct VerdictFinding {
    pub kind: String,
    pub severity: String,
    pub file: String,
    pub line: u32,
    pub message: String,
    pub why: String,
    pub fix_hint: String,
    pub suggestion: String,
    pub confidence: f32,
}

/// Run the check. Returns the process exit code: 0 pass, 1 fail, 2 error.
pub(crate) fn cmd_check(args: &CheckArgs) -> i32 {
    let start = Instant::now();

    if !args.path.exists() {
        eprintln!("verum check: path does not exist: {}", args.path.display());
        return 2;
    }

    let config = crate::make_atlas_config(&args.path);
    let root = config.root.clone();
    let standard = crate::load_standard_from_file(&args.path);

    let ir = match Atlas::new(config).build() {
        Ok(ir) => ir,
        Err(e) => {
            eprintln!("verum check: mapping failed: {e:#}");
            return 2;
        }
    };
    let result = match Prism::analyse_at(&ir, &standard, Some(&args.path)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("verum check: analysis failed: {e:#}");
            return 2;
        }
    };

    let mut findings = verdict_findings(
        &result.findings,
        &ir,
        &result.duplicate_groups,
        &root,
        &args.files,
    );
    findings.sort_by(|a, b| {
        severity_str_rank(&b.severity)
            .cmp(&severity_str_rank(&a.severity))
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.message.cmp(&b.message))
    });

    let mut counts = Counts::default();
    for f in &findings {
        match f.severity.as_str() {
            "critical" => counts.critical += 1,
            "high" => counts.high += 1,
            "medium" => counts.medium += 1,
            _ => counts.low += 1,
        }
    }
    let threshold = args.fail_on.rank();
    let pass = !findings
        .iter()
        .any(|f| severity_str_rank(&f.severity) >= threshold);

    let verdict = Verdict {
        pass,
        counts,
        findings,
        duration_ms: start.elapsed().as_millis() as u64,
    };

    match args.format {
        CheckFormat::Json => match serde_json::to_string(&verdict) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("verum check: could not serialize verdict: {e}");
                return 2;
            }
        },
        CheckFormat::Text => print_text(&verdict),
    }

    append_stats(&verdict);

    if verdict.pass {
        0
    } else {
        1
    }
}

fn print_text(v: &Verdict) {
    println!(
        "{} critical={} high={} medium={} low={} duration_ms={}",
        if v.pass { "PASS" } else { "FAIL" },
        v.counts.critical,
        v.counts.high,
        v.counts.medium,
        v.counts.low,
        v.duration_ms
    );
    for f in &v.findings {
        println!(
            "{} {} {}:{} {}",
            f.severity.to_uppercase(),
            f.kind,
            f.file,
            f.line,
            f.message
        );
        println!("  why: {}", f.why);
        println!("  fix: {}", f.fix_hint);
    }
}

/// Findings that belong in a machine verdict: everything except Info-level
/// notes and DangerousChain mapping aids (the same surfaces the deploy gate
/// ignores).
fn is_verdict_finding(f: &Finding) -> bool {
    f.severity != Severity::Info && !is_chain(&f.kind)
}

fn verdict_findings(
    findings: &[Finding],
    ir: &Ir,
    groups: &[DuplicateGroup],
    root: &Path,
    files_filter: &[String],
) -> Vec<VerdictFinding> {
    findings
        .iter()
        .filter(|f| is_verdict_finding(f))
        .map(|f| {
            let file = relative_slash_path(&f.file, root);
            VerdictFinding {
                kind: finding_kind_label(&f.kind).to_string(),
                severity: severity_str(&f.severity).to_string(),
                line: f.line_start,
                message: f.message.clone(),
                why: kind_why(&f.kind).to_string(),
                fix_hint: fix_hint(f, ir, groups, root),
                suggestion: f.suggestion.clone(),
                confidence: f.confidence,
                file,
            }
        })
        .filter(|vf| files_filter.is_empty() || matches_filter(&vf.file, files_filter))
        .collect()
}

/// True when `rel` (root-relative, `/`-separated) matches one of the filter
/// entries: exact path, path suffix on a component boundary, or bare name.
fn matches_filter(rel: &str, filters: &[String]) -> bool {
    filters.iter().any(|raw| {
        let f = raw.trim().trim_start_matches("./").replace('\\', "/");
        if f.is_empty() {
            return false;
        }
        rel == f || rel.ends_with(&format!("/{f}"))
    })
}

fn relative_slash_path(path: &Path, root: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.to_string_lossy().replace('\\', "/")
}

fn severity_str(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn severity_str_rank(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Detector reference: per-kind consequence ("why") and fix-hint templates.
//
// Structured as one exhaustive match per surface so adding a FindingKind
// variant is a compile error here, forcing the new kind to get a consequence
// sentence and an actionable hint. If a shared detector reference table lands
// elsewhere, `kind_why` is the piece to merge into it.
// ---------------------------------------------------------------------------

/// One sentence of consequence: what actually goes wrong if this stands.
pub(crate) fn kind_why(kind: &FindingKind) -> &'static str {
    use FindingKind::*;
    match kind {
        DeadFunction => "Unreferenced code still costs review and compile time, and silently diverges from the live path until someone trusts it by mistake.",
        DeadClass => "An unreferenced class is maintenance surface that can rot into a misleading, out-of-date copy of live behaviour.",
        DeadFile => "A file nothing references keeps getting read, reviewed, and refactored for zero runtime effect.",
        UnreachableCode => "Statements after this point can never execute, so any fix made there silently does nothing.",
        ExactDuplicate => "Two identical implementations drift apart: a bug fixed in one copy survives in the other.",
        RenamedDuplicate => "The same body under two names doubles the surface a bug fix has to reach.",
        SemanticDuplicate => "Two near-identical implementations invite divergent fixes and inconsistent behaviour.",
        SqlInjection => "Attacker-controlled input reaches a SQL query, allowing data theft, tampering, or full database takeover.",
        XssVulnerability => "User input echoed without escaping lets an attacker run script in other users' browsers and steal their sessions.",
        WeakCrypto => "This algorithm is cryptographically broken; hashes can be collided or brute-forced far below the intended cost.",
        HardcodedSecret => "A secret committed to source is exposed to everyone with repo access and survives forever in history.",
        EvalUsage => "eval executes arbitrary strings, so any input that reaches it is remote code execution.",
        MissingAuthMiddleware => "The endpoint is reachable without authentication, exposing its data and actions to anyone.",
        MissingRoleCheck => "Any authenticated user can perform this privileged action, not just the role it was meant for.",
        PotentialIdor => "A request-supplied id is used directly, letting one user read or modify another user's records.",
        WeakRandom => "This RNG is predictable, so tokens or secrets derived from it can be guessed.",
        OpenRedirect => "An attacker can craft a link on your domain that forwards victims to a site they control.",
        GodClass => "A class this large concentrates unrelated responsibilities, so every change risks breaking something else it owns.",
        CircularDependency => "Modules in a cycle cannot be built, tested, or understood in isolation, and changes ripple around the loop.",
        HighComplexity => "This many branches cannot be reasoned about or tested exhaustively, so edge-case bugs hide here.",
        LongFunction => "A function this long mixes multiple jobs, making every edit riskier and review slower.",
        TooManyParams => "Long parameter lists get called with arguments in the wrong order and resist future change.",
        DeepNesting => "Deeply nested control flow hides which conditions actually guard the inner code.",
        NPlusOneQuery => "A query per loop iteration multiplies database round-trips with data size, collapsing under production load.",
        StringConcatInLoop => "Rebuilding the string every iteration is quadratic work that degrades sharply as input grows.",
        ObjectInstantiationInLoop => "Constructing the same object every iteration burns allocations the loop never needed.",
        MissingHookDependencies => "Without a dependency array the hook re-runs on every render, causing wasted work or infinite loops.",
        NamingInconsistency => "A name that breaks the local convention misleads readers and makes the symbol hard to find.",
        ConventionViolation => "Code that ignores the configured convention increases friction for everyone who works in this tree.",
        OpenSecurityGroup => "The port is reachable from the entire internet, inviting scanning and brute-force from anywhere.",
        UnencryptedStorage => "Data at rest is readable in plaintext by anyone who obtains the disk, snapshot, or bucket.",
        PublicResource => "The resource is world-readable, so its contents are one URL away from being exfiltrated.",
        IamOverPermission => "Wildcard permissions turn any compromise of this principal into a compromise of everything it can touch.",
        RunningAsRoot => "A container process running as root becomes full host-level power after any escape or misconfiguration.",
        PrivilegedContainer => "Privileged mode disables container isolation, giving the workload effectively root on the node.",
        MissingResourceLimits => "Without limits one runaway pod can starve every other workload on the node.",
        MissingHealthProbes => "Without probes the orchestrator keeps routing traffic to a dead or unready instance.",
        UnpinnedImage => "A floating tag can silently change under you, deploying code that was never reviewed or tested.",
        NoNetworkPolicy => "Every pod can talk to every other pod, so one compromised workload can reach them all.",
        SecretInEnvVar => "A literal secret in the manifest is visible to anyone who can read the spec, the diff, or the process environment.",
        HardcodedCredential => "A credential baked into configuration leaks with the file and cannot be rotated without a redeploy.",
        PciViolation => "This breaks a PCI-DSS control, exposing cardholder data and the organisation to fines and audit failure.",
        GdprViolation => "This breaks a GDPR obligation on personal data, creating regulatory and breach-notification exposure.",
        Soc2Violation => "This weakens a SOC 2 control an auditor will flag, undermining the trust report customers rely on.",
        DangerousChain => "An entry point reaches a dangerous sink without a visible gate, so one crafted request can trigger the sink.",
        UnsafeUsage => "unsafe suspends the compiler's memory-safety guarantees, so a mistake here is undefined behaviour, not a bug report.",
        PanicRisk => "This path panics instead of returning an error; on a server that can take the whole process down.",
        BlockingInAsync => "A blocking call inside async stalls the executor thread, freezing every task scheduled on it.",
        UnboundedChannel => "With no capacity bound, a slow consumer lets the queue grow without limit, adding latency until memory runs out.",
        HotPathAllocation => "Allocating per message puts the allocator on the hot path, costing throughput and adding latency jitter.",
        LockOnHotPath => "A blocking lock on the hot path serializes it, turning concurrency into contention.",
        LockAcrossAwait => "Holding a guard across .await can deadlock the executor and makes the future non-Send.",
        SplitDatagramMessage => "Datagrams have no byte-stream continuity: losing one piece shears the message and desynchronizes the receiver's parser.",
        OversizedDatagram => "Above the MTU the datagram travels as IP fragments, and losing any fragment loses the whole message.",
        UnvalidatedLengthPrefix => "A hostile or corrupt peer can supply a huge length and force enormous allocations or a stalled reader.",
        PathTraversal => "User input in a filesystem path lets an attacker escape the intended directory with `..` and read or write arbitrary files.",
        VulnerableDependency => "The locked version has a published vulnerability that attackers can look up and exploit directly.",
        UnmaintainedDependency => "An abandoned dependency will never receive security fixes, so every future CVE in it is yours to carry.",
        DuplicateDependency => "Multiple major versions of one crate bloat the binary and can split types across incompatible versions.",
        MissingSafetyComment => "Without a stated invariant, the next editor cannot know what keeps this unsafe block sound.",
        CrateApiMisuse => "The call contradicts the crate's documented behaviour, so the code does something other than what it reads as doing.",
        NonConstantTimeComparison => "A short-circuiting comparison leaks timing an attacker can use to forge the secret byte by byte.",
        StaticAeadNonce => "Reusing a nonce with the same key breaks confidentiality, and for most AEAD modes integrity, of every message.",
        ParseFailure => "This file was skipped after its parser panicked, so findings in it are missing from the results.",
        StaleSuppression => "This verum:ignore comment suppresses nothing, so it either documents a fixed issue or sits ready to swallow the next real finding at that spot.",
    }
}

/// The actionable next edit for `f`. Dead-code and duplicate findings surface
/// the faber fix planner's plan (symbol, line range, canonical target, call
/// sites); every other kind interpolates a per-kind template with the
/// finding's specifics. Never empty.
pub(crate) fn fix_hint(f: &Finding, ir: &Ir, groups: &[DuplicateGroup], root: &Path) -> String {
    use FindingKind::*;
    let spot = format!("{}:{}", relative_slash_path(&f.file, root), f.line_start);
    let name = symbol_name(f, ir);
    match &f.kind {
        DeadFunction => dead_code_hint(f, ir, root, "function"),
        DeadClass => dead_code_hint(f, ir, root, "class"),
        DeadFile => format!(
            "delete {}; nothing references it",
            relative_slash_path(&f.file, root)
        ),
        UnreachableCode => format!(
            "delete the unreachable statements at {spot}, or fix the early return/break/throw above them if they were meant to run"
        ),
        ExactDuplicate | RenamedDuplicate | SemanticDuplicate => {
            duplicate_hint(f, ir, groups, root)
        }
        SqlInjection => format!(
            "bind the user input as a query parameter (prepared statement / query-builder placeholder) instead of concatenating it into the SQL at {spot}"
        ),
        XssVulnerability => format!(
            "escape the value on output at {spot} (htmlspecialchars / the framework's escaping syntax) instead of emitting raw input"
        ),
        WeakCrypto => format!(
            "replace the weak algorithm at {spot}: password_hash/bcrypt/argon2 for passwords, SHA-256 or better for digests"
        ),
        HardcodedSecret => format!(
            "move the literal secret at {spot} into an environment variable or secret manager, then rotate the leaked value"
        ),
        EvalUsage => format!(
            "replace eval at {spot} with explicit dispatch (a whitelisted map of allowed operations) or a proper parser for the data"
        ),
        MissingAuthMiddleware => format!(
            "attach authentication middleware to the route at {spot} (e.g. wrap it in the auth middleware group)"
        ),
        MissingRoleCheck => format!(
            "add an explicit role/permission check before the privileged operation at {spot}"
        ),
        PotentialIdor => format!(
            "scope the lookup at {spot} to the authenticated user (filter by owner id) or add an explicit ownership check before returning the record"
        ),
        WeakRandom => format!(
            "use a cryptographically secure RNG at {spot} (random_bytes/random_int, secrets, crypto.randomBytes, OsRng) for security-sensitive values"
        ),
        OpenRedirect => format!(
            "validate the redirect target at {spot} against an allowlist of internal paths before redirecting"
        ),
        GodClass => hint_with_name(
            &name,
            |n| format!("split `{n}` by responsibility: extract cohesive method clusters into their own classes"),
            format!("split the class at {spot} by responsibility: extract cohesive method clusters into their own classes"),
        ),
        CircularDependency => format!(
            "break the cycle involving {spot}: invert one edge by extracting an interface/trait or moving the shared type into a third module"
        ),
        HighComplexity => hint_with_name(
            &name,
            |n| format!("extract the branch arms of `{n}` into named helper functions until each function has one job"),
            format!("extract the branch arms of the function at {spot} into named helper functions"),
        ),
        LongFunction => hint_with_name(
            &name,
            |n| format!("split `{n}` (lines {}-{}) into smaller functions, one per logical step", f.line_start, f.line_end),
            format!("split the function at {spot} into smaller functions, one per logical step"),
        ),
        TooManyParams => hint_with_name(
            &name,
            |n| format!("group `{n}`'s parameters into a struct/options object so call sites name what they pass"),
            format!("group the parameters of the function at {spot} into a struct/options object"),
        ),
        DeepNesting => format!(
            "flatten the nesting at {spot} with early returns/guard clauses, or extract the inner block into a function"
        ),
        NPlusOneQuery => format!(
            "hoist the query out of the loop at {spot}: batch it with a single WHERE IN, or eager-load the relation before the loop"
        ),
        StringConcatInLoop => format!(
            "accumulate the parts and join once after the loop at {spot} (or write into a builder/buffer)"
        ),
        ObjectInstantiationInLoop => format!(
            "hoist the construction out of the loop at {spot} and reuse one instance across iterations"
        ),
        MissingHookDependencies => format!(
            "add a dependency array to the hook call at {spot} listing exactly the values the effect reads"
        ),
        NamingInconsistency => hint_with_name(
            &name,
            |n| format!("rename `{n}` to match the dominant convention for its kind ({})", f.suggestion),
            format!("rename the symbol at {spot} to match the dominant convention ({})", f.suggestion),
        ),
        ConventionViolation => hint_with_name(
            &name,
            |n| format!("rename `{n}` to follow the configured convention ({})", f.suggestion),
            format!("rename the symbol at {spot} to follow the configured convention ({})", f.suggestion),
        ),
        OpenSecurityGroup => format!(
            "restrict the ingress CIDR at {spot} to the specific ranges that need access instead of 0.0.0.0/0"
        ),
        UnencryptedStorage => format!(
            "enable at-rest encryption on the resource at {spot} (server_side_encryption / encrypted = true / a KMS key)"
        ),
        PublicResource => format!(
            "make the resource at {spot} private and serve public content through signed URLs or a CDN distribution"
        ),
        IamOverPermission => format!(
            "replace the wildcard actions/resources at {spot} with the specific actions and ARNs the workload actually uses"
        ),
        RunningAsRoot => format!(
            "run as a non-root user: add `USER <uid>` to the Dockerfile or set securityContext.runAsNonRoot: true at {spot}"
        ),
        PrivilegedContainer => format!(
            "remove privileged: true at {spot} and grant only the specific capabilities needed via securityContext.capabilities.add"
        ),
        MissingResourceLimits => format!(
            "set resources.requests and resources.limits (cpu, memory) for the container at {spot}"
        ),
        MissingHealthProbes => format!(
            "add livenessProbe and readinessProbe to the container at {spot}"
        ),
        UnpinnedImage => format!(
            "pin the image at {spot} to an immutable digest (image@sha256:...) or an exact version tag"
        ),
        NoNetworkPolicy => format!(
            "add a default-deny NetworkPolicy for the namespace at {spot}, then allow only the required flows"
        ),
        SecretInEnvVar => format!(
            "replace the literal env value at {spot} with a secretKeyRef (or a mounted Secret volume)"
        ),
        HardcodedCredential => format!(
            "move the credential at {spot} into a secret store (Kubernetes Secret, Vault, SSM) and rotate it"
        ),
        PciViolation => format!(
            "close the PCI-DSS control gap at {spot}: {}",
            detail_or(&f.message, "see the finding message")
        ),
        GdprViolation => format!(
            "close the GDPR gap at {spot}: {}",
            detail_or(&f.message, "see the finding message")
        ),
        Soc2Violation => format!(
            "close the SOC 2 control gap at {spot}: {}",
            detail_or(&f.message, "see the finding message")
        ),
        DangerousChain => format!(
            "add an authorization/validation gate on the entry point before the sink in this chain ({})",
            detail_or(&f.message, "see the chain description")
        ),
        UnsafeUsage => format!(
            "justify the unsafe at {spot} with a `// SAFETY:` comment stating the invariant, or replace it with a safe abstraction"
        ),
        PanicRisk => format!(
            "replace the panic path at {spot} (unwrap/expect/panic!) with error propagation (`?`) or explicit handling"
        ),
        BlockingInAsync => format!(
            "move the blocking call at {spot} into spawn_blocking, or switch to the async equivalent API"
        ),
        UnboundedChannel => format!(
            "use a bounded channel with an explicit capacity at {spot} and handle backpressure at the send site"
        ),
        HotPathAllocation => format!(
            "hoist the allocation/clone at {spot} out of the per-message path: reuse a buffer or preallocate outside the loop"
        ),
        LockOnHotPath => format!(
            "move the lock at {spot} off the hot path: shard the state, use atomics, or snapshot outside the loop"
        ),
        LockAcrossAwait => format!(
            "drop the guard before the .await at {spot} (scope it in a block), or switch to an async-aware lock"
        ),
        SplitDatagramMessage => format!(
            "assemble the length prefix and payload into one buffer and emit them in a single write call at {spot}"
        ),
        OversizedDatagram => format!(
            "keep each datagram under the safe MTU at {spot}: split the message at the application layer or use a stream transport"
        ),
        UnvalidatedLengthPrefix => format!(
            "bound the parsed length at {spot} against a protocol maximum before using it as an allocation size or read length"
        ),
        PathTraversal => format!(
            "canonicalize the path at {spot} and verify it stays under the allowed base directory before use; reject `..` components"
        ),
        VulnerableDependency => format!(
            "upgrade the dependency to a version the advisory lists as fixed ({})",
            detail_or(&f.message, "see the advisory in the finding message")
        ),
        UnmaintainedDependency => format!(
            "plan a migration off the unmaintained dependency ({}) to a maintained alternative",
            detail_or(&f.message, "see the finding message")
        ),
        DuplicateDependency => format!(
            "unify the version requirements so one major version remains ({})",
            detail_or(&f.message, "run `cargo tree -d` to see the split")
        ),
        MissingSafetyComment => format!(
            "add a `// SAFETY:` comment above the unsafe block at {spot} stating the invariant that makes it sound"
        ),
        CrateApiMisuse => format!(
            "adjust the call at {spot} to the crate's documented behaviour: {}",
            detail_or(&f.message, "see the finding message")
        ),
        NonConstantTimeComparison => format!(
            "replace the `==` at {spot} with a constant-time comparison: subtle::ConstantTimeEq's ct_eq() (add `subtle` to [dependencies]) in Rust, hash_equals() in PHP, hmac.compare_digest() in Python"
        ),
        StaticAeadNonce => format!(
            "generate a fresh nonce per encryption at {spot} (random via OsRng, or a strictly increasing counter); never a literal"
        ),
        ParseFailure => format!(
            "inspect {} by hand (the parser panicked and the file was skipped) and report it as a parser bug",
            relative_slash_path(&f.file, root)
        ),
        StaleSuppression => format!(
            "delete the stale verum:ignore comment at {spot}, or fix its kind list so it matches what is actually flagged there"
        ),
    }
}

/// Faber's dead-code plan as a hint: symbol, exact line range, and whether the
/// planner considers it safe to delete outright.
fn dead_code_hint(f: &Finding, ir: &Ir, root: &Path, word: &str) -> String {
    let rel = relative_slash_path(&f.file, root);
    if let Some(sym) = f.symbol.and_then(|sid| ir.symbols.get(&sid)) {
        if verum_faber::dead_code::is_safe_to_auto_delete(sym, ir) {
            format!(
                "delete {word} `{}` (lines {}-{} in {rel}); nothing references it",
                sym.name, sym.line_start, sym.line_end
            )
        } else {
            format!(
                "`{}` (lines {}-{} in {rel}) looks dead, but sits on a surface the fix planner won't auto-delete (framework hook, magic dispatch, or test file); verify no dynamic caller exists, then delete it",
                sym.name, sym.line_start, sym.line_end
            )
        }
    } else {
        format!(
            "delete the dead {word} at {rel}:{}; nothing references it",
            f.line_start
        )
    }
}

/// Faber's duplicate plan as a hint: which copy is canonical, where it lives,
/// and how many call sites the planner would remap.
fn duplicate_hint(f: &Finding, ir: &Ir, groups: &[DuplicateGroup], root: &Path) -> String {
    if let Some(sid) = f.symbol {
        for g in groups {
            if g.duplicates.contains(&sid) {
                if let (Some(dup), Some(canon)) =
                    (ir.symbols.get(&sid), ir.symbols.get(&g.canonical))
                {
                    let canon_rel = relative_slash_path(&canon.file, root);
                    return format!(
                        "replace the body of `{}` with a call to canonical `{}` in {canon_rel}:{} (or remap its {} call site(s) to `{}` and delete `{}`)",
                        dup.name,
                        canon.name,
                        canon.line_start,
                        g.call_sites_to_remap.len(),
                        canon.name,
                        dup.name
                    );
                }
            }
            if g.canonical == sid {
                if let Some(canon) = ir.symbols.get(&sid) {
                    return format!(
                        "keep `{}` as the canonical copy; remap the {} call site(s) of its {} duplicate(s) to it and delete them",
                        canon.name,
                        g.call_sites_to_remap.len(),
                        g.duplicates.len()
                    );
                }
            }
        }
    }
    "merge the duplicate implementations into one canonical function and delete the others"
        .to_string()
}

/// Prefer `f(name)` when a symbol name is known, else the fallback.
fn hint_with_name(
    name: &Option<String>,
    with: impl FnOnce(&str) -> String,
    fallback: String,
) -> String {
    match name {
        Some(n) => with(n),
        None => fallback,
    }
}

/// The finding's message when it adds detail, else the fallback phrase.
fn detail_or(message: &str, fallback: &str) -> String {
    let m = message.trim();
    if m.is_empty() {
        fallback.to_string()
    } else {
        m.to_string()
    }
}

/// The symbol name for a finding: the IR symbol when linked, else the first
/// `backticked` token in the message.
fn symbol_name(f: &Finding, ir: &Ir) -> Option<String> {
    if let Some(sym) = f.symbol.and_then(|sid| ir.symbols.get(&sid)) {
        return Some(sym.name.clone());
    }
    let start = f.message.find('`')?;
    let rest = &f.message[start + 1..];
    let end = rest.find('`')?;
    let name = &rest[..end];
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

// ---------------------------------------------------------------------------
// Opt-in local stats (VERUM_STATS=1). Never affects the verdict.
// ---------------------------------------------------------------------------

fn append_stats(verdict: &Verdict) {
    if std::env::var("VERUM_STATS").as_deref() != Ok("1") {
        return;
    }
    let path = match std::env::var("VERUM_STATS_FILE") {
        Ok(p) if !p.is_empty() => PathBuf::from(p),
        _ => match std::env::var("HOME") {
            Ok(home) if !home.is_empty() => PathBuf::from(home).join(".verum").join("stats.jsonl"),
            _ => {
                eprintln!(
                    "verum check: VERUM_STATS=1 but no VERUM_STATS_FILE and no HOME; stats skipped"
                );
                return;
            }
        },
    };
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let line = serde_json::json!({
        "ts_ms": ts_ms,
        "cmd": "check",
        "duration_ms": verdict.duration_ms,
        "pass": verdict.pass,
        "counts": {
            "critical": verdict.counts.critical,
            "high": verdict.counts.high,
            "medium": verdict.counts.medium,
            "low": verdict.counts.low,
        },
    });
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("verum check: could not create stats dir: {e}");
            return;
        }
    }
    use std::io::Write as _;
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(mut file) => {
            if let Err(e) = writeln!(file, "{line}") {
                eprintln!("verum check: could not append stats: {e}");
            }
        }
        Err(e) => eprintln!("verum check: could not open stats file: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every FindingKind variant, in declaration order. `kind_why` and
    /// `fix_hint` match exhaustively, so a new variant fails compilation
    /// there; add it here too so the coverage assertions see it.
    fn all_kinds() -> Vec<FindingKind> {
        use FindingKind::*;
        vec![
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
            DangerousChain,
            UnsafeUsage,
            PanicRisk,
            BlockingInAsync,
            UnboundedChannel,
            HotPathAllocation,
            LockOnHotPath,
            LockAcrossAwait,
            SplitDatagramMessage,
            OversizedDatagram,
            UnvalidatedLengthPrefix,
            PathTraversal,
            VulnerableDependency,
            UnmaintainedDependency,
            DuplicateDependency,
            MissingSafetyComment,
            CrateApiMisuse,
            NonConstantTimeComparison,
            StaticAeadNonce,
            ParseFailure,
            StaleSuppression,
        ]
    }

    fn synthetic_finding(kind: FindingKind) -> Finding {
        Finding {
            id: "t-1".to_string(),
            kind,
            severity: Severity::High,
            confidence: 0.9,
            file: PathBuf::from("/repo/src/thing.rs"),
            line_start: 10,
            line_end: 42,
            symbol: None,
            message: "detector message about `target_symbol`".to_string(),
            suggestion: "detector suggestion".to_string(),
            auto_fixable: false,
            related: Vec::new(),
            fingerprint: String::new(),
        }
    }

    #[test]
    fn every_kind_has_a_nonempty_why_and_fix_hint() {
        let ir = Ir::new();
        let groups: Vec<DuplicateGroup> = Vec::new();
        let root = Path::new("/repo");
        for kind in all_kinds() {
            let why = kind_why(&kind);
            assert!(
                !why.trim().is_empty(),
                "kind {kind:?} has an empty why sentence"
            );
            assert!(
                why.trim().ends_with('.'),
                "kind {kind:?}'s why is not a sentence: {why:?}"
            );
            let f = synthetic_finding(kind.clone());
            let hint = fix_hint(&f, &ir, &groups, root);
            assert!(
                !hint.trim().is_empty(),
                "kind {kind:?} produced an empty fix_hint"
            );
        }
    }

    #[test]
    fn hints_interpolate_the_findings_location() {
        let ir = Ir::new();
        let f = synthetic_finding(FindingKind::SqlInjection);
        let hint = fix_hint(&f, &ir, &[], Path::new("/repo"));
        assert!(
            hint.contains("src/thing.rs:10"),
            "hint should cite the root-relative location: {hint}"
        );
    }

    #[test]
    fn constant_time_hint_names_the_concrete_replacement() {
        let ir = Ir::new();
        let f = synthetic_finding(FindingKind::NonConstantTimeComparison);
        let hint = fix_hint(&f, &ir, &[], Path::new("/repo"));
        assert!(hint.contains("ct_eq"), "hint: {hint}");
        assert!(hint.contains("subtle"), "hint: {hint}");
    }

    #[test]
    fn info_and_chain_findings_are_not_verdict_findings() {
        let mut f = synthetic_finding(FindingKind::UnsafeUsage);
        f.severity = Severity::Info;
        assert!(!is_verdict_finding(&f));
        let mut c = synthetic_finding(FindingKind::DangerousChain);
        c.severity = Severity::High;
        assert!(!is_verdict_finding(&c));
        let s = synthetic_finding(FindingKind::SqlInjection);
        assert!(is_verdict_finding(&s));
    }

    #[test]
    fn files_filter_matches_relative_suffix_and_bare_name() {
        let filters = vec!["thing.rs".to_string()];
        assert!(matches_filter("src/thing.rs", &filters));
        assert!(matches_filter("thing.rs", &filters));
        assert!(!matches_filter("src/other.rs", &filters));
        // Component boundary: "everything.rs" must not match "thing.rs".
        assert!(!matches_filter("src/everything.rs", &filters));
        let nested = vec!["src/thing.rs".to_string()];
        assert!(matches_filter("src/thing.rs", &nested));
        assert!(matches_filter("app/src/thing.rs", &nested));
        assert!(!matches_filter("src/thing.rs.bak", &nested));
    }

    #[test]
    fn symbol_name_falls_back_to_backticked_token() {
        let ir = Ir::new();
        let f = synthetic_finding(FindingKind::LongFunction);
        assert_eq!(symbol_name(&f, &ir).as_deref(), Some("target_symbol"));
        let mut plain = synthetic_finding(FindingKind::LongFunction);
        plain.message = "no names here".to_string();
        assert_eq!(symbol_name(&plain, &ir), None);
    }
}
