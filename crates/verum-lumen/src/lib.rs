pub mod app_security;
pub mod chains;
pub mod complexity;
pub mod crate_semantics;
pub mod crypto_hygiene;
pub mod dead_code;
pub mod deps;
pub mod duplicates;
pub mod fingerprint;
/// In-memory entry points for the out-of-tree fuzz targets in `fuzz/`.
/// Compiled only under the off-by-default `fuzzing` feature.
#[cfg(feature = "fuzzing")]
pub mod fuzz_api;
pub mod infrastructure;
pub mod lcov;
pub mod loc;
pub mod naming;
pub mod performance;
pub mod rbac;
pub mod reachability;
pub mod rust_insights;
pub mod scan;
pub mod scoring;
pub mod security;
pub mod suppress;
pub mod taint;
pub mod transport;

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use verum_nucleus::{DuplicateGroup, Finding, FindingKind, Ir, Score};

/// True for files that are not shipped application code - tests, examples,
/// vendored dependencies, and generated output. Code-quality and security
/// findings in these are noise (a hardcoded password in a test fixture, an
/// unused test helper), so they are filtered from the default report. The
/// files stay in the IR so their calls still count toward reachability.
///
/// `fixtures` is deliberately *not* auxiliary: this project's own test suite
/// points the analyzer at fixture trees as real targets.
pub fn is_auxiliary_path(path: &str) -> bool {
    // Normalize backslashes first: callers pass `to_string_lossy()` of a raw
    // (OS-native) path, and on Windows that means `\`-separated. Every check
    // below is written against `/`-separated literals; without this, the
    // `tests/fixtures` substring check below never matches on Windows. A
    // no-op on Unix paths, which are already `/`-separated.
    let path = path.replace('\\', "/");
    let path = path.as_str();
    // Verum's own test suite points the analyzer at `tests/fixtures/` trees as
    // deliberate targets. A real project's `test/fixtures/` or
    // `resources/test/` of intentionally-broken code (e.g. a linter's test
    // corpus) stays auxiliary via the segment check below.
    if path.contains("tests/fixtures") {
        return false;
    }
    // Match on whole path segments so a leading or trailing `vendor/` counts the
    // same as a nested `/vendor/`.
    const DIR_SEGMENTS: &[&str] = &[
        "test",
        "tests",
        "__tests__",
        "spec",
        "specs",
        "example",
        "examples",
        "sample",
        "samples",
        "vendor",
        "node_modules",
        "benches",
        "bench",
        "testdata",
        "mocks",
        "dist",
        "build",
        "target",
        "generated",
        "third_party",
        "third-party",
        "external",
        // Web-served assets: overwhelmingly bundled/vendored JS/CSS, not
        // first-party source you would fix a finding in.
        "public",
        "static",
        "assets",
        "plugins",
    ];
    if path
        .split(['/', '\\'])
        .any(|seg| DIR_SEGMENTS.contains(&seg))
    {
        return true;
    }
    const FILE_MARKERS: &[&str] = &[
        "_test.",
        ".test.",
        ".spec.",
        "_spec.",
        ".min.js",
        ".pb.go",
        "_pb2.py",
        ".generated.",
    ];
    FILE_MARKERS.iter().any(|m| path.contains(m))
}

/// True for files that are part of a test suite, as opposed to the wider set
/// of non-shipped files [`is_auxiliary_path`] covers (which also sweeps up
/// vendored dependencies, examples and build output - none of which are
/// tests).
///
/// This is the narrow sibling of [`is_auxiliary_path`], sharing its
/// whole-segment matching so a leading or trailing `tests/` counts the same as
/// a nested `/tests/`, and its `tests/fixtures` carve-out: Verum's own suite
/// points the analyzer at fixture trees as real targets, and a fixture tree
/// that classified as its own test suite would report a meaningless 100%.
///
/// Used to seed the roots of the static test-reachability walk, so a false
/// positive here inflates reachability - the reason it lists only markers that
/// unambiguously name a test.
pub fn is_test_path(path: &str) -> bool {
    // See the matching comment in `is_auxiliary_path`: normalize `\` to `/`
    // so the `tests/fixtures` check below still matches a Windows-native path.
    let path = path.replace('\\', "/");
    let path = path.as_str();
    if path.contains("tests/fixtures") {
        return false;
    }
    const DIR_SEGMENTS: &[&str] = &["test", "tests", "__tests__", "spec", "specs"];
    if path
        .split(['/', '\\'])
        .any(|seg| DIR_SEGMENTS.contains(&seg))
    {
        return true;
    }
    const FILE_MARKERS: &[&str] = &["_test.", ".test.", ".spec.", "_spec."];
    let file_name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    FILE_MARKERS.iter().any(|m| file_name.contains(m))
        // pytest's convention, anchored to the start so `latest_build.py` is
        // not a test.
        || file_name.starts_with("test_")
        || file_name == "conftest.py"
}

/// Infrastructure and compliance findings describe a deployed artifact, not
/// source hygiene, so they are reported wherever they occur - including in a
/// sample manifest under `examples/`. Everything else is suppressed in
/// auxiliary files by [`is_auxiliary_path`].
fn kind_survives_in_auxiliary(kind: &FindingKind) -> bool {
    matches!(
        kind,
        FindingKind::OpenSecurityGroup
            | FindingKind::UnencryptedStorage
            | FindingKind::PublicResource
            | FindingKind::IamOverPermission
            | FindingKind::RunningAsRoot
            | FindingKind::PrivilegedContainer
            | FindingKind::MissingResourceLimits
            | FindingKind::MissingHealthProbes
            | FindingKind::UnpinnedImage
            | FindingKind::NoNetworkPolicy
            | FindingKind::SecretInEnvVar
            | FindingKind::HardcodedCredential
            | FindingKind::PciViolation
            | FindingKind::GdprViolation
            | FindingKind::Soc2Violation
            // A panic that had to be isolated is a fact about the run itself;
            // suppressing it in a vendored or test file would hide that the
            // scan of that file is incomplete.
            | FindingKind::ParseFailure
            // A stale `verum:ignore` is a fact about the suppression comment,
            // and it can only arise in a file that already surfaces findings;
            // hiding it in auxiliary files would let suppressions rot there.
            | FindingKind::StaleSuppression
    )
}

/// Which naming convention a symbol category should follow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NamingConvention {
    PascalCase,
    #[serde(alias = "camelCase")]
    CamelCase,
    #[serde(alias = "snake_case")]
    SnakeCase,
    #[serde(alias = "SCREAMING_SNAKE_CASE")]
    ScreamingSnakeCase,
}

/// Per-language naming rules.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NamingRules {
    pub classes: Option<NamingConvention>,
    pub methods: Option<NamingConvention>,
    pub functions: Option<NamingConvention>,
    pub variables: Option<NamingConvention>,
    pub properties: Option<NamingConvention>,
    pub constants: Option<NamingConvention>,
    pub components: Option<NamingConvention>,
}

/// Naming configuration keyed by language.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NamingConfig {
    pub php: Option<NamingRules>,
    pub typescript: Option<NamingRules>,
    pub javascript: Option<NamingRules>,
    pub rust: Option<NamingRules>,
    pub python: Option<NamingRules>,
    pub go: Option<NamingRules>,
}

/// Security configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Hash functions to always forbid (e.g. "des", "rc4").
    pub forbid_weak_crypto: Vec<String>,
    /// Contexts where weak crypto is acceptable, keyed by function name.
    /// e.g. "md5" -> {"cache_key", "etag", "gravatar"}
    pub weak_crypto_allowlist: HashMap<String, HashSet<String>>,
}

/// Dead code configuration - framework-specific entry point patterns.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeadCodeConfig {
    /// Method names that are framework entry points (e.g. "handle", "boot").
    pub laravel_entry_points: Vec<String>,
    /// Regex patterns for magic methods (e.g. "^get[A-Z].*Attribute$").
    pub laravel_magic_patterns: Vec<String>,
    /// Patterns for React entry points.
    pub react_ignore_patterns: Vec<String>,
}

/// Standard configuration for analysis thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Standard {
    pub max_function_lines: u32,
    pub max_parameters: u8,
    pub max_class_methods: u16,
    pub auto_fix_threshold: f32,
    pub ai_review_threshold: f32,
    pub naming: NamingConfig,
    pub security: SecurityConfig,
    pub dead_code: DeadCodeConfig,
}

impl Default for Standard {
    fn default() -> Self {
        Self {
            max_function_lines: 50,
            max_parameters: 5,
            max_class_methods: 20,
            auto_fix_threshold: 0.85,
            ai_review_threshold: 0.50,
            naming: NamingConfig::default(),
            security: SecurityConfig::default(),
            dead_code: DeadCodeConfig::default(),
        }
    }
}

/// Result of a Prism analysis run.
#[derive(Debug, Default)]
pub struct PrismResult {
    pub findings: Vec<Finding>,
    pub duplicate_groups: Vec<DuplicateGroup>,
    pub score: Score,
    pub auto_fixable: Vec<Finding>,
    pub ai_review: Vec<Finding>,
    pub human_review: Vec<Finding>,
    /// Line counts per file, language and top-level directory.
    pub loc: loc::LocReport,
    /// What the test suite could reach, statically. Not coverage - see
    /// [`reachability`].
    pub test_reachability: reachability::TestReachability,
    /// Findings removed by inline `verum:ignore` comments (see [`suppress`]).
    /// Kept out of `findings`, the score, and the gate, but reported so
    /// `--show-suppressed` can list them and counts stay honest.
    pub suppressed: Vec<Finding>,
}

pub struct Prism;

impl Prism {
    pub fn analyse(ir: &Ir, standard: &Standard) -> Result<PrismResult> {
        Self::analyse_at(ir, standard, None)
    }

    /// Run all analysis passes, plus the filesystem-rooted dependency audit
    /// when a project root is supplied (it reads `<root>/Cargo.lock`).
    pub fn analyse_at(
        ir: &Ir,
        standard: &Standard,
        root: Option<&std::path::Path>,
    ) -> Result<PrismResult> {
        // Per-pass timing when VERUM_PROFILE is set in the environment. The
        // passes run concurrently below, so individual timings OVERLAP: they
        // are each pass's own elapsed time, not additive shares of the wall
        // time, and their print order varies run to run.
        let profile = std::env::var("VERUM_PROFILE").is_ok();
        macro_rules! prof {
            ($name:literal, $e:expr) => {{
                let __t = std::time::Instant::now();
                let __r = $e;
                if profile {
                    eprintln!("  pass {:<16} {:>7.2}s", $name, __t.elapsed().as_secs_f64());
                }
                __r
            }};
        }

        // `taint`, `rust_insights`, `transport`, `security` and
        // `crate_semantics` are all line scanners over the same tree, and each
        // derived the same two things per file: the file's lines, and the
        // symbols declared in it. Do both once here - the read in parallel,
        // the symbol lookup as a single index - so the passes share them
        // instead of each re-reading the tree and rescanning every symbol per
        // file.
        let scan_ctx = prof!("scan_context", scan::ScanContext::build(ir));

        // Every pass below reads only (&Ir, &Standard, &ScanContext, root), so
        // they run concurrently, each collecting into its OWN slot. Determinism
        // holds because nothing is pushed into a shared Vec from workers: the
        // slots are merged in the fixed order further down (the order the
        // passes used to run in), then normalized by the global sort + dedup.
        let mut deps_f: Vec<Finding> = Vec::new();
        let mut crate_semantics_f: Vec<Finding> = Vec::new();
        let mut dead_code_f: Vec<Finding> = Vec::new();
        let mut duplicates_r: (Vec<Finding>, Vec<DuplicateGroup>) = (Vec::new(), Vec::new());
        let mut security_f: Vec<Finding> = Vec::new();
        let mut app_security_f: Vec<Finding> = Vec::new();
        let mut crypto_hygiene_f: Vec<Finding> = Vec::new();
        let mut taint_f: Vec<Finding> = Vec::new();
        let mut naming_f: Vec<Finding> = Vec::new();
        let mut complexity_f: Vec<Finding> = Vec::new();
        let mut performance_f: Vec<Finding> = Vec::new();
        let mut rust_insights_f: Vec<Finding> = Vec::new();
        let mut transport_f: Vec<Finding> = Vec::new();
        let mut rbac_f: Vec<Finding> = Vec::new();
        let mut infrastructure_f: Vec<Finding> = Vec::new();
        let mut chains_f: Vec<Finding> = Vec::new();
        // Measurements rather than findings: they produce no `Finding`s, so
        // they merge into their own slots and never touch the finding order.
        let mut loc_r = loc::LocReport::default();
        let mut reachability_r = reachability::TestReachability::default();

        let scan_ctx_ref = &scan_ctx;
        rayon::scope(|s| {
            // Root-scoped: reads <root>/Cargo.lock.
            s.spawn(|_| {
                if let Some(root) = root {
                    deps_f = prof!("deps", deps::analyse(root));
                }
            });
            s.spawn(|_| {
                crate_semantics_f = prof!(
                    "crate_semantics",
                    crate_semantics::analyse_with_context(ir, root, scan_ctx_ref)
                )
            });
            s.spawn(|_| {
                dead_code_f = prof!("dead_code", dead_code::analyse(ir, &standard.dead_code))
            });
            s.spawn(|_| duplicates_r = prof!("duplicates", duplicates::analyse(ir)));
            s.spawn(|_| {
                security_f = prof!(
                    "security",
                    security::analyse_with_context(ir, &standard.security, scan_ctx_ref)
                )
            });
            s.spawn(|_| {
                app_security_f = prof!(
                    "app_security",
                    app_security::analyse_with_context(ir, scan_ctx_ref)
                )
            });
            s.spawn(|_| {
                crypto_hygiene_f = prof!(
                    "crypto_hygiene",
                    crypto_hygiene::analyse_with_context(ir, scan_ctx_ref)
                )
            });
            s.spawn(|_| taint_f = prof!("taint", taint::analyse_with_context(ir, scan_ctx_ref).0));
            s.spawn(|_| naming_f = prof!("naming", naming::analyse(ir, &standard.naming)));
            s.spawn(|_| complexity_f = prof!("complexity", complexity::analyse(ir, standard)));
            s.spawn(|_| performance_f = prof!("performance", performance::analyse(ir)));
            // Informational; excluded from scoring.
            s.spawn(|_| {
                rust_insights_f = prof!(
                    "rust_insights",
                    rust_insights::analyse_with_context(ir, scan_ctx_ref)
                )
            });
            s.spawn(|_| {
                transport_f = prof!(
                    "transport",
                    transport::analyse_with_context(ir, scan_ctx_ref)
                )
            });
            s.spawn(|_| rbac_f = prof!("rbac", rbac::analyse(ir)));
            // K8s/Docker/Terraform findings come pre-built from the atlas phase.
            s.spawn(|_| infrastructure_f = prof!("infrastructure", infrastructure::analyse(ir)));
            s.spawn(|_| chains_f = prof!("chains", chains::analyse(ir)));
            s.spawn(|_| loc_r = prof!("loc", loc::analyse(ir, scan_ctx_ref, root)));
            s.spawn(|_| reachability_r = prof!("reachability", reachability::analyse(ir, root)));
        });

        let (dup_findings, dup_groups) = duplicates_r;

        // FIXED merge order - the order the passes ran in sequentially - so the
        // stable sort + first-wins dedup below see the same sequence they
        // always did, regardless of which worker finished first.
        let mut findings = Vec::new();
        findings.extend(deps_f);
        findings.extend(crate_semantics_f);
        findings.extend(dead_code_f);
        findings.extend(dup_findings);
        findings.extend(security_f);
        findings.extend(app_security_f);
        findings.extend(crypto_hygiene_f);
        findings.extend(taint_f);
        findings.extend(naming_f);
        findings.extend(complexity_f);
        findings.extend(performance_f);
        findings.extend(rust_insights_f);
        findings.extend(transport_f);
        findings.extend(rbac_f);
        findings.extend(infrastructure_f);
        findings.extend(chains_f);
        // Parse-failure diagnostics recorded by the mapper when a per-file
        // parse panicked and was isolated. Appended in the fixed merge order
        // like every pass slot; the global sort below normalizes placement.
        findings.extend(ir.parse_failures.iter().cloned());

        // Drop source-hygiene and security findings that land in test, example,
        // vendored, or generated files - they are noise, not shipped-code
        // defects. Infrastructure/compliance findings are kept everywhere.
        findings.retain(|f| {
            kind_survives_in_auxiliary(&f.kind) || !is_auxiliary_path(&f.file.to_string_lossy())
        });

        // Several passes iterate HashMaps; sort so the same input always
        // produces byte-identical output.
        findings
            .sort_by(|a, b| (&a.file, a.line_start, &a.id).cmp(&(&b.file, b.line_start, &b.id)));

        // Two passes can flag the same issue at the same spot (e.g. `eval()` via
        // both the pattern scan and taint). Collapse to one per kind+location.
        let mut seen = HashSet::new();
        findings.retain(|f| seen.insert((format!("{:?}", f.kind), f.file.clone(), f.line_start)));

        // Inline `verum:ignore` suppressions: a cheap post-pass over only the
        // files that have findings (their lines are already in the scan
        // context). Suppressed findings leave the list before scoring; a
        // suppression that matched nothing comes back as a Low
        // StaleSuppression finding, re-sorted into the same global order. On
        // a tree with no `verum:ignore` comments this is a no-op.
        let outcome = suppress::apply(findings, &scan_ctx);
        let suppressed = outcome.suppressed;
        findings = outcome.kept;
        if !outcome.stale.is_empty() {
            findings.extend(outcome.stale);
            findings.sort_by(|a, b| {
                (&a.file, a.line_start, &a.id).cmp(&(&b.file, b.line_start, &b.id))
            });
        }

        // Stable identities for baseline matching, assigned over the final
        // sorted order so the occurrence index is reproducible. Purely
        // additive: no finding is added, removed, or reordered by this.
        // Suppressed findings get theirs separately - they are listed with
        // `--show-suppressed` and deserve an identity there too.
        fingerprint::assign(&mut findings, ir, root);
        let mut suppressed = suppressed;
        fingerprint::assign(&mut suppressed, ir, root);

        let score = scoring::compute(ir, &findings, &reachability_r);

        let mut auto_fixable = Vec::new();
        let mut ai_review = Vec::new();
        let mut human_review = Vec::new();

        for f in &findings {
            if f.auto_fixable && f.confidence >= standard.auto_fix_threshold {
                auto_fixable.push(f.clone());
            } else if f.confidence >= standard.ai_review_threshold {
                ai_review.push(f.clone());
            } else {
                human_review.push(f.clone());
            }
        }

        Ok(PrismResult {
            findings,
            duplicate_groups: dup_groups,
            score,
            auto_fixable,
            ai_review,
            human_review,
            loc: loc_r,
            test_reachability: reachability_r,
            suppressed,
        })
    }
}
