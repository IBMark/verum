pub mod chains;
pub mod complexity;
pub mod crate_semantics;
pub mod dead_code;
pub mod deps;
pub mod duplicates;
pub mod infrastructure;
pub mod naming;
pub mod performance;
pub mod rbac;
pub mod rust_insights;
pub mod scan;
pub mod scoring;
pub mod security;
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
        let mut findings = Vec::new();

        // Per-pass timing when VERUM_PROFILE is set in the environment.
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

        // Root-scoped: reads <root>/Cargo.lock.
        if let Some(root) = root {
            findings.extend(prof!("deps", deps::analyse(root)));
        }

        findings.extend(prof!("crate_semantics", crate_semantics::analyse(ir, root)));
        findings.extend(prof!(
            "dead_code",
            dead_code::analyse(ir, &standard.dead_code)
        ));

        let (dup_findings, dup_groups) = prof!("duplicates", duplicates::analyse(ir));
        findings.extend(dup_findings);

        findings.extend(prof!("security", security::analyse(ir, &standard.security)));

        // `taint`, `rust_insights` and `transport` are all line scanners over
        // the same tree, and each derived the same two things per file: the
        // file's lines, and the symbols declared in it. Do both once here - the
        // read in parallel, the symbol lookup as a single index - so the passes
        // share them instead of each re-reading the tree and rescanning every
        // symbol per file.
        let scan_ctx = prof!("scan_context", scan::ScanContext::build(ir));

        findings.extend(prof!("taint", taint::analyse_with_context(ir, &scan_ctx).0));
        findings.extend(prof!("naming", naming::analyse(ir, &standard.naming)));
        findings.extend(prof!("complexity", complexity::analyse(ir, standard)));
        findings.extend(prof!("performance", performance::analyse(ir)));

        // Informational; excluded from scoring.
        findings.extend(prof!(
            "rust_insights",
            rust_insights::analyse_with_context(ir, &scan_ctx)
        ));
        findings.extend(prof!(
            "transport",
            transport::analyse_with_context(ir, &scan_ctx)
        ));

        findings.extend(prof!("rbac", rbac::analyse(ir)));
        // K8s/Docker/Terraform findings come pre-built from the atlas phase.
        findings.extend(prof!("infrastructure", infrastructure::analyse(ir)));
        findings.extend(prof!("chains", chains::analyse(ir)));

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

        let score = scoring::compute(ir, &findings);

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
        })
    }
}
