use verum_nucleus::{Finding, FindingKind, Ir, Score, Severity};

use crate::lcov::MeasuredCoverage;
use crate::reachability::TestReachability;

/// Static test-reachability at which the test-reachability dimension reaches
/// 100, as a percentage of shipped functions.
///
/// Calibrated, not guessed. Reachability is counted only along *resolved* call
/// edges, so it measures the evidence Verum can actually see, and that ceiling
/// is well below 100%: a suite that drives code through trait dispatch,
/// generics or derive macros leaves no statically resolvable edge from the
/// test to the function it exercises. Measured over the corpus at the pinned
/// commits, on repositories nobody would call untested:
///
/// ```text
///   clap    35.2%     ripgrep 27.0%     tokio 20.8%
///   fd      19.0%     rayon   11.6%     serde  0.2%
/// ```
///
/// `rayon` and `serde` sit at the bottom for the reason above - almost every
/// call into them is trait- or macro-dispatched - which is exactly why a
/// measured coverage file, when one exists, supersedes this estimate entirely
/// (see [`measured_dimension`]).
///
/// The target is set at the top of that band, so a repository whose tests
/// demonstrably reach a third of its functions scores full marks and one whose
/// tests reach nothing scores zero. This is a floor on evidence, never a
/// verdict on a test suite.
pub const REACHABILITY_TARGET_PERCENT: f32 = 35.0;

/// Density at which a size-sensitive penalty reaches its maximum: findings of
/// that class touching 10% of the codebase's symbols is already a pervasive,
/// structural problem, so nothing is gained by letting the count run further.
const SATURATION_DENSITY: f32 = 0.10;

/// Floor on the denominator used for density.
///
/// Two jobs. It stops a handful of symbols from producing an absurd density
/// (one duplicate in a five-symbol crate is not a 20%-duplicated codebase),
/// and it keeps the small-repo end of the scale where it has always been:
/// at exactly this many symbols the density curve reproduces the old
/// per-finding penalties almost exactly (complexity 5/finding, duplicates
/// 3/finding), so tiny messy repos are not quietly forgiven. Normalization
/// only starts to bite above this size - which is the case it exists for.
const MIN_SIZE_BASIS: usize = 100;

/// Turn a raw finding count into a penalty proportional to its DENSITY over
/// the codebase, rather than to the count itself.
///
/// Architecture, naming, complexity and duplicate penalties used to be
/// `count * weight`, clamped at a maximum. Because the maxima were reached
/// after a handful of findings, every real codebase pinned every one of those
/// dimensions to its floor: a 500-symbol crate and a 45,000-symbol workspace
/// both scored the same 50/100 on complexity, so the number carried no
/// information and large repos were punished purely for being large. Scoring
/// the ratio instead means the headline answers "what fraction of this code is
/// affected?", which is comparable across codebase sizes.
///
/// Deterministic: pure integer inputs through fixed f32 arithmetic, no
/// iteration order or environment involved.
fn density_penalty(count: usize, symbols: usize, max_penalty: u8) -> u8 {
    let basis = symbols.max(MIN_SIZE_BASIS) as f32;
    let density = count as f32 / basis;
    let scaled = (density / SATURATION_DENSITY) * max_penalty as f32;
    // Round rather than truncate: truncation turns the binary representation
    // of a clean ratio (2.9999998) into a penalty one point below the exact
    // arithmetic, which is the sort of drift that makes a score look arbitrary.
    scaled.min(max_penalty as f32).round() as u8
}

/// Score the static test-reachability of a tree, 0..=100.
///
/// The mapping is a documented straight line: no tests at all is 0, and the
/// score rises linearly with the fraction of shipped functions a test can
/// reach until it saturates at [`REACHABILITY_TARGET_PERCENT`].
///
/// ```text
///   0% reachable ->   0        17.5% ->  50        35%+ -> 100
/// ```
///
/// The dimension this feeds used to be hardcoded to 100, so a repository with
/// no tests whatsoever reported perfect test coverage. It is a *reachability*
/// number, not a coverage number: it says what the suite could possibly
/// exercise, not what it did. [`measured_dimension`] replaces it whenever a
/// real coverage file is supplied.
pub fn reachability_dimension(reachability: &TestReachability) -> u8 {
    // No tests found is 0 outright, not a rounding of some small percentage:
    // the honest answer to "how well tested is this?" is "not at all".
    if reachability.test_roots == 0 {
        return 0;
    }
    let ratio = (reachability.percent / REACHABILITY_TARGET_PERCENT).min(1.0);
    (ratio * 100.0).round() as u8
}

/// Score measured coverage, 0..=100, from a real coverage run.
///
/// Line coverage, used directly. A measured percentage is already the answer
/// and needs no calibration curve - the ramp in [`reachability_dimension`]
/// exists only to compensate for a static walk seeing less than a running
/// test does. Measured data always wins: it is the ground truth the static
/// estimate is trying to approximate.
pub fn measured_dimension(coverage: &MeasuredCoverage) -> u8 {
    coverage.line_percent.round().clamp(0.0, 100.0) as u8
}

/// Turn findings into per-dimension scores and a capped overall.
///
/// `reachability` supplies the test-reachability dimension. It is reported but
/// deliberately left out of the weighted `overall` - the same set of
/// dimensions carries the headline as before, so adding this measurement moves
/// no existing score. Folding it in is a separate, deliberately breaking
/// re-weighting.
pub fn compute(ir: &Ir, findings: &[Finding], reachability: &TestReachability) -> Score {
    let mut score = Score {
        security: 100,
        architecture: 100,
        performance: 100,
        naming: 100,
        complexity: 100,
        test_coverage: reachability_dimension(reachability),
        ui_consistency: 100,
        journey_coverage: 100,
        visual_accuracy: 100,
        infrastructure: 100,
        compliance: 100,
        overall: 0,
    };

    for f in findings {
        match &f.kind {
            FindingKind::SqlInjection
            | FindingKind::XssVulnerability
            | FindingKind::WeakCrypto
            | FindingKind::HardcodedSecret
            | FindingKind::EvalUsage
            | FindingKind::WeakRandom
            | FindingKind::PathTraversal
            | FindingKind::OpenRedirect
            | FindingKind::NonConstantTimeComparison
            | FindingKind::StaticAeadNonce
            | FindingKind::TlsVerificationDisabled
            | FindingKind::UnsafeDeserialization => {
                let penalty = match &f.severity {
                    Severity::Critical => 15,
                    Severity::High => 5,
                    Severity::Medium => 2,
                    _ => 1,
                };
                score.security = score.security.saturating_sub(penalty);
            }
            FindingKind::MissingAuthMiddleware | FindingKind::MissingRoleCheck => {
                let penalty = match &f.severity {
                    Severity::Critical => 15,
                    Severity::High => 5,
                    _ => 2,
                };
                score.security = score.security.saturating_sub(penalty);
            }
            _ => {}
        }
    }

    // Everything below is size-normalized: penalties track the DENSITY of the
    // finding class over the codebase, not the raw count. See
    // `density_penalty`. The maxima (50 dead code, 30 duplicates, 40 naming,
    // 50 complexity) are unchanged - only the input to them is.
    let total_symbols = ir.symbol_count();
    let dead_count = findings
        .iter()
        .filter(|f| {
            matches!(
                f.kind,
                FindingKind::DeadFunction | FindingKind::DeadClass | FindingKind::DeadFile
            )
        })
        .count();
    let arch_penalty = density_penalty(dead_count, total_symbols, 50);
    score.architecture = score.architecture.saturating_sub(arch_penalty);

    let dup_count = findings
        .iter()
        .filter(|f| {
            matches!(
                f.kind,
                FindingKind::ExactDuplicate
                    | FindingKind::RenamedDuplicate
                    | FindingKind::SemanticDuplicate
            )
        })
        .count();
    let dup_penalty = density_penalty(dup_count, total_symbols, 30);
    score.architecture = score.architecture.saturating_sub(dup_penalty);

    let naming_count = findings
        .iter()
        .filter(|f| {
            matches!(
                f.kind,
                FindingKind::ConventionViolation | FindingKind::NamingInconsistency
            )
        })
        .count();
    let naming_penalty = density_penalty(naming_count, total_symbols, 40);
    score.naming = score.naming.saturating_sub(naming_penalty);

    let complexity_count = findings
        .iter()
        .filter(|f| {
            matches!(
                f.kind,
                FindingKind::LongFunction
                    | FindingKind::TooManyParams
                    | FindingKind::HighComplexity
                    | FindingKind::DeepNesting
            )
        })
        .count();
    let complexity_penalty = density_penalty(complexity_count, total_symbols, 50);
    score.complexity = score.complexity.saturating_sub(complexity_penalty);

    for f in findings {
        match &f.kind {
            FindingKind::NPlusOneQuery => {
                let penalty = match &f.severity {
                    Severity::High => 10,
                    Severity::Medium => 5,
                    Severity::Low => 2,
                    _ => 1,
                };
                score.performance = score.performance.saturating_sub(penalty);
            }
            FindingKind::StringConcatInLoop | FindingKind::ObjectInstantiationInLoop => {
                score.performance = score.performance.saturating_sub(3);
            }
            FindingKind::MissingHookDependencies => {
                score.performance = score.performance.saturating_sub(2);
            }
            _ => {}
        }
    }

    // Transport / protocol correctness: framing that cannot survive its own
    // transport is an architecture defect; an unvalidated wire length is a
    // remote-DoS surface, so it lands on the security score.
    for f in findings {
        match &f.kind {
            FindingKind::SplitDatagramMessage | FindingKind::OversizedDatagram => {
                let penalty = match &f.severity {
                    Severity::Critical => 15,
                    Severity::High => 8,
                    Severity::Medium => 4,
                    _ => 2,
                };
                score.architecture = score.architecture.saturating_sub(penalty);
            }
            FindingKind::UnvalidatedLengthPrefix => {
                let penalty = match &f.severity {
                    Severity::Critical => 15,
                    Severity::High => 5,
                    _ => 2,
                };
                score.security = score.security.saturating_sub(penalty);
            }
            _ => {}
        }
    }

    // Dependency audit: vulnerable deps hit security; unmaintained/duplicate
    // are architecture hygiene.
    for f in findings {
        match &f.kind {
            FindingKind::VulnerableDependency => {
                let penalty = match &f.severity {
                    Severity::Critical => 15,
                    Severity::High => 8,
                    Severity::Medium => 4,
                    _ => 2,
                };
                score.security = score.security.saturating_sub(penalty);
            }
            FindingKind::UnmaintainedDependency => {
                score.architecture = score.architecture.saturating_sub(2);
            }
            FindingKind::DuplicateDependency => {
                score.architecture = score.architecture.saturating_sub(1);
            }
            _ => {}
        }
    }

    for f in findings {
        match &f.kind {
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
            | FindingKind::HardcodedCredential => {
                let penalty = match &f.severity {
                    Severity::Critical => 15,
                    Severity::High => 8,
                    Severity::Medium => 4,
                    Severity::Low => 2,
                    _ => 1,
                };
                score.infrastructure = score.infrastructure.saturating_sub(penalty);
            }
            _ => {}
        }
    }

    // Compute weighted overall over the dimensions this pass actually measures.
    // UI consistency, journey coverage and compliance are not analysed here -
    // including them at their initial 100 would silently inflate every score.
    score.compute_overall_masked(false, false, false);

    // Cap the overall by worst actionable severity so a serious finding cannot
    // be diluted by a weighted mean. Informational surfaces - the "be ready to
    // explain" Rust insights and the exploratory chain map - are excluded:
    // they carry High severities for ranking, not must-fix verdicts, and
    // capping on them would punish every async service.
    let actionable = |f: &&Finding| !is_informational(&f.kind);
    let has_critical = findings
        .iter()
        .filter(actionable)
        .any(|f| f.severity == Severity::Critical);
    let has_high = findings
        .iter()
        .filter(actionable)
        .any(|f| f.severity == Severity::High);
    score.apply_severity_cap(has_critical, has_high);

    score
}

/// Findings that rank/annotate rather than assert a must-fix defect, so they
/// must not drive the severity cap.
fn is_informational(kind: &FindingKind) -> bool {
    matches!(
        kind,
        FindingKind::UnsafeUsage
            | FindingKind::PanicRisk
            | FindingKind::BlockingInAsync
            | FindingKind::UnboundedChannel
            | FindingKind::HotPathAllocation
            | FindingKind::LockOnHotPath
            | FindingKind::DangerousChain
            | FindingKind::MissingSafetyComment
            // A parse isolated after a panic is a diagnostic about the run,
            // not a defect in the code under audit: no penalty, no cap.
            | FindingKind::ParseFailure
            // A stale suppression is comment hygiene, not a code defect.
            | FindingKind::StaleSuppression
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use verum_nucleus::SymbolKind;

    fn finding(kind: FindingKind, severity: Severity) -> Finding {
        Finding {
            fingerprint: String::new(),
            id: "t".into(),
            kind,
            severity,
            confidence: 1.0,
            file: PathBuf::from("lib.rs"),
            line_start: 1,
            line_end: 1,
            symbol: None,
            message: String::new(),
            suggestion: String::new(),
            auto_fixable: false,
            related: Vec::new(),
        }
    }

    /// A tree in which no test suite was found at all.
    fn untested() -> TestReachability {
        TestReachability {
            functions: 10,
            ..Default::default()
        }
    }

    /// A tree whose tests reach `percent` of its functions.
    fn reaching(percent: f32) -> TestReachability {
        TestReachability {
            test_roots: 5,
            functions: 100,
            reachable: percent.round() as usize,
            percent,
            ..Default::default()
        }
    }

    fn ir_with_symbols(n: usize) -> Ir {
        let mut ir = Ir::new();
        for i in 0..n {
            let id = verum_nucleus::SymbolId(i as u64 + 1);
            ir.symbols.insert(
                id,
                verum_nucleus::Symbol {
                    id,
                    name: format!("f{i}"),
                    fully_qualified: format!("f{i}"),
                    kind: SymbolKind::Function,
                    visibility: verum_nucleus::Visibility::Public,
                    file: PathBuf::from("lib.rs"),
                    line_start: 1,
                    line_end: 2,
                    col_start: 0,
                    col_end: 0,
                    language: verum_nucleus::Language::Rust,
                    parent: None,
                    hash: 0,
                    normalized_hash: 0,
                    flow_hash: 0,
                    param_count: 0,
                    is_entry_point: false,
                    doc_comment: None,
                },
            );
        }
        ir
    }

    #[test]
    fn one_critical_caps_overall_in_clean_codebase() {
        // 50 clean symbols, a single CRITICAL taint finding: a weighted mean
        // would still land in the 90s. The cap must force <= 79.
        let ir = ir_with_symbols(50);
        let findings = vec![finding(FindingKind::SqlInjection, Severity::Critical)];
        let score = compute(&ir, &findings, &untested());
        assert!(score.overall <= 79, "got {}", score.overall);
    }

    #[test]
    fn one_high_caps_at_89() {
        let ir = ir_with_symbols(50);
        let findings = vec![finding(FindingKind::PathTraversal, Severity::High)];
        let score = compute(&ir, &findings, &untested());
        assert!(score.overall <= 89, "got {}", score.overall);
    }

    #[test]
    fn informational_high_does_not_cap() {
        // The founding regression in reverse: an async service full of HIGH-
        // ranked insight surfaces should not be capped to 89.
        let ir = ir_with_symbols(50);
        let findings = vec![
            finding(FindingKind::DangerousChain, Severity::High),
            finding(FindingKind::BlockingInAsync, Severity::Medium),
        ];
        let score = compute(&ir, &findings, &untested());
        assert!(
            score.overall > 89,
            "informational should not cap, got {}",
            score.overall
        );
    }

    #[test]
    fn clean_codebase_stays_high() {
        let ir = ir_with_symbols(50);
        let score = compute(&ir, &[], &untested());
        assert_eq!(score.overall, 100);
    }

    fn repeat(kind: FindingKind, severity: Severity, n: usize) -> Vec<Finding> {
        (0..n)
            .map(|_| finding(kind.clone(), severity.clone()))
            .collect()
    }

    #[test]
    fn same_finding_count_hurts_a_small_codebase_more_than_a_large_one() {
        // The regression this normalization exists for: 40 long functions is a
        // pervasive problem in a 400-symbol crate and a rounding error in a
        // 40,000-symbol workspace. Under the old count-based penalty both
        // pinned complexity to its 50 floor.
        let findings = repeat(FindingKind::LongFunction, Severity::Medium, 40);
        let small = compute(&ir_with_symbols(400), &findings, &untested());
        let large = compute(&ir_with_symbols(40_000), &findings, &untested());
        assert!(
            large.complexity > small.complexity,
            "density should favour the larger codebase: small {} large {}",
            small.complexity,
            large.complexity
        );
        assert_eq!(small.complexity, 50, "10% density is the saturation point");
        assert!(
            large.complexity >= 99,
            "0.1% density is noise, got {}",
            large.complexity
        );
    }

    #[test]
    fn equal_density_scores_equally_regardless_of_size() {
        // The property that makes scores comparable across repos: the headline
        // measures the fraction of the codebase affected, not its size.
        let small = compute(
            &ir_with_symbols(1_000),
            &repeat(FindingKind::HighComplexity, Severity::Medium, 20),
            &untested(),
        );
        let large = compute(
            &ir_with_symbols(10_000),
            &repeat(FindingKind::HighComplexity, Severity::Medium, 200),
            &untested(),
        );
        assert_eq!(small.complexity, large.complexity);
        assert_eq!(small.overall, large.overall);
    }

    #[test]
    fn dense_small_codebase_is_still_punished() {
        // Normalization must not become an amnesty for genuinely messy small
        // repos: a 200-symbol crate where a fifth of the symbols are overlong,
        // a tenth are duplicated and a tenth are misnamed still bottoms out
        // every size-sensitive dimension.
        let mut findings = repeat(FindingKind::LongFunction, Severity::Medium, 40);
        findings.extend(repeat(FindingKind::ExactDuplicate, Severity::Low, 20));
        findings.extend(repeat(FindingKind::ConventionViolation, Severity::Low, 20));
        let score = compute(&ir_with_symbols(200), &findings, &untested());
        assert_eq!(score.complexity, 50);
        assert_eq!(score.naming, 60);
        assert_eq!(score.architecture, 70);
    }

    #[test]
    fn tiny_codebases_use_the_size_floor() {
        // A single duplicate in a five-symbol crate is not a 20%-duplicated
        // codebase. The denominator floor keeps the penalty proportionate.
        let findings = repeat(FindingKind::ExactDuplicate, Severity::Low, 1);
        let tiny = compute(&ir_with_symbols(5), &findings, &untested());
        let floored = compute(&ir_with_symbols(MIN_SIZE_BASIS), &findings, &untested());
        assert_eq!(tiny.architecture, floored.architecture);
        assert_eq!(tiny.architecture, 97);
    }

    #[test]
    fn density_penalty_never_exceeds_its_maximum() {
        // Guards the old `(count * 5) as u8` wraparound class of bug: however
        // many findings arrive, the penalty stays inside its dimension budget.
        assert_eq!(density_penalty(usize::MAX, 1, 30), 30);
        assert_eq!(density_penalty(1_000_000, 10, 50), 50);
        assert_eq!(density_penalty(0, 10_000, 50), 0);
    }

    #[test]
    fn a_repo_with_no_tests_no_longer_scores_full_marks() {
        // The regression this dimension exists for: it was hardcoded to 100,
        // so a codebase without a single test reported perfect test coverage.
        let score = compute(&ir_with_symbols(50), &[], &untested());
        assert_eq!(score.test_coverage, 0);
    }

    #[test]
    fn a_well_reached_repo_scores_high() {
        // `clap` at the pinned corpus commit reaches 35.2% of its functions.
        assert_eq!(reachability_dimension(&reaching(35.2)), 100);
        assert_eq!(reachability_dimension(&reaching(90.0)), 100);
        // `ripgrep`, 27.0%.
        assert!(reachability_dimension(&reaching(27.0)) >= 75);
    }

    #[test]
    fn the_reachability_ramp_is_linear_up_to_the_target() {
        assert_eq!(reachability_dimension(&reaching(0.0)), 0);
        assert_eq!(reachability_dimension(&reaching(17.5)), 50);
        assert_eq!(reachability_dimension(&reaching(8.75)), 25);
    }

    #[test]
    fn tests_that_reach_almost_nothing_score_almost_nothing() {
        // `serde`'s macro-dispatched suite resolves to 0.2% of its
        // functions; a token suite must not read as a tested codebase.
        assert!(
            reachability_dimension(&reaching(1.0)) <= 5,
            "a token test suite is not coverage"
        );
        assert_eq!(reachability_dimension(&reaching(0.2)), 1);
    }

    #[test]
    fn the_test_dimension_does_not_move_the_overall() {
        // Reporting the number honestly must not silently re-weight every
        // existing score; folding it into `overall` is a separate decision.
        let ir = ir_with_symbols(50);
        let untested_score = compute(&ir, &[], &untested());
        let tested_score = compute(&ir, &[], &reaching(100.0));
        assert_eq!(untested_score.test_coverage, 0);
        assert_eq!(tested_score.test_coverage, 100);
        assert_eq!(untested_score.overall, tested_score.overall);
    }

    #[test]
    fn measured_coverage_is_used_as_measured() {
        let coverage = MeasuredCoverage {
            line_percent: 83.4,
            ..Default::default()
        };
        assert_eq!(measured_dimension(&coverage), 83);
        assert_eq!(measured_dimension(&MeasuredCoverage::default()), 0);
    }
}
