use verum_nucleus::{Finding, FindingKind, Ir, Score, Severity};

/// Turn findings into per-dimension scores and a capped overall.
pub fn compute(ir: &Ir, findings: &[Finding]) -> Score {
    let mut score = Score {
        security: 100,
        architecture: 100,
        performance: 100,
        naming: 100,
        complexity: 100,
        test_coverage: 100,
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
            | FindingKind::OpenRedirect => {
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

    // Architecture penalty scales with the dead-code ratio.
    let total_symbols = ir.symbol_count().max(1);
    let dead_count = findings
        .iter()
        .filter(|f| {
            matches!(
                f.kind,
                FindingKind::DeadFunction | FindingKind::DeadClass | FindingKind::DeadFile
            )
        })
        .count();
    let dead_ratio = dead_count as f32 / total_symbols as f32;
    let arch_penalty = (dead_ratio * 50.0).min(50.0) as u8;
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
    // Compute in usize first - casting the count to u8 before clamping would
    // wrap mod 256 and let large codebases score better than small ones.
    let dup_penalty = (dup_count * 5).min(30) as u8;
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
    let naming_penalty = (naming_count * 2).min(40) as u8;
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
    let complexity_penalty = (complexity_count * 5).min(50) as u8;
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
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use verum_nucleus::SymbolKind;

    fn finding(kind: FindingKind, severity: Severity) -> Finding {
        Finding {
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
        let score = compute(&ir, &findings);
        assert!(score.overall <= 79, "got {}", score.overall);
    }

    #[test]
    fn one_high_caps_at_89() {
        let ir = ir_with_symbols(50);
        let findings = vec![finding(FindingKind::PathTraversal, Severity::High)];
        let score = compute(&ir, &findings);
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
        let score = compute(&ir, &findings);
        assert!(
            score.overall > 89,
            "informational should not cap, got {}",
            score.overall
        );
    }

    #[test]
    fn clean_codebase_stays_high() {
        let ir = ir_with_symbols(50);
        let score = compute(&ir, &[]);
        assert_eq!(score.overall, 100);
    }
}
