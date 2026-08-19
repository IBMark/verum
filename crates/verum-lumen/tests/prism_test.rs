use verum_lumen::{Prism, Standard};
use verum_nucleus::FindingKind;

#[test]
fn test_dead_code_detection_on_php_simple() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let fixture_path = std::path::Path::new(&manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/php_simple");

    let config = verum_mappa::AtlasConfig {
        root: fixture_path,
        ..Default::default()
    };
    let atlas = verum_mappa::Atlas::new(config);
    let ir = atlas.build().expect("should parse php_simple fixture");

    assert!(ir.symbol_count() > 0, "should have symbols");

    let standard = Standard::default();
    let result = Prism::analyse(&ir, &standard).expect("prism should analyse");

    println!("Total findings: {}", result.findings.len());
    for f in &result.findings {
        println!(
            "  [{:?}] {:?} - {} (confidence: {})",
            f.severity, f.kind, f.message, f.confidence
        );
    }

    // Should find dead code
    let dead_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| matches!(f.kind, FindingKind::DeadFunction))
        .collect();
    assert!(
        !dead_findings.is_empty(),
        "should find dead code findings, found: {:?}",
        result
            .findings
            .iter()
            .map(|f| format!("{:?}: {}", f.kind, f.message))
            .collect::<Vec<_>>()
    );

    // Should find formatLegacyDate or legacyFormat as dead
    let dead_names: Vec<&str> = dead_findings
        .iter()
        .filter_map(|f| {
            if f.message.contains("formatLegacyDate") {
                Some("formatLegacyDate")
            } else if f.message.contains("legacyFormat") {
                Some("legacyFormat")
            } else if f.message.contains("internalHelper") {
                Some("internalHelper")
            } else {
                None
            }
        })
        .collect();
    println!("Dead code found: {:?}", dead_names);
    // At least some dead functions should be found
    assert!(!dead_names.is_empty(), "should find known dead functions");

    // The fixture contains getUserById / fetchUser - identical bodies apart
    // from name and comments - which must group as renamed duplicates.
    assert!(
        !result.duplicate_groups.is_empty(),
        "should detect the getUserById/fetchUser duplicate pair"
    );

    // Check score
    println!("Score: overall={}", result.score.overall);
    println!("  security={}", result.score.security);
    println!("  architecture={}", result.score.architecture);
    println!("  naming={}", result.score.naming);
    println!("  complexity={}", result.score.complexity);
}

#[test]
fn test_security_detection_on_php_security() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let fixture_path = std::path::Path::new(&manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/php_security");

    let config = verum_mappa::AtlasConfig {
        root: fixture_path,
        ..Default::default()
    };
    let atlas = verum_mappa::Atlas::new(config);
    let ir = atlas.build().expect("should parse php_security fixture");

    let standard = Standard::default();
    let result = Prism::analyse(&ir, &standard).expect("prism should analyse");

    println!("Security findings: {}", result.findings.len());
    for f in &result.findings {
        println!(
            "  [{:?}] {:?} - {} ({}:{})",
            f.severity,
            f.kind,
            f.message,
            f.file.display(),
            f.line_start
        );
    }

    // Should find WeakCrypto (md5)
    let weak_crypto = result
        .findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::WeakCrypto));
    assert!(weak_crypto, "should find WeakCrypto finding for md5()");

    // Should find EvalUsage
    let eval_usage = result
        .findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::EvalUsage));
    assert!(eval_usage, "should find EvalUsage finding");

    // Should find HardcodedSecret
    let secret = result
        .findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::HardcodedSecret));
    assert!(secret, "should find HardcodedSecret finding");

    // Taint analysis: $_GET into DB::raw is SQL injection, echo of $_GET is XSS
    let sqli = result
        .findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::SqlInjection));
    assert!(sqli, "should find SqlInjection via taint analysis");
    let xss = result
        .findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::XssVulnerability));
    assert!(xss, "should find XssVulnerability via taint analysis");

    // Security score should be low
    println!("Security score: {}", result.score.security);
    assert!(
        result.score.security < 80,
        "security score should be low, got {}",
        result.score.security
    );
}

#[test]
fn test_interprocedural_taint() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let fixture_path = std::path::Path::new(&manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/php_interproc");

    let config = verum_mappa::AtlasConfig {
        root: fixture_path,
        ..Default::default()
    };
    let ir = verum_mappa::Atlas::new(config)
        .build()
        .expect("should parse");

    let (findings, paths) = verum_lumen::taint::analyse_with_paths(&ir);
    for f in &findings {
        println!("  [{:?}] {:?} - {}", f.severity, f.kind, f.message);
    }

    // show() passes $_GET-derived $id into loadReport(), which contains a raw
    // SQL sink - only visible across the function boundary.
    let cross_sql = findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::SqlInjection) && f.message.contains("loadReport"));
    assert!(cross_sql, "should flag tainted argument into loadReport()");

    // greet() echoes the tainted return of currentUser() - requires the
    // tainted-return fixpoint round.
    let xss_via_return = findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::XssVulnerability));
    assert!(xss_via_return, "should flag echo of tainted return value");

    // Structured taint paths are produced with at least one multi-hop entry.
    assert!(
        paths.iter().any(|p| p.hops.len() >= 2),
        "should build a multi-hop TaintPath"
    );

    // safeGreet() sanitizes with htmlspecialchars - must not be flagged.
    let safe_flagged = findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::XssVulnerability) && f.line_start >= 27);
    assert!(!safe_flagged, "sanitized path must not be flagged");
}

#[test]
fn test_rust_insights_on_net_server_fixture() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let fixture = std::path::Path::new(&manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/rust_net_server");

    let config = verum_mappa::AtlasConfig {
        root: fixture,
        language: verum_nucleus::Language::Rust,
        ..Default::default()
    };
    let ir = verum_mappa::Atlas::new(config)
        .build()
        .expect("should parse");
    let insights = verum_lumen::rust_insights::analyse(&ir);

    let has = |k: FindingKind| insights.iter().any(|f| f.kind == k);
    for f in &insights {
        println!(
            "  [{:?}] {} ({}:{})",
            f.kind,
            f.message,
            f.file.display(),
            f.line_start
        );
    }

    assert!(
        has(FindingKind::UnsafeUsage),
        "should flag the unsafe header parse"
    );
    assert!(
        has(FindingKind::PanicRisk),
        "should flag unwraps in the hot loops"
    );
    assert!(
        has(FindingKind::UnboundedChannel),
        "should flag the unbounded std channel"
    );
    assert!(
        has(FindingKind::BlockingInAsync),
        "should flag blocking I/O in the async supervisor"
    );
    assert!(
        has(FindingKind::HotPathAllocation),
        "should flag the per-message to_vec allocation"
    );

    // A sync guard held across await (quic::handle_stream_bad) fires; the tokio
    // async mutex (handle_stream_ok) must not - it's meant to be held there.
    let lock_awaits = insights
        .iter()
        .filter(|f| f.kind == FindingKind::LockAcrossAwait)
        .count();
    assert_eq!(
        lock_awaits, 1,
        "only the std-mutex-across-await should flag"
    );

    // Every insight carries a remediation suggestion.
    assert!(insights.iter().all(|f| !f.suggestion.is_empty()));

    // Insights are informational - never Critical/High severity.
    assert!(insights.iter().all(|f| !matches!(
        f.severity,
        verum_nucleus::Severity::Critical | verum_nucleus::Severity::High
    )));
}

#[test]
fn transport_flags_unbounded_length_but_not_bounded() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let fixture = std::path::Path::new(&manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/rust_net_server");
    let config = verum_mappa::AtlasConfig {
        root: fixture,
        language: verum_nucleus::Language::Rust,
        ..Default::default()
    };
    let ir = verum_mappa::Atlas::new(config)
        .build()
        .expect("should parse");
    let findings = verum_lumen::transport::analyse(&ir);

    // tcp::read_frame_unbounded reads a u32 length off the wire and allocates it;
    // read_frame_bounded caps it against MAX_FRAME first and must not be flagged.
    let tcp_hits = findings
        .iter()
        .filter(|f| f.kind == FindingKind::UnvalidatedLengthPrefix)
        .filter(|f| f.file.to_string_lossy().ends_with("tcp.rs"))
        .count();
    assert_eq!(tcp_hits, 1, "only the unbounded read should be flagged");
}

#[test]
fn test_naming_analysis() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let fixture_path = std::path::Path::new(&manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/php_simple");

    let config = verum_mappa::AtlasConfig {
        root: fixture_path,
        ..Default::default()
    };
    let atlas = verum_mappa::Atlas::new(config);
    let ir = atlas.build().expect("should parse");

    // Run naming analysis directly (default per-language rules)
    let findings = verum_lumen::naming::analyse(&ir, &verum_lumen::NamingConfig::default());
    println!("Naming findings: {}", findings.len());
    for f in &findings {
        println!("  {:?}: {}", f.kind, f.message);
    }

    // The fixture has getUserById and fetchUser which are get/fetch inconsistency
    let has_inconsistency = findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::NamingInconsistency));
    assert!(
        has_inconsistency,
        "should detect naming inconsistency between get/fetch"
    );
}
