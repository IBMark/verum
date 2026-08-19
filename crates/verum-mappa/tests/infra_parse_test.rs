use std::path::PathBuf;

use verum_nucleus::FindingKind;

fn fixtures_dir() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    PathBuf::from(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
        .join("k8s_simple")
}

#[test]
fn test_parse_kubernetes_yaml() {
    let path = fixtures_dir().join("deployment.yaml");
    let ir = verum_mappa::kubernetes::parse_file(&path).expect("should parse K8s YAML");

    assert!(ir.symbol_count() > 0, "should extract K8s resource symbols");

    let has_web_app = ir.symbols.values().any(|s| s.name == "web-app");
    assert!(has_web_app, "should find web-app Deployment resource");

    assert!(!ir.files.is_empty(), "should have file info");

    assert!(
        !ir.infra_findings.is_empty(),
        "should detect infrastructure security issues"
    );

    let has_unpinned = ir
        .infra_findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::UnpinnedImage));
    assert!(has_unpinned, "should detect unpinned image (nginx:latest)");

    let has_privileged = ir
        .infra_findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::PrivilegedContainer));
    assert!(has_privileged, "should detect privileged container");

    let has_missing_limits = ir
        .infra_findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::MissingResourceLimits));
    assert!(has_missing_limits, "should detect missing resource limits");

    let has_missing_probes = ir
        .infra_findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::MissingHealthProbes));
    assert!(has_missing_probes, "should detect missing health probes");

    let has_secret = ir
        .infra_findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::SecretInEnvVar));
    assert!(has_secret, "should detect secret in env var");

    println!("K8s findings: {}", ir.infra_findings.len());
    for f in &ir.infra_findings {
        println!("  {:?} ({:?}) - {}", f.kind, f.severity, f.message);
    }
}

#[test]
fn test_parse_dockerfile() {
    let path = fixtures_dir().join("Dockerfile");
    let ir = verum_mappa::dockerfile::parse_file(&path).expect("should parse Dockerfile");

    assert!(ir.symbol_count() > 0, "should extract Docker stage symbols");

    assert!(!ir.files.is_empty(), "should have file info");

    assert!(
        !ir.infra_findings.is_empty(),
        "should detect Dockerfile security issues"
    );

    let has_unpinned = ir
        .infra_findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::UnpinnedImage));
    assert!(
        has_unpinned,
        "should detect unpinned base image (node:latest)"
    );

    let has_root = ir
        .infra_findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::RunningAsRoot));
    assert!(has_root, "should detect USER root");

    let has_credential = ir
        .infra_findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::HardcodedCredential));
    assert!(has_credential, "should detect hardcoded secret in ENV");

    println!("Dockerfile findings: {}", ir.infra_findings.len());
    for f in &ir.infra_findings {
        println!("  {:?} ({:?}) - {}", f.kind, f.severity, f.message);
    }
}

#[test]
fn test_parse_terraform() {
    let path = fixtures_dir().join("main.tf");
    let ir = verum_mappa::terraform::parse_file(&path).expect("should parse Terraform");

    assert!(
        ir.symbol_count() > 0,
        "should extract Terraform resource symbols"
    );

    let has_allow_all = ir.symbols.values().any(|s| s.name == "allow_all");
    assert!(
        has_allow_all,
        "should find allow_all security group resource"
    );

    let has_data_bucket = ir.symbols.values().any(|s| s.name == "data");
    assert!(has_data_bucket, "should find data S3 bucket resource");

    assert!(!ir.files.is_empty(), "should have file info");

    assert!(
        !ir.infra_findings.is_empty(),
        "should detect Terraform security issues"
    );

    let has_open_sg = ir
        .infra_findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::OpenSecurityGroup));
    assert!(has_open_sg, "should detect open security group (0.0.0.0/0)");

    let has_public_s3 = ir
        .infra_findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::PublicResource));
    assert!(has_public_s3, "should detect public S3 bucket");

    let has_unencrypted = ir
        .infra_findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::UnencryptedStorage));
    assert!(has_unencrypted, "should detect unencrypted S3 bucket");

    let has_iam_over = ir
        .infra_findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::IamOverPermission));
    assert!(
        has_iam_over,
        "should detect IAM over-permission (Action: *)"
    );

    println!("Terraform findings: {}", ir.infra_findings.len());
    for f in &ir.infra_findings {
        println!("  {:?} ({:?}) - {}", f.kind, f.severity, f.message);
    }
}

#[test]
fn test_atlas_collects_infra_files() {
    let config = verum_mappa::AtlasConfig {
        root: fixtures_dir(),
        language: verum_nucleus::Language::Php, // primary language doesn't matter
        ..Default::default()
    };
    let atlas = verum_mappa::Atlas::new(config);
    let ir = atlas.build().expect("should build IR with infra files");

    assert!(
        ir.metadata.total_files >= 3,
        "should have at least 3 infra files"
    );

    assert!(
        !ir.infra_findings.is_empty(),
        "should have infra findings from all parsers"
    );

    println!("Total files: {}", ir.metadata.total_files);
    println!("Total symbols: {}", ir.symbol_count());
    println!("Total infra findings: {}", ir.infra_findings.len());
    for f in &ir.infra_findings {
        println!(
            "  {:?} ({:?}) - {} [{}:{}]",
            f.kind,
            f.severity,
            f.message,
            f.file.display(),
            f.line_start
        );
    }
}
