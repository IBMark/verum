use std::path::Path;

use anyhow::Result;
use regex::Regex;

use verum_nucleus::{
    FileId, FileInfo, Finding, FindingKind, Ir, Language, Severity, Symbol, SymbolId, SymbolKind,
    Visibility,
};

/// Parse a Terraform (.tf) file into IR. Line-based scan with block-context
/// tracking: resources become symbols, and checks cover network, storage, IAM,
/// credentials, and the state backend.
pub fn parse_file(path: &Path) -> Result<Ir> {
    let source = std::fs::read_to_string(path)?;
    let line_count = source.lines().count() as u32;
    let size_bytes = std::fs::metadata(path)?.len();

    let mut ir = Ir::new();
    let mut findings = Vec::new();
    let mut symbol_ids = Vec::new();

    let file_id = FileId(crate::stable_hash(path.to_string_lossy().as_ref()));

    let resource_re = Regex::new(r#"^resource\s+"([^"]+)"\s+"([^"]+)""#).unwrap();
    let data_re = Regex::new(r#"^data\s+"([^"]+)"\s+"([^"]+)""#).unwrap();
    let module_re = Regex::new(r#"^module\s+"([^"]+)""#).unwrap();
    let variable_re = Regex::new(r#"^variable\s+"([^"]+)""#).unwrap();
    let terraform_block_re = Regex::new(r#"^terraform\s*\{"#).unwrap();
    let terraform_block_loose_re = Regex::new(r#"^terraform\s*\{?"#).unwrap();
    let provider_re = Regex::new(r#"^provider\s+"([^"]+)""#).unwrap();
    let backend_re = Regex::new(r#"^\s*backend\s+"([^"]+)""#).unwrap();
    let required_version_re = Regex::new(r#"required_version\s*="#).unwrap();

    let cidr_open_re = Regex::new(r#"(?:cidr_blocks|cidr)\s*=\s*\[?\s*"0\.0\.0\.0/0""#).unwrap();
    let ipv6_open_re = Regex::new(r#"(?:ipv6_cidr_blocks|ipv6_cidr)\s*=\s*\[?\s*"::/0""#).unwrap();
    let from_port_re = Regex::new(r#"from_port\s*=\s*(\d+)"#).unwrap();
    let to_port_re = Regex::new(r#"to_port\s*=\s*(\d+)"#).unwrap();
    let protocol_all_re = Regex::new(r#"protocol\s*=\s*"-1""#).unwrap();

    let public_acl_re = Regex::new(r#"acl\s*=\s*"public-read(?:-write)?""#).unwrap();
    let publicly_accessible_re = Regex::new(r#"publicly_accessible\s*=\s*true"#).unwrap();

    let action_star_re =
        Regex::new(r#"(?i)(?:Action|actions)\s*=\s*(?:\[?\s*"?\*"?\s*\]?|\*)"#).unwrap();
    let resource_star_re =
        Regex::new(r#"(?i)(?:Resource|resources)\s*=\s*(?:\[?\s*"?\*"?\s*\]?|\*)"#).unwrap();

    let hardcoded_cred_re = Regex::new(
        r#"(?i)(?:password|secret_key|access_key|api_key|token|master_password|admin_password)\s*=\s*"[^"]{8,}""#,
    )
    .unwrap();
    let access_key_re =
        Regex::new(r#"(?i)(?:access_key|aws_access_key_id)\s*=\s*"(?:AKIA|ASIA)[A-Z0-9]{16}""#)
            .unwrap();
    let secret_key_re =
        Regex::new(r#"(?i)(?:secret_key|aws_secret_access_key)\s*=\s*"[A-Za-z0-9/+=]{40}""#)
            .unwrap();

    let imdsv2_re = Regex::new(r#"http_tokens\s*=\s*"required""#).unwrap();

    let force_destroy_re = Regex::new(r#"force_destroy\s*=\s*true"#).unwrap();
    let todo_re = Regex::new(r#"(?i)(?:#|//)\s*(?:TODO|FIXME|HACK|XXX)\b"#).unwrap();

    let sensitive_default_re = Regex::new(r#"(?i)default\s*=\s*"[^"]{8,}""#).unwrap();

    let mut ctx = BlockContext::new();
    let lines: Vec<&str> = source.lines().collect();

    // Pre-scan for file-level facts (terraform block, backend config).
    let mut has_terraform_block = false;
    let mut has_backend = false;
    let mut has_backend_encrypt = false;
    let mut has_backend_lock = false;
    let mut has_required_version = false;
    let mut has_provider_version = false;

    for line in &lines {
        let trimmed = line.trim();
        if (terraform_block_re.is_match(trimmed) || terraform_block_loose_re.is_match(trimmed))
            && trimmed.starts_with("terraform")
        {
            has_terraform_block = true;
        }
        if backend_re.is_match(trimmed) {
            has_backend = true;
        }
        if trimmed.contains("encrypt") && trimmed.contains("true") {
            has_backend_encrypt = true;
        }
        if trimmed.contains("dynamodb_table") || trimmed.contains("lock") {
            has_backend_lock = true;
        }
        if required_version_re.is_match(trimmed) {
            has_required_version = true;
        }
        if trimmed.contains("required_providers")
            || (trimmed.contains("version") && trimmed.contains("source"))
        {
            has_provider_version = true;
        }
    }

    for (line_idx, line) in lines.iter().enumerate() {
        let line_num = (line_idx + 1) as u32;
        let trimmed = line.trim();

        if trimmed.is_empty() {
            continue;
        }

        if todo_re.is_match(trimmed) {
            findings.push(make_finding(
                path,
                line_num,
                FindingKind::ConventionViolation,
                Severity::Low,
                0.90,
                "TODO/FIXME comment in infrastructure code",
                "Resolve TODOs before merging infrastructure changes",
            ));
        }

        // comments were only eligible for the TODO check above
        if trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }

        let open_braces = trimmed.matches('{').count() as i32;
        let close_braces = trimmed.matches('}').count() as i32;

        if let Some(caps) = resource_re.captures(trimmed) {
            ctx.finalize_resource(&mut ir, &mut symbol_ids, &mut findings, path);

            let rtype = caps[1].to_string();
            let rname = caps[2].to_string();
            ctx.enter_resource(rtype, rname, line_num);
        }

        if let Some(caps) = data_re.captures(trimmed) {
            let fq = format!("tf::data.{}.{}", &caps[1], &caps[2]);
            // Namespace the id by file path so identically named data sources
            // in different files survive IR merge.
            let id = SymbolId(crate::stable_hash(&format!("{}::{}", fq, path.display())));
            ir.symbols.insert(
                id,
                Symbol {
                    id,
                    name: caps[2].to_string(),
                    fully_qualified: fq,
                    kind: SymbolKind::Variable,
                    visibility: Visibility::Public,
                    file: path.to_path_buf(),
                    line_start: line_num,
                    line_end: line_num,
                    col_start: 0,
                    col_end: 0,
                    language: Language::Terraform,
                    parent: None,
                    hash: 0,
                    normalized_hash: 0,
                    flow_hash: 0,
                    param_count: 0,
                    is_entry_point: true,
                    doc_comment: Some(format!("Terraform data source {}", &caps[1])),
                },
            );
            ir.metadata.total_symbols += 1;
            symbol_ids.push(id);
        }

        if let Some(caps) = module_re.captures(trimmed) {
            let fq = format!("tf::module.{}", &caps[1]);
            // Namespace the id by file path so identically named modules in
            // different files survive IR merge.
            let id = SymbolId(crate::stable_hash(&format!("{}::{}", fq, path.display())));
            ir.symbols.insert(
                id,
                Symbol {
                    id,
                    name: caps[1].to_string(),
                    fully_qualified: fq,
                    kind: SymbolKind::Class,
                    visibility: Visibility::Public,
                    file: path.to_path_buf(),
                    line_start: line_num,
                    line_end: line_num,
                    col_start: 0,
                    col_end: 0,
                    language: Language::Terraform,
                    parent: None,
                    hash: 0,
                    normalized_hash: 0,
                    flow_hash: 0,
                    param_count: 0,
                    is_entry_point: true,
                    doc_comment: Some("Terraform module".to_string()),
                },
            );
            ir.metadata.total_symbols += 1;
            symbol_ids.push(id);
        }

        if let Some(caps) = variable_re.captures(trimmed) {
            let var_name = caps[1].to_string();
            let var_name_lower = var_name.to_lowercase();
            if var_name_lower.contains("password")
                || var_name_lower.contains("secret")
                || var_name_lower.contains("token")
                || var_name_lower.contains("api_key")
                || var_name_lower.contains("credential")
            {
                ctx.in_sensitive_variable = true;
                ctx.sensitive_var_name = Some(var_name);
                ctx.sensitive_var_line = line_num;
            }
        }

        if provider_re.is_match(trimmed) {
            ctx.in_provider = true;
        }

        ctx.brace_depth += open_braces - close_braces;

        if trimmed.starts_with("ingress")
            || trimmed.contains("ingress {")
            || trimmed.contains("ingress{")
        {
            ctx.in_ingress = true;
            ctx.ingress_depth = ctx.brace_depth;
        }
        if trimmed.starts_with("egress")
            || trimmed.contains("egress {")
            || trimmed.contains("egress{")
        {
            ctx.in_egress = true;
            ctx.has_egress = true;
        }
        if trimmed.starts_with("server_side_encryption")
            || trimmed.contains("server_side_encryption")
        {
            ctx.has_encryption = true;
        }
        if trimmed.contains("versioning") && trimmed.contains('{') {
            ctx.in_versioning_block = true;
        }
        if ctx.in_versioning_block && trimmed.contains("enabled") && trimmed.contains("true") {
            ctx.has_versioning = true;
        }
        if trimmed.contains("logging") && trimmed.contains('{') {
            ctx.has_logging = true;
        }
        if trimmed.contains("storage_encrypted") && trimmed.contains("true") {
            ctx.has_encryption = true;
        }
        if trimmed.contains("encrypted") && trimmed.contains("true") {
            ctx.has_encryption = true;
        }
        if trimmed.contains("metadata_options") && trimmed.contains('{') {
            ctx.in_metadata_options = true;
        }
        if ctx.in_metadata_options && imdsv2_re.is_match(trimmed) {
            ctx.has_imdsv2 = true;
        }
        if trimmed.contains("vpc_config") || trimmed.contains("subnet_ids") {
            ctx.has_vpc_config = true;
        }
        if trimmed.contains("health_check") {
            ctx.has_health_check = true;
        }
        if trimmed.contains("tags") && (trimmed.contains('{') || trimmed.contains("=")) {
            ctx.has_tags = true;
        }
        if trimmed.contains("flow_log") || trimmed.contains("aws_flow_log") {
            ctx.has_flow_logs = true;
        }
        if trimmed.contains("inline_policy") {
            ctx.has_inline_policy = true;
        }
        if trimmed.contains("mfa") || trimmed.contains("condition") {
            // Rough check for MFA conditions in assume role policy
            if trimmed.contains("MultiFactorAuth") || trimmed.contains("mfa") {
                ctx.has_mfa_requirement = true;
            }
        }

        if ctx.in_sensitive_variable && sensitive_default_re.is_match(trimmed) {
            findings.push(make_finding(
                path,
                line_num,
                FindingKind::HardcodedCredential,
                Severity::High,
                0.85,
                &format!(
                    "Sensitive variable '{}' has a hardcoded default value",
                    ctx.sensitive_var_name.as_deref().unwrap_or("unknown")
                ),
                "Remove the default value and pass via terraform.tfvars, environment variables, or a secrets manager",
            ));
        }

        if close_braces > 0 {
            if ctx.in_ingress && ctx.brace_depth < ctx.ingress_depth {
                ctx.in_ingress = false;
            }
            if ctx.in_egress && ctx.brace_depth <= 1 {
                ctx.in_egress = false;
            }
            if ctx.in_versioning_block && ctx.brace_depth <= 1 {
                ctx.in_versioning_block = false;
            }
            if ctx.in_metadata_options && ctx.brace_depth <= 1 {
                ctx.in_metadata_options = false;
            }
            if ctx.in_sensitive_variable && ctx.brace_depth <= 0 {
                ctx.in_sensitive_variable = false;
                ctx.sensitive_var_name = None;
            }
            if ctx.in_provider && ctx.brace_depth <= 0 {
                ctx.in_provider = false;
            }
        }

        if ctx.in_ingress && (cidr_open_re.is_match(trimmed) || ipv6_open_re.is_match(trimmed)) {
            findings.push(make_finding(
                path,
                line_num,
                FindingKind::OpenSecurityGroup,
                Severity::Critical,
                0.95,
                "Security group ingress rule allows traffic from 0.0.0.0/0 or ::/0",
                "Restrict CIDR blocks to specific IP ranges",
            ));
        }

        if ctx.in_ingress {
            if let Some(from_caps) = from_port_re.captures(trimmed) {
                if let Ok(port) = from_caps[1].parse::<u32>() {
                    if port == 0 {
                        ctx.ingress_from_port_zero = true;
                    }
                }
            }
            if let Some(to_caps) = to_port_re.captures(trimmed) {
                if let Ok(port) = to_caps[1].parse::<u32>() {
                    if port == 65535 && ctx.ingress_from_port_zero {
                        findings.push(make_finding(
                            path,
                            line_num,
                            FindingKind::OpenSecurityGroup,
                            Severity::Critical,
                            0.95,
                            "Security group allows all ports (0-65535)",
                            "Restrict to only necessary ports",
                        ));
                    }
                }
            }
        }

        if ctx.in_ingress && protocol_all_re.is_match(trimmed) {
            findings.push(make_finding(
                path,
                line_num,
                FindingKind::OpenSecurityGroup,
                Severity::High,
                0.90,
                "Security group allows all protocols (protocol = \"-1\")",
                "Restrict to specific protocols (tcp, udp)",
            ));
        }

        if ctx.is_s3_bucket() && public_acl_re.is_match(trimmed) {
            findings.push(make_finding(
                path,
                line_num,
                FindingKind::PublicResource,
                Severity::Critical,
                0.95,
                "S3 bucket has public-read ACL",
                "Use private ACL and grant access via IAM policies or presigned URLs",
            ));
        }

        if ctx.is_rds() && publicly_accessible_re.is_match(trimmed) {
            findings.push(make_finding(
                path,
                line_num,
                FindingKind::PublicResource,
                Severity::Critical,
                0.95,
                "RDS instance is publicly accessible",
                "Set publicly_accessible = false and use VPC/security groups for access",
            ));
        }

        if ctx.is_iam_policy() && action_star_re.is_match(trimmed) {
            findings.push(make_finding(
                path,
                line_num,
                FindingKind::IamOverPermission,
                Severity::Critical,
                0.95,
                "IAM policy grants wildcard Action (*)",
                "Follow the principle of least privilege -- specify exact actions",
            ));
        }

        if ctx.is_iam_policy() && resource_star_re.is_match(trimmed) {
            findings.push(make_finding(
                path,
                line_num,
                FindingKind::IamOverPermission,
                Severity::High,
                0.90,
                "IAM policy grants access to all resources (*)",
                "Restrict Resource to specific ARNs",
            ));
        }

        if access_key_re.is_match(trimmed) {
            findings.push(make_finding(
                path,
                line_num,
                FindingKind::HardcodedCredential,
                Severity::Critical,
                0.95,
                "Hardcoded AWS access key detected",
                "Use AWS profiles, instance roles, or environment variables",
            ));
        } else if secret_key_re.is_match(trimmed) {
            findings.push(make_finding(
                path,
                line_num,
                FindingKind::HardcodedCredential,
                Severity::Critical,
                0.95,
                "Hardcoded AWS secret key detected",
                "Use AWS profiles, instance roles, or environment variables",
            ));
        } else if hardcoded_cred_re.is_match(trimmed) {
            // General hardcoded credential (don't double-flag access/secret keys)
            findings.push(make_finding(
                path,
                line_num,
                FindingKind::HardcodedCredential,
                Severity::Critical,
                0.85,
                "Hardcoded credential detected in Terraform configuration",
                "Use terraform variables with sensitive flag or a secrets manager",
            ));
        }

        if force_destroy_re.is_match(trimmed) {
            findings.push(make_finding(
                path,
                line_num,
                FindingKind::ConventionViolation,
                Severity::High,
                0.85,
                "force_destroy = true enables data loss on terraform destroy",
                "Remove force_destroy or set to false for production resources",
            ));
        }
    }

    ctx.finalize_resource(&mut ir, &mut symbol_ids, &mut findings, path);

    if !has_backend {
        // Only flag if this file has a terraform block or resources (skip pure module/variable files)
        let has_resources = !ir.symbols.is_empty();
        if has_resources && has_terraform_block {
            findings.push(make_finding(
                path,
                1,
                FindingKind::Soc2Violation,
                Severity::High,
                0.80,
                "No backend configuration -- Terraform state is stored locally",
                "Configure a remote backend (S3, GCS, Terraform Cloud) for state storage",
            ));
        }
    } else {
        if !has_backend_encrypt {
            findings.push(make_finding(
                path,
                1,
                FindingKind::UnencryptedStorage,
                Severity::High,
                0.80,
                "Terraform backend does not have encryption enabled",
                "Set encrypt = true in the backend configuration",
            ));
        }
        if !has_backend_lock {
            findings.push(make_finding(
                path,
                1,
                FindingKind::Soc2Violation,
                Severity::Medium,
                0.75,
                "Terraform backend does not have state locking configured",
                "Add dynamodb_table for S3 backend or use a backend with built-in locking",
            ));
        }
    }

    if has_terraform_block && !has_required_version {
        findings.push(make_finding(
            path,
            1,
            FindingKind::UnpinnedImage,
            Severity::Low,
            0.80,
            "No terraform.required_version constraint -- any Terraform version can apply",
            "Add required_version to pin to a known-working Terraform version range",
        ));
    }

    if has_terraform_block && !has_provider_version {
        findings.push(make_finding(
            path,
            1,
            FindingKind::UnpinnedImage,
            Severity::Medium,
            0.80,
            "No provider version constraints in required_providers",
            "Add required_providers with version constraints to prevent breaking changes",
        ));
    }

    ir.files.insert(
        path.to_path_buf(),
        FileInfo {
            id: file_id,
            path: path.to_path_buf(),
            language: Language::Terraform,
            line_count,
            size_bytes,
            last_modified: 0,
            hash: 0,
            symbols: symbol_ids,
        },
    );
    ir.metadata.total_files += 1;
    ir.metadata.total_lines += line_count as u64;

    ir.infra_findings = findings;

    Ok(ir)
}

/// Tracks context while scanning lines within a Terraform file.
#[allow(dead_code)]
struct BlockContext {
    resource_type: Option<String>,
    resource_name: Option<String>,
    resource_start_line: u32,
    brace_depth: i32,

    in_ingress: bool,
    ingress_depth: i32,
    ingress_from_port_zero: bool,
    in_egress: bool,
    has_egress: bool,
    in_versioning_block: bool,
    in_metadata_options: bool,
    in_sensitive_variable: bool,
    sensitive_var_name: Option<String>,
    sensitive_var_line: u32,
    in_provider: bool,

    // Resource-level flags (reset per resource)
    has_encryption: bool,
    has_versioning: bool,
    has_logging: bool,
    has_tags: bool,
    has_imdsv2: bool,
    has_vpc_config: bool,
    has_health_check: bool,
    has_flow_logs: bool,
    has_inline_policy: bool,
    has_mfa_requirement: bool,
}

#[allow(dead_code)]
impl BlockContext {
    fn new() -> Self {
        Self {
            resource_type: None,
            resource_name: None,
            resource_start_line: 0,
            brace_depth: 0,
            in_ingress: false,
            ingress_depth: 0,
            ingress_from_port_zero: false,
            in_egress: false,
            has_egress: false,
            in_versioning_block: false,
            in_metadata_options: false,
            in_sensitive_variable: false,
            sensitive_var_name: None,
            sensitive_var_line: 0,
            in_provider: false,
            has_encryption: false,
            has_versioning: false,
            has_logging: false,
            has_tags: false,
            has_imdsv2: false,
            has_vpc_config: false,
            has_health_check: false,
            has_flow_logs: false,
            has_inline_policy: false,
            has_mfa_requirement: false,
        }
    }

    fn is_s3_bucket(&self) -> bool {
        self.resource_type.as_deref() == Some("aws_s3_bucket")
    }

    fn is_rds(&self) -> bool {
        matches!(
            self.resource_type.as_deref(),
            Some("aws_db_instance") | Some("aws_rds_cluster")
        )
    }

    fn is_iam_policy(&self) -> bool {
        matches!(
            self.resource_type.as_deref(),
            Some(t) if t.contains("iam_policy") || t.contains("iam_role_policy")
        )
    }

    fn is_security_group(&self) -> bool {
        self.resource_type.as_deref() == Some("aws_security_group")
    }

    fn is_ec2_instance(&self) -> bool {
        self.resource_type.as_deref() == Some("aws_instance")
    }

    fn is_lambda(&self) -> bool {
        self.resource_type.as_deref() == Some("aws_lambda_function")
    }

    fn is_asg(&self) -> bool {
        matches!(
            self.resource_type.as_deref(),
            Some("aws_autoscaling_group") | Some("aws_launch_template")
        )
    }

    fn is_vpc(&self) -> bool {
        self.resource_type.as_deref() == Some("aws_vpc")
    }

    fn is_ebs(&self) -> bool {
        self.resource_type.as_deref() == Some("aws_ebs_volume")
    }

    fn is_iam_user(&self) -> bool {
        self.resource_type.as_deref() == Some("aws_iam_user")
    }

    /// Finalize the current resource block: create the symbol and emit
    /// resource-level findings, then reset per-resource state.
    fn finalize_resource(
        &mut self,
        ir: &mut Ir,
        symbol_ids: &mut Vec<SymbolId>,
        findings: &mut Vec<Finding>,
        path: &Path,
    ) {
        if let (Some(rtype), Some(rname)) = (&self.resource_type, &self.resource_name) {
            let rtype = rtype.clone();
            let rname = rname.clone();
            let start_line = self.resource_start_line;

            let fq = format!("tf::{}.{}", rtype, rname);
            // Namespace the id by file path: the same resource name in two
            // files must not collide when partial IRs are merged.
            let id = SymbolId(crate::stable_hash(&format!("{}::{}", fq, path.display())));
            ir.symbols.insert(
                id,
                Symbol {
                    id,
                    name: rname.clone(),
                    fully_qualified: fq,
                    kind: SymbolKind::Class,
                    visibility: Visibility::Public,
                    file: path.to_path_buf(),
                    line_start: start_line,
                    line_end: start_line, // approximate
                    col_start: 0,
                    col_end: 0,
                    language: Language::Terraform,
                    parent: None,
                    hash: 0,
                    normalized_hash: 0,
                    flow_hash: 0,
                    param_count: 0,
                    is_entry_point: true,
                    doc_comment: Some(format!("Terraform resource {}", rtype)),
                },
            );
            ir.metadata.total_symbols += 1;
            symbol_ids.push(id);

            if rtype == "aws_s3_bucket" && !self.has_encryption {
                findings.push(make_finding(
                    path,
                    start_line,
                    FindingKind::UnencryptedStorage,
                    Severity::High,
                    0.85,
                    &format!("S3 bucket '{}' does not have server-side encryption configured", rname),
                    "Add server_side_encryption_configuration block or use aws_s3_bucket_server_side_encryption_configuration",
                ));
            }

            if rtype == "aws_s3_bucket" && !self.has_versioning {
                findings.push(make_finding(
                    path,
                    start_line,
                    FindingKind::UnencryptedStorage,
                    Severity::Medium,
                    0.80,
                    &format!("S3 bucket '{}' does not have versioning enabled", rname),
                    "Enable versioning for data protection and recovery",
                ));
            }

            if rtype == "aws_s3_bucket" && !self.has_logging {
                findings.push(make_finding(
                    path,
                    start_line,
                    FindingKind::Soc2Violation,
                    Severity::Medium,
                    0.75,
                    &format!("S3 bucket '{}' does not have access logging enabled", rname),
                    "Enable server access logging or use CloudTrail data events",
                ));
            }

            if (rtype == "aws_db_instance" || rtype == "aws_rds_cluster") && !self.has_encryption {
                findings.push(make_finding(
                    path,
                    start_line,
                    FindingKind::UnencryptedStorage,
                    Severity::High,
                    0.90,
                    &format!("RDS resource '{}' does not have encryption enabled", rname),
                    "Set storage_encrypted = true",
                ));
            }

            if rtype == "aws_ebs_volume" && !self.has_encryption {
                findings.push(make_finding(
                    path,
                    start_line,
                    FindingKind::UnencryptedStorage,
                    Severity::Medium,
                    0.85,
                    &format!("EBS volume '{}' does not have encryption enabled", rname),
                    "Set encrypted = true",
                ));
            }

            if rtype == "aws_security_group" && !self.has_egress {
                findings.push(make_finding(
                    path,
                    start_line,
                    FindingKind::OpenSecurityGroup,
                    Severity::Medium,
                    0.75,
                    &format!(
                        "Security group '{}' has no explicit egress restrictions",
                        rname
                    ),
                    "Define egress rules to restrict outbound traffic",
                ));
            }

            if rtype == "aws_instance" && !self.has_imdsv2 {
                findings.push(make_finding(
                    path,
                    start_line,
                    FindingKind::Soc2Violation,
                    Severity::Medium,
                    0.80,
                    &format!("EC2 instance '{}' does not enforce IMDSv2", rname),
                    "Add metadata_options with http_tokens = \"required\"",
                ));
            }

            if rtype == "aws_lambda_function" && !self.has_vpc_config {
                findings.push(make_finding(
                    path,
                    start_line,
                    FindingKind::NoNetworkPolicy,
                    Severity::Medium,
                    0.70,
                    &format!("Lambda function '{}' is not deployed in a VPC", rname),
                    "Add vpc_config to deploy Lambda within a VPC for network isolation",
                ));
            }

            if rtype == "aws_autoscaling_group" && !self.has_health_check {
                findings.push(make_finding(
                    path,
                    start_line,
                    FindingKind::MissingHealthProbes,
                    Severity::Medium,
                    0.80,
                    &format!(
                        "Auto Scaling group '{}' has no health check configuration",
                        rname
                    ),
                    "Configure health_check_type and health_check_grace_period",
                ));
            }

            if rtype == "aws_vpc" && !self.has_flow_logs {
                findings.push(make_finding(
                    path,
                    start_line,
                    FindingKind::NoNetworkPolicy,
                    Severity::Medium,
                    0.75,
                    &format!("VPC '{}' does not have flow logs enabled", rname),
                    "Create an aws_flow_log resource for network traffic monitoring",
                ));
            }

            if rtype == "aws_iam_user" && self.has_inline_policy {
                findings.push(make_finding(
                    path,
                    start_line,
                    FindingKind::IamOverPermission,
                    Severity::Medium,
                    0.80,
                    &format!("IAM user '{}' has inline policies", rname),
                    "Use managed policies attached via aws_iam_user_policy_attachment instead",
                ));
            }

            if !self.has_tags && is_taggable_resource(&rtype) {
                findings.push(make_finding(
                    path,
                    start_line,
                    FindingKind::ConventionViolation,
                    Severity::Low,
                    0.70,
                    &format!("Resource '{}' ({}) has no tags", rname, rtype),
                    "Add tags for cost allocation, ownership, and environment identification",
                ));
            }
        }

        self.resource_type = None;
        self.resource_name = None;
        self.resource_start_line = 0;
        self.in_ingress = false;
        self.ingress_depth = 0;
        self.ingress_from_port_zero = false;
        self.in_egress = false;
        self.has_egress = false;
        self.in_versioning_block = false;
        self.in_metadata_options = false;
        self.has_encryption = false;
        self.has_versioning = false;
        self.has_logging = false;
        self.has_tags = false;
        self.has_imdsv2 = false;
        self.has_vpc_config = false;
        self.has_health_check = false;
        self.has_flow_logs = false;
        self.has_inline_policy = false;
        self.has_mfa_requirement = false;
    }

    fn enter_resource(&mut self, rtype: String, rname: String, line: u32) {
        self.resource_type = Some(rtype);
        self.resource_name = Some(rname);
        self.resource_start_line = line;
        self.brace_depth = 0;
        self.in_ingress = false;
        self.ingress_depth = 0;
        self.ingress_from_port_zero = false;
        self.in_egress = false;
        self.has_egress = false;
        self.in_versioning_block = false;
        self.in_metadata_options = false;
        self.has_encryption = false;
        self.has_versioning = false;
        self.has_logging = false;
        self.has_tags = false;
        self.has_imdsv2 = false;
        self.has_vpc_config = false;
        self.has_health_check = false;
        self.has_flow_logs = false;
        self.has_inline_policy = false;
        self.has_mfa_requirement = false;
    }
}

fn is_taggable_resource(rtype: &str) -> bool {
    matches!(
        rtype,
        "aws_instance"
            | "aws_s3_bucket"
            | "aws_security_group"
            | "aws_db_instance"
            | "aws_rds_cluster"
            | "aws_ebs_volume"
            | "aws_vpc"
            | "aws_subnet"
            | "aws_lambda_function"
            | "aws_iam_role"
            | "aws_iam_user"
            | "aws_autoscaling_group"
            | "aws_launch_template"
            | "aws_lb"
            | "aws_ecs_cluster"
            | "aws_ecs_service"
            | "aws_eks_cluster"
            | "aws_elasticache_cluster"
            | "aws_sns_topic"
            | "aws_sqs_queue"
            | "aws_kinesis_stream"
    )
}

fn make_finding(
    path: &Path,
    line_num: u32,
    kind: FindingKind,
    severity: Severity,
    confidence: f32,
    message: &str,
    suggestion: &str,
) -> Finding {
    Finding {
        fingerprint: String::new(),
        id: format!("tf-{:?}-{}:{}", kind, path.display(), line_num),
        kind,
        severity,
        confidence,
        file: path.to_path_buf(),
        line_start: line_num,
        line_end: line_num,
        symbol: None,
        message: message.to_string(),
        suggestion: suggestion.to_string(),
        auto_fixable: false,
        related: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn parse_tf_str(content: &str) -> Ir {
        // pid + per-call counter: unique across parallel test threads, unlike
        // the wall clock (two threads can read equal nanos).
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("verum_tf_test_{}_{seq}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.tf");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        let result = parse_file(&path).expect("should parse");
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    fn has_finding(ir: &Ir, kind: FindingKind) -> bool {
        ir.infra_findings.iter().any(|f| f.kind == kind)
    }

    fn has_finding_severity(ir: &Ir, kind: FindingKind, severity: Severity) -> bool {
        ir.infra_findings
            .iter()
            .any(|f| f.kind == kind && f.severity == severity)
    }

    #[test]
    fn test_open_security_group() {
        let ir = parse_tf_str(
            r#"
resource "aws_security_group" "bad" {
  name = "bad"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"#,
        );
        assert!(has_finding_severity(
            &ir,
            FindingKind::OpenSecurityGroup,
            Severity::Critical
        ));
    }

    #[test]
    fn test_all_ports_open() {
        let ir = parse_tf_str(
            r#"
resource "aws_security_group" "wide" {
  name = "wide"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
"#,
        );
        // Should detect all-ports-open even without 0.0.0.0/0
        let has_all_ports = ir
            .infra_findings
            .iter()
            .any(|f| f.kind == FindingKind::OpenSecurityGroup && f.message.contains("all ports"));
        assert!(has_all_ports);
    }

    #[test]
    fn test_all_protocols() {
        let ir = parse_tf_str(
            r#"
resource "aws_security_group" "proto" {
  name = "proto"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
"#,
        );
        assert!(has_finding_severity(
            &ir,
            FindingKind::OpenSecurityGroup,
            Severity::High
        ));
    }

    #[test]
    fn test_missing_egress() {
        let ir = parse_tf_str(
            r#"
resource "aws_security_group" "no_egress" {
  name = "no_egress"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
"#,
        );
        let has_no_egress = ir.infra_findings.iter().any(|f| {
            f.kind == FindingKind::OpenSecurityGroup
                && f.severity == Severity::Medium
                && f.message.contains("egress")
        });
        assert!(has_no_egress);
    }

    #[test]
    fn test_public_s3() {
        let ir = parse_tf_str(
            r#"
resource "aws_s3_bucket" "public" {
  bucket = "my-bucket"
  acl    = "public-read"
}
"#,
        );
        assert!(has_finding_severity(
            &ir,
            FindingKind::PublicResource,
            Severity::Critical
        ));
    }

    #[test]
    fn test_s3_no_encryption() {
        let ir = parse_tf_str(
            r#"
resource "aws_s3_bucket" "unenc" {
  bucket = "my-bucket"
}
"#,
        );
        assert!(has_finding_severity(
            &ir,
            FindingKind::UnencryptedStorage,
            Severity::High
        ));
    }

    #[test]
    fn test_s3_no_versioning() {
        let ir = parse_tf_str(
            r#"
resource "aws_s3_bucket" "nover" {
  bucket = "my-bucket"
}
"#,
        );
        let has_no_ver = ir
            .infra_findings
            .iter()
            .any(|f| f.kind == FindingKind::UnencryptedStorage && f.message.contains("versioning"));
        assert!(has_no_ver);
    }

    #[test]
    fn test_s3_no_logging() {
        let ir = parse_tf_str(
            r#"
resource "aws_s3_bucket" "nolog" {
  bucket = "my-bucket"
}
"#,
        );
        assert!(has_finding_severity(
            &ir,
            FindingKind::Soc2Violation,
            Severity::Medium
        ));
    }

    #[test]
    fn test_rds_publicly_accessible() {
        let ir = parse_tf_str(
            r#"
resource "aws_db_instance" "db" {
  engine              = "postgres"
  publicly_accessible = true
}
"#,
        );
        assert!(has_finding_severity(
            &ir,
            FindingKind::PublicResource,
            Severity::Critical
        ));
    }

    #[test]
    fn test_rds_no_encryption() {
        let ir = parse_tf_str(
            r#"
resource "aws_db_instance" "db" {
  engine = "postgres"
}
"#,
        );
        assert!(has_finding_severity(
            &ir,
            FindingKind::UnencryptedStorage,
            Severity::High
        ));
    }

    #[test]
    fn test_iam_action_star() {
        let ir = parse_tf_str(
            r#"
resource "aws_iam_policy" "admin" {
  name = "admin"
  policy = jsonencode({
    Statement = [{
      Action   = "*"
      Resource = "*"
      Effect   = "Allow"
    }]
  })
}
"#,
        );
        assert!(has_finding_severity(
            &ir,
            FindingKind::IamOverPermission,
            Severity::Critical
        ));
        assert!(has_finding_severity(
            &ir,
            FindingKind::IamOverPermission,
            Severity::High
        ));
    }

    #[test]
    fn test_hardcoded_credentials() {
        let ir = parse_tf_str(
            r#"
resource "aws_db_instance" "db" {
  engine          = "postgres"
  master_password = "SuperSecret123!"
}
"#,
        );
        assert!(has_finding(&ir, FindingKind::HardcodedCredential));
    }

    #[test]
    fn test_force_destroy() {
        let ir = parse_tf_str(
            r#"
resource "aws_s3_bucket" "data" {
  bucket        = "important-data"
  force_destroy = true
}
"#,
        );
        assert!(has_finding_severity(
            &ir,
            FindingKind::ConventionViolation,
            Severity::High
        ));
    }

    #[test]
    fn test_missing_tags() {
        let ir = parse_tf_str(
            r#"
resource "aws_instance" "web" {
  ami           = "ami-12345"
  instance_type = "t3.micro"
}
"#,
        );
        let has_no_tags = ir
            .infra_findings
            .iter()
            .any(|f| f.kind == FindingKind::ConventionViolation && f.message.contains("tags"));
        assert!(has_no_tags);
    }

    #[test]
    fn test_ec2_no_imdsv2() {
        let ir = parse_tf_str(
            r#"
resource "aws_instance" "web" {
  ami           = "ami-12345"
  instance_type = "t3.micro"
}
"#,
        );
        assert!(has_finding_severity(
            &ir,
            FindingKind::Soc2Violation,
            Severity::Medium
        ));
    }

    #[test]
    fn test_lambda_no_vpc() {
        let ir = parse_tf_str(
            r#"
resource "aws_lambda_function" "fn" {
  function_name = "my-func"
  runtime       = "python3.12"
  handler       = "main.handler"
}
"#,
        );
        assert!(has_finding_severity(
            &ir,
            FindingKind::NoNetworkPolicy,
            Severity::Medium
        ));
    }

    #[test]
    fn test_todo_comment() {
        let ir = parse_tf_str(
            r#"
resource "aws_instance" "web" {
  ami           = "ami-12345"
  # TODO: fix this later
  instance_type = "t3.micro"
}
"#,
        );
        let has_todo = ir
            .infra_findings
            .iter()
            .any(|f| f.kind == FindingKind::ConventionViolation && f.message.contains("TODO"));
        assert!(has_todo);
    }
}
