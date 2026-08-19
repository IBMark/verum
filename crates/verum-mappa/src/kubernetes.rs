use std::path::Path;

use anyhow::Result;
use regex::Regex;
use serde_yaml::Value;

use verum_nucleus::{
    FileId, FileInfo, Finding, FindingKind, Ir, Language, Severity, Symbol, SymbolId, SymbolKind,
    Visibility,
};

/// Parse a Kubernetes manifest into IR. Structured YAML parsing does the
/// resource-level checks; a line-based scan catches what YAML parsing can't
/// place (TODOs, placeholders, commented-out config).
pub fn parse_file(path: &Path) -> Result<Ir> {
    let source = std::fs::read_to_string(path)?;
    let line_count = source.lines().count() as u32;
    let size_bytes = std::fs::metadata(path)?.len();

    let mut ir = Ir::new();

    if !source.contains("apiVersion:") || !source.contains("kind:") {
        let file_id = FileId(crate::stable_hash(path.to_string_lossy().as_ref()));
        ir.files.insert(
            path.to_path_buf(),
            FileInfo {
                id: file_id,
                path: path.to_path_buf(),
                language: Language::Kubernetes,
                line_count,
                size_bytes,
                last_modified: 0,
                hash: 0,
                symbols: Vec::new(),
            },
        );
        ir.metadata.total_files += 1;
        ir.metadata.total_lines += line_count as u64;
        return Ok(ir);
    }

    let file_id = FileId(crate::stable_hash(path.to_string_lossy().as_ref()));
    let mut findings = Vec::new();
    let mut symbol_ids = Vec::new();

    let documents = split_yaml_documents(&source);

    for (doc_offset, doc_text) in &documents {
        let parsed: Value = match serde_yaml::from_str(doc_text) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if !parsed.is_mapping() {
            continue;
        }

        let kind = yaml_str(&parsed, "kind").unwrap_or_default();
        let name = yaml_nested_str(&parsed, &["metadata", "name"]).unwrap_or_default();

        if kind.is_empty() {
            continue;
        }

        let doc_line_count = doc_text.lines().count() as u32;
        let sym_id = create_resource_symbol(
            &mut ir,
            path,
            &kind,
            &name,
            *doc_offset,
            doc_offset + doc_line_count,
        );
        symbol_ids.push(sym_id);

        match kind.as_str() {
            "Deployment" | "StatefulSet" | "DaemonSet" | "Job" | "CronJob" | "ReplicaSet" => {
                check_workload(&parsed, &kind, path, *doc_offset, &source, &mut findings);
            }
            "Pod" => {
                let spec = &parsed["spec"];
                check_pod_spec(spec, path, *doc_offset, &source, &mut findings);
            }
            "Ingress" => {
                check_ingress_tls(&parsed, path, *doc_offset, &mut findings);
            }
            "NetworkPolicy" => {
                check_network_policy(&parsed, path, *doc_offset, &mut findings);
            }
            "ClusterRole" | "Role" => {
                check_rbac(&parsed, &kind, path, *doc_offset, &mut findings);
            }
            "ClusterRoleBinding" | "RoleBinding" => {
                // Check for overly broad bindings (covered via RBAC rules on the referenced role)
            }
            "ServiceAccount" => {
                check_service_account(&parsed, path, *doc_offset, &mut findings);
            }
            "Namespace" => {
                check_namespace(&parsed, path, *doc_offset, &mut findings);
            }
            "Secret" => {
                check_secrets(&parsed, path, *doc_offset, &mut findings);
            }
            "ClusterPolicy" | "Policy" => {
                // Kyverno policies
                check_policy_enforcement(&parsed, path, *doc_offset, &mut findings);
            }
            "SealedSecret" => {
                // SealedSecrets are fine - but check for placeholder values
                check_sealed_secret_placeholders(&parsed, path, *doc_offset, &mut findings);
            }
            _ => {}
        }
    }

    check_line_patterns(&source, path, &mut findings);

    ir.files.insert(
        path.to_path_buf(),
        FileInfo {
            id: file_id,
            path: path.to_path_buf(),
            language: Language::Kubernetes,
            line_count,
            size_bytes,
            last_modified: 0,
            hash: 0,
            symbols: symbol_ids,
        },
    );
    ir.metadata.total_files += 1;
    ir.metadata.total_lines += line_count as u64;

    findings.sort_by(|a, b| a.id.cmp(&b.id));
    findings.dedup_by(|a, b| a.id == b.id);

    ir.infra_findings = findings;
    Ok(ir)
}

/// Split a multi-document YAML string into (line_offset, text) pairs.
fn split_yaml_documents(source: &str) -> Vec<(u32, String)> {
    let mut docs = Vec::new();
    let mut current = String::new();
    let mut current_start: u32 = 1;

    for (line_num, line) in (1_u32..).zip(source.lines()) {
        if line.trim() == "---" {
            if !current.trim().is_empty() {
                docs.push((current_start, current.clone()));
            }
            current.clear();
            current_start = line_num + 1;
        } else {
            current.push_str(line);
            current.push('\n');
        }
    }
    if !current.trim().is_empty() {
        docs.push((current_start, current));
    }
    if docs.is_empty() && !source.trim().is_empty() {
        docs.push((1, source.to_string()));
    }
    docs
}

fn yaml_str(val: &Value, key: &str) -> Option<String> {
    val.get(key)?.as_str().map(|s| s.to_string())
}

fn yaml_nested_str(val: &Value, keys: &[&str]) -> Option<String> {
    let mut v = val;
    for k in keys {
        v = v.get(*k)?;
    }
    v.as_str().map(|s| s.to_string())
}

fn yaml_bool(val: &Value, key: &str) -> Option<bool> {
    val.get(key)?.as_bool()
}

fn yaml_u64(val: &Value, key: &str) -> Option<u64> {
    val.get(key)?.as_u64()
}

fn yaml_seq<'a>(val: &'a Value, key: &str) -> Option<&'a Vec<Value>> {
    val.get(key)?.as_sequence()
}

fn yaml_str_list(val: &Value, key: &str) -> Vec<String> {
    match val.get(key).and_then(|v| v.as_sequence()) {
        Some(seq) => seq
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        None => Vec::new(),
    }
}

/// Find the line number of a pattern in the source, starting search from a given offset.
fn find_line_of(source: &str, pattern: &str, after_line: u32) -> u32 {
    for (idx, line) in source.lines().enumerate() {
        let line_num = (idx + 1) as u32;
        if line_num >= after_line && line.contains(pattern) {
            return line_num;
        }
    }
    after_line
}

/// Find line number of a pattern occurring at or after `after_line`, within `max_range` lines.
fn find_line_of_bounded(source: &str, pattern: &str, after_line: u32, max_range: u32) -> u32 {
    for (idx, line) in source.lines().enumerate() {
        let line_num = (idx + 1) as u32;
        if line_num < after_line {
            continue;
        }
        if line_num > after_line + max_range {
            break;
        }
        if line.contains(pattern) {
            return line_num;
        }
    }
    after_line
}

fn check_workload(
    val: &Value,
    kind: &str,
    file: &Path,
    doc_offset: u32,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    let pod_spec = if kind == "CronJob" {
        &val["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    } else {
        &val["spec"]["template"]["spec"]
    };

    check_pod_spec(pod_spec, file, doc_offset, source, findings);
}

fn check_pod_spec(
    pod_spec: &Value,
    file: &Path,
    doc_offset: u32,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    if pod_spec.is_null() {
        return;
    }

    if yaml_bool(pod_spec, "hostNetwork") == Some(true) {
        let ln = find_line_of(source, "hostNetwork:", doc_offset);
        findings.push(make_finding(
            file,
            ln,
            FindingKind::OpenSecurityGroup,
            Severity::High,
            0.95,
            "Pod uses host network namespace",
            "Avoid hostNetwork unless required for network-level agents (e.g., CNI, mesh)",
        ));
    }

    if yaml_bool(pod_spec, "hostPID") == Some(true) {
        let ln = find_line_of(source, "hostPID:", doc_offset);
        findings.push(make_finding(
            file,
            ln,
            FindingKind::PrivilegedContainer,
            Severity::High,
            0.95,
            "Pod uses host PID namespace - can see and signal host processes",
            "Remove hostPID: true unless this is a debugging or monitoring agent",
        ));
    }

    if yaml_bool(pod_spec, "hostIPC") == Some(true) {
        let ln = find_line_of(source, "hostIPC:", doc_offset);
        findings.push(make_finding(
            file,
            ln,
            FindingKind::PrivilegedContainer,
            Severity::High,
            0.95,
            "Pod uses host IPC namespace - can access host shared memory",
            "Remove hostIPC: true",
        ));
    }

    // Defaults to true when missing, but only an explicit true is flagged.
    if yaml_bool(pod_spec, "automountServiceAccountToken") == Some(true) {
        let ln = find_line_of(source, "automountServiceAccountToken:", doc_offset);
        findings.push(make_finding(
            file,
            ln,
            FindingKind::IamOverPermission,
            Severity::Low,
            0.70,
            "automountServiceAccountToken is explicitly true - token mounted into pod",
            "Set automountServiceAccountToken: false if the pod does not need Kubernetes API access",
        ));
    }

    if let Some(containers) = yaml_seq(pod_spec, "containers") {
        for container in containers {
            check_container(container, file, doc_offset, source, findings);
        }
    }

    if let Some(containers) = yaml_seq(pod_spec, "initContainers") {
        for container in containers {
            check_container(container, file, doc_offset, source, findings);
        }
    }
}

fn check_container(
    container: &Value,
    file: &Path,
    doc_offset: u32,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    let cname = yaml_str(container, "name").unwrap_or_else(|| "<unnamed>".to_string());

    if let Some(image) = yaml_str(container, "image") {
        check_image(&image, &cname, file, doc_offset, source, findings);
    }

    let sec_ctx = &container["securityContext"];

    if yaml_bool(sec_ctx, "privileged") == Some(true) {
        let ln = find_line_of_bounded(source, "privileged: true", doc_offset, 200);
        findings.push(make_finding(
            file,
            ln,
            FindingKind::PrivilegedContainer,
            Severity::Critical,
            0.99,
            &format!("Container '{}' runs in privileged mode", cname),
            "Remove 'privileged: true' and use specific capabilities instead",
        ));
    }

    if yaml_u64(sec_ctx, "runAsUser") == Some(0) {
        let ln = find_line_of_bounded(source, "runAsUser: 0", doc_offset, 200);
        findings.push(make_finding(
            file,
            ln,
            FindingKind::RunningAsRoot,
            Severity::High,
            0.95,
            &format!("Container '{}' runs as root (UID 0)", cname),
            "Set runAsUser to a non-root UID (e.g., 1000) and runAsNonRoot: true",
        ));
    }

    if yaml_bool(sec_ctx, "runAsNonRoot") != Some(true) {
        let ln = find_line_of_bounded(source, &format!("name: {}", cname), doc_offset, 200);
        findings.push(make_finding(
            file,
            ln,
            FindingKind::RunningAsRoot,
            Severity::Medium,
            0.80,
            &format!(
                "Container '{}' does not set runAsNonRoot: true - may run as root",
                cname
            ),
            "Add securityContext.runAsNonRoot: true",
        ));
    }

    if yaml_bool(sec_ctx, "readOnlyRootFilesystem") != Some(true) {
        let ln = find_line_of_bounded(source, &format!("name: {}", cname), doc_offset, 200);
        findings.push(make_finding(
            file,
            ln,
            FindingKind::MissingResourceLimits,
            Severity::Medium,
            0.75,
            &format!(
                "Container '{}' does not set readOnlyRootFilesystem: true",
                cname
            ),
            "Set securityContext.readOnlyRootFilesystem: true and mount writable paths as emptyDir",
        ));
    }

    let ape = yaml_bool(sec_ctx, "allowPrivilegeEscalation");
    if ape == Some(true) || ape.is_none() {
        let ln = if ape == Some(true) {
            find_line_of_bounded(source, "allowPrivilegeEscalation:", doc_offset, 200)
        } else {
            find_line_of_bounded(source, &format!("name: {}", cname), doc_offset, 200)
        };
        findings.push(make_finding(
            file,
            ln,
            FindingKind::PrivilegedContainer,
            Severity::Medium,
            0.80,
            &format!(
                "Container '{}' {} - processes can gain more privileges than parent",
                cname,
                if ape == Some(true) {
                    "has allowPrivilegeEscalation: true"
                } else {
                    "does not set allowPrivilegeEscalation: false"
                }
            ),
            "Set securityContext.allowPrivilegeEscalation: false",
        ));
    }

    let has_drop_all = sec_ctx
        .get("capabilities")
        .and_then(|c| c.get("drop"))
        .and_then(|d| d.as_sequence())
        .map(|seq| {
            seq.iter().any(|v| {
                v.as_str()
                    .map(|s| s.eq_ignore_ascii_case("ALL"))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);

    if !has_drop_all {
        let ln = find_line_of_bounded(source, &format!("name: {}", cname), doc_offset, 200);
        findings.push(make_finding(
            file,
            ln,
            FindingKind::PrivilegedContainer,
            Severity::Medium,
            0.80,
            &format!(
                "Container '{}' does not drop all capabilities",
                cname
            ),
            "Add securityContext.capabilities.drop: [\"ALL\"] and add back only required capabilities",
        ));
    }

    let resources = &container["resources"];

    if resources.get("limits").is_none() || resources["limits"].is_null() {
        let ln = find_line_of_bounded(source, &format!("name: {}", cname), doc_offset, 200);
        findings.push(make_finding(
            file,
            ln,
            FindingKind::MissingResourceLimits,
            Severity::Medium,
            0.95,
            &format!("Container '{}' has no resource limits defined", cname),
            "Add resources.limits with cpu and memory constraints",
        ));
    }

    if resources.get("requests").is_none() || resources["requests"].is_null() {
        let ln = find_line_of_bounded(source, &format!("name: {}", cname), doc_offset, 200);
        findings.push(make_finding(
            file,
            ln,
            FindingKind::MissingResourceLimits,
            Severity::Low,
            0.90,
            &format!("Container '{}' has no resource requests defined", cname),
            "Add resources.requests for proper scheduling and QoS class",
        ));
    }

    if container.get("livenessProbe").is_none() || container["livenessProbe"].is_null() {
        let ln = find_line_of_bounded(source, &format!("name: {}", cname), doc_offset, 200);
        findings.push(make_finding(
            file,
            ln,
            FindingKind::MissingHealthProbes,
            Severity::Medium,
            0.90,
            &format!("Container '{}' is missing a liveness probe", cname),
            "Add a livenessProbe to enable automatic restart on failure",
        ));
    }

    if container.get("readinessProbe").is_none() || container["readinessProbe"].is_null() {
        let ln = find_line_of_bounded(source, &format!("name: {}", cname), doc_offset, 200);
        findings.push(make_finding(
            file,
            ln,
            FindingKind::MissingHealthProbes,
            Severity::Medium,
            0.90,
            &format!("Container '{}' is missing a readiness probe", cname),
            "Add a readinessProbe to prevent traffic before the container is ready",
        ));
    }

    if let Some(env_vars) = yaml_seq(container, "env") {
        check_env_vars(env_vars, file, doc_offset, source, findings);
    }
}

fn check_image(
    image: &str,
    container_name: &str,
    file: &Path,
    doc_offset: u32,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    let ln = find_line_of_bounded(source, image, doc_offset, 200);

    if image.ends_with(":latest") {
        findings.push(make_finding(
            file,
            ln,
            FindingKind::UnpinnedImage,
            Severity::Medium,
            0.95,
            &format!(
                "Container '{}' uses image '{}' with :latest tag",
                container_name, image
            ),
            "Pin image to a specific version tag or SHA256 digest",
        ));
    } else if !image.contains(':') {
        findings.push(make_finding(
            file,
            ln,
            FindingKind::UnpinnedImage,
            Severity::Medium,
            0.95,
            &format!(
                "Container '{}' uses image '{}' with no tag (defaults to :latest)",
                container_name, image
            ),
            "Pin image to a specific version tag or SHA256 digest",
        ));
    }

    // Pre-release version (v0.x.y)
    let prerelease_re = Regex::new(r":v?0\.\d+\.\d+").expect("valid regex");
    if prerelease_re.is_match(image) {
        findings.push(make_finding(
            file,
            ln,
            FindingKind::UnpinnedImage,
            Severity::Low,
            0.70,
            &format!(
                "Container '{}' uses pre-release image version '{}'",
                container_name, image
            ),
            "Consider using a stable release (v1.0.0+) for production workloads",
        ));
    }
}

fn check_env_vars(
    env_vars: &[Value],
    file: &Path,
    doc_offset: u32,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    let secret_name_re = Regex::new(r"(?i)(password|secret|api_key|token|credential|private_key)")
        .expect("valid regex");
    let tls_disabled_re =
        Regex::new(r"(?i)^(ssl_enabled|tls_enabled|tls_verify|ssl_verify)$").expect("valid regex");

    for env in env_vars {
        let env_name = yaml_str(env, "name").unwrap_or_default();
        let env_value = yaml_str(env, "value").unwrap_or_default();

        if tls_disabled_re.is_match(&env_name) {
            let lower = env_value.to_lowercase();
            if lower == "false" || lower == "0" || lower == "no" || lower == "off" {
                let ln = find_line_of_bounded(source, &env_name, doc_offset, 200);
                findings.push(make_finding(
                    file,
                    ln,
                    FindingKind::UnencryptedStorage,
                    Severity::High,
                    0.90,
                    &format!("TLS/SSL is disabled via env var {}={}", env_name, env_value),
                    "Enable TLS/SSL for encrypted communication",
                ));
            }
        }

        // Skip if value comes from a secretKeyRef / configMapKeyRef
        if env.get("valueFrom").is_some() {
            continue;
        }

        if secret_name_re.is_match(&env_name) && !env_value.is_empty() {
            let ln = find_line_of_bounded(source, &env_name, doc_offset, 200);
            findings.push(make_finding(
                file,
                ln,
                FindingKind::SecretInEnvVar,
                Severity::Critical,
                0.85,
                &format!(
                    "Secret-looking env var '{}' has a plaintext value",
                    env_name
                ),
                "Use a Kubernetes Secret with valueFrom.secretKeyRef instead of inline values",
            ));
        }
    }
}

fn check_ingress_tls(val: &Value, file: &Path, doc_offset: u32, findings: &mut Vec<Finding>) {
    let spec = &val["spec"];
    let name = yaml_nested_str(val, &["metadata", "name"]).unwrap_or_default();

    let tls = spec.get("tls");

    if tls.is_none() || tls == Some(&Value::Null) {
        findings.push(make_finding(
            file,
            doc_offset,
            FindingKind::UnencryptedStorage,
            Severity::Medium,
            0.90,
            &format!(
                "Ingress '{}' has no TLS configuration - traffic is unencrypted",
                name
            ),
            "Add spec.tls with a certificate secret for HTTPS termination",
        ));
        return;
    }

    if let Some(tls_seq) = tls.and_then(|t| t.as_sequence()) {
        if tls_seq.is_empty() {
            findings.push(make_finding(
                file,
                doc_offset,
                FindingKind::UnencryptedStorage,
                Severity::Medium,
                0.90,
                &format!(
                    "Ingress '{}' has an empty TLS section - no hosts covered",
                    name
                ),
                "Add TLS entries with hosts and secretName for HTTPS",
            ));
        }
    }
}

fn check_network_policy(val: &Value, file: &Path, doc_offset: u32, findings: &mut Vec<Finding>) {
    let spec = &val["spec"];
    let name = yaml_nested_str(val, &["metadata", "name"]).unwrap_or_default();

    // Empty podSelector AND empty/missing policyTypes -> effectively no-op
    let pod_selector = &spec["podSelector"];
    let policy_types = spec.get("policyTypes");

    let empty_selector = pod_selector.is_null()
        || pod_selector
            .as_mapping()
            .map(|m| m.is_empty())
            .unwrap_or(true);
    let empty_types = policy_types.is_none()
        || policy_types
            .and_then(|t| t.as_sequence())
            .map(|s| s.is_empty())
            .unwrap_or(true);

    if empty_selector && empty_types {
        findings.push(make_finding(
            file,
            doc_offset,
            FindingKind::NoNetworkPolicy,
            Severity::High,
            0.85,
            &format!(
                "NetworkPolicy '{}' has empty podSelector and no policyTypes - effectively a no-op",
                name
            ),
            "Specify policyTypes (Ingress, Egress) to actually enforce network isolation",
        ));
    }

    check_cidr_blocks(
        &spec["ingress"],
        "ingress",
        &name,
        file,
        doc_offset,
        findings,
    );
    check_cidr_blocks(&spec["egress"], "egress", &name, file, doc_offset, findings);
}

fn check_cidr_blocks(
    rules: &Value,
    direction: &str,
    policy_name: &str,
    file: &Path,
    doc_offset: u32,
    findings: &mut Vec<Finding>,
) {
    if let Some(rule_list) = rules.as_sequence() {
        for rule in rule_list {
            // ingress: from/egress: to
            let peers_key = if direction == "ingress" { "from" } else { "to" };
            if let Some(peers) = rule.get(peers_key).and_then(|p| p.as_sequence()) {
                for peer in peers {
                    if let Some(cidr) = peer
                        .get("ipBlock")
                        .and_then(|b| b.get("cidr"))
                        .and_then(|c| c.as_str())
                    {
                        if cidr == "0.0.0.0/0" || cidr == "::/0" {
                            findings.push(make_finding(
                                file,
                                doc_offset,
                                FindingKind::OpenSecurityGroup,
                                Severity::Critical,
                                0.95,
                                &format!(
                                    "NetworkPolicy '{}' allows {} from/to {} (entire internet)",
                                    policy_name, direction, cidr
                                ),
                                "Restrict CIDR blocks to specific IP ranges",
                            ));
                        }
                    }
                }
            }
        }
    }
}

fn check_rbac(val: &Value, kind: &str, file: &Path, doc_offset: u32, findings: &mut Vec<Finding>) {
    let name = yaml_nested_str(val, &["metadata", "name"]).unwrap_or_default();

    if let Some(rules) = yaml_seq(val, "rules") {
        for rule in rules {
            let api_groups = yaml_str_list(rule, "apiGroups");
            let resources = yaml_str_list(rule, "resources");
            let verbs = yaml_str_list(rule, "verbs");

            let wildcard_groups = api_groups.iter().any(|s| s == "*");
            let wildcard_resources = resources.iter().any(|s| s == "*");
            let wildcard_verbs = verbs.iter().any(|s| s == "*");

            if wildcard_groups && wildcard_resources && wildcard_verbs {
                findings.push(make_finding(
                    file,
                    doc_offset,
                    FindingKind::IamOverPermission,
                    Severity::High,
                    0.95,
                    &format!(
                        "{} '{}' grants wildcard access to all API groups, resources, and verbs",
                        kind, name
                    ),
                    "Apply least privilege - scope to specific API groups, resources, and verbs",
                ));
            } else if wildcard_groups && wildcard_resources {
                findings.push(make_finding(
                    file,
                    doc_offset,
                    FindingKind::IamOverPermission,
                    Severity::High,
                    0.90,
                    &format!(
                        "{} '{}' grants access to all API groups and resources",
                        kind, name
                    ),
                    "Scope apiGroups and resources to only what is needed",
                ));
            }
        }
    }
}

fn check_service_account(val: &Value, file: &Path, doc_offset: u32, findings: &mut Vec<Finding>) {
    let name = yaml_nested_str(val, &["metadata", "name"]).unwrap_or_default();

    // automountServiceAccountToken defaults to true if missing
    let auto_mount = yaml_bool(val, "automountServiceAccountToken");
    if auto_mount.is_none() || auto_mount == Some(true) {
        findings.push(make_finding(
            file,
            doc_offset,
            FindingKind::IamOverPermission,
            Severity::Low,
            0.70,
            &format!(
                "ServiceAccount '{}' has automountServiceAccountToken {} - API token mounted into all pods using this SA",
                name,
                if auto_mount.is_none() { "defaulting to true" } else { "set to true" }
            ),
            "Set automountServiceAccountToken: false and override per-pod where needed",
        ));
    }
}

fn check_namespace(val: &Value, file: &Path, doc_offset: u32, findings: &mut Vec<Finding>) {
    let name = yaml_nested_str(val, &["metadata", "name"]).unwrap_or_default();
    let labels = &val["metadata"]["labels"];

    let has_pss_enforce = labels
        .get("pod-security.kubernetes.io/enforce")
        .and_then(|v| v.as_str());

    if has_pss_enforce.is_none() {
        findings.push(make_finding(
            file,
            doc_offset,
            FindingKind::Soc2Violation,
            Severity::Medium,
            0.85,
            &format!(
                "Namespace '{}' is missing pod-security.kubernetes.io/enforce label",
                name
            ),
            "Add Pod Security Standards labels (enforce: baseline or restricted)",
        ));
    } else if let Some(level) = has_pss_enforce {
        // privileged enforcement is essentially no enforcement
        if level == "privileged" {
            findings.push(make_finding(
                file,
                doc_offset,
                FindingKind::Soc2Violation,
                Severity::Medium,
                0.85,
                &format!(
                    "Namespace '{}' uses pod-security.kubernetes.io/enforce: privileged - no security restrictions",
                    name
                ),
                "Set enforce level to 'baseline' or 'restricted' for production namespaces",
            ));
        }

        let enforce_level = pss_level_rank(level);
        if let Some(audit) = labels
            .get("pod-security.kubernetes.io/audit")
            .and_then(|v| v.as_str())
        {
            let audit_level = pss_level_rank(audit);
            if enforce_level < audit_level {
                findings.push(make_finding(
                    file,
                    doc_offset,
                    FindingKind::Soc2Violation,
                    Severity::Low,
                    0.75,
                    &format!(
                        "Namespace '{}' enforce level ('{}') is lower than audit level ('{}') - violations will be logged but not blocked",
                        name, level, audit
                    ),
                    "Set enforce level at least as strict as audit/warn levels",
                ));
            }
        }
    }
}

/// Rank PSS levels: privileged=0, baseline=1, restricted=2
fn pss_level_rank(level: &str) -> u8 {
    match level {
        "restricted" => 2,
        "baseline" => 1,
        _ => 0, // privileged or unknown
    }
}

fn check_secrets(val: &Value, file: &Path, doc_offset: u32, findings: &mut Vec<Finding>) {
    let name = yaml_nested_str(val, &["metadata", "name"]).unwrap_or_default();

    // stringData with actual values (not in a SealedSecret)
    if let Some(string_data) = val.get("stringData") {
        if let Some(map) = string_data.as_mapping() {
            if !map.is_empty() {
                findings.push(make_finding(
                    file,
                    doc_offset,
                    FindingKind::SecretInEnvVar,
                    Severity::High,
                    0.90,
                    &format!(
                        "Secret '{}' contains plaintext values in stringData - these should not be committed to version control",
                        name
                    ),
                    "Use SealedSecrets, ExternalSecrets, or Vault to manage secret values",
                ));
            }
        }
    }

    // data with values (base64 encoded but still in git)
    if let Some(data) = val.get("data") {
        if let Some(map) = data.as_mapping() {
            if !map.is_empty() {
                findings.push(make_finding(
                    file,
                    doc_offset,
                    FindingKind::SecretInEnvVar,
                    Severity::High,
                    0.85,
                    &format!(
                        "Secret '{}' contains base64-encoded values in data - base64 is not encryption",
                        name
                    ),
                    "Use SealedSecrets, ExternalSecrets, or Vault instead of storing secrets in manifests",
                ));
            }
        }
    }
}

fn check_sealed_secret_placeholders(
    val: &Value,
    file: &Path,
    doc_offset: u32,
    findings: &mut Vec<Finding>,
) {
    let name = yaml_nested_str(val, &["metadata", "name"]).unwrap_or_default();
    let placeholder_re = Regex::new(
        r"(?i)(REPLACE_WITH|GENERATE_BEFORE|CHANGEME|TODO|placeholder|xxx+|INSERT_HERE|FILL_IN)",
    )
    .expect("valid regex");

    if let Some(enc_data) = val.get("spec").and_then(|s| s.get("encryptedData")) {
        if let Some(map) = enc_data.as_mapping() {
            for (key, value) in map {
                if let Some(val_str) = value.as_str() {
                    if placeholder_re.is_match(val_str) {
                        let key_name = key.as_str().unwrap_or("<unknown>");
                        findings.push(make_finding(
                            file,
                            doc_offset,
                            FindingKind::HardcodedCredential,
                            Severity::Critical,
                            0.95,
                            &format!(
                                "SealedSecret '{}' has placeholder value for key '{}': '{}'",
                                name, key_name, val_str
                            ),
                            "Replace placeholder with actual kubeseal-encrypted value before deploying",
                        ));
                    }
                }
            }
        }
    }
}

fn check_policy_enforcement(
    val: &Value,
    file: &Path,
    doc_offset: u32,
    findings: &mut Vec<Finding>,
) {
    let name = yaml_nested_str(val, &["metadata", "name"]).unwrap_or_default();

    if let Some(action) = yaml_nested_str(val, &["spec", "validationFailureAction"]) {
        let action_lower = action.to_lowercase();
        if action_lower == "audit" {
            findings.push(make_finding(
                file,
                doc_offset,
                FindingKind::Soc2Violation,
                Severity::High,
                0.90,
                &format!(
                    "Policy '{}' has validationFailureAction: Audit - violations are logged but not blocked",
                    name
                ),
                "Set validationFailureAction: Enforce for production clusters",
            ));
        }
    }
}

fn check_line_patterns(source: &str, file: &Path, findings: &mut Vec<Finding>) {
    let todo_re = Regex::new(r"#\s*(TODO|FIXME|HACK|XXX)\b").expect("valid regex");
    let comment_block_re = Regex::new(r"^\s*#\s*(.*\S.*)$").expect("valid regex");
    let placeholder_re = Regex::new(
        r"(?i)\b(REPLACE_WITH\w*|GENERATE_BEFORE\w*|CHANGEME|placeholder|INSERT_HERE|FILL_IN)\b",
    )
    .expect("valid regex");
    let yaml_key_re = Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_.-]*:").expect("valid regex");

    let lines: Vec<&str> = source.lines().collect();
    let mut _consecutive_comments = 0u32;

    for (idx, line) in lines.iter().enumerate() {
        let line_num = (idx + 1) as u32;

        if todo_re.is_match(line) {
            findings.push(make_finding(
                file,
                line_num,
                FindingKind::ConventionViolation,
                Severity::Low,
                0.90,
                &format!(
                    "TODO/FIXME comment in infrastructure manifest: {}",
                    line.trim()
                ),
                "Resolve TODO items before deploying to production",
            ));
        }

        if placeholder_re.is_match(line) {
            // Distinct id so this can't dedup against the structured
            // SealedSecret placeholder finding.
            findings.push(make_finding_with_id(
                &format!("k8s-placeholder-{}:{}", file.display(), line_num),
                file,
                line_num,
                FindingKind::HardcodedCredential,
                Severity::Critical,
                0.90,
                &format!("Placeholder value found: {}", line.trim()),
                "Replace placeholder with actual value or use ExternalSecrets/SealedSecrets",
            ));
        }

        // Commented-out YAML configuration (heuristic: line starts with `# ` followed by valid YAML key)
        if comment_block_re.is_match(line) {
            let trimmed = line.trim().trim_start_matches('#').trim();
            if trimmed.contains(": ")
                && !trimmed.starts_with("TODO")
                && !trimmed.starts_with("FIXME")
                && !trimmed.starts_with("HACK")
                && !trimmed.starts_with("NOTE")
                && !trimmed.starts_with("XXX")
                && !trimmed.starts_with("http")
                && !trimmed.starts_with("See ")
                && !trimmed.starts_with("This ")
                && !trimmed.starts_with("The ")
                && !trimmed.starts_with("For ")
                && !trimmed.starts_with("If ")
                && !trimmed.starts_with("When ")
                && !trimmed.starts_with("IMPORTANT")
                && !trimmed.starts_with("Before ")
                && !trimmed.starts_with("After ")
                && !trimmed.starts_with("Replace ")
                && !trimmed.starts_with("Create ")
                && !trimmed.starts_with("Initialize ")
            {
                if yaml_key_re.is_match(trimmed) {
                    _consecutive_comments += 1;
                    // Only blocks of 2+ consecutive lines, to skip inline
                    // explanatory comments.
                    if _consecutive_comments >= 2 {
                        // Only emit once per block start
                        if _consecutive_comments == 2 {
                            findings.push(make_finding(
                                file,
                                line_num - 1,
                                FindingKind::ConventionViolation,
                                Severity::Info,
                                0.60,
                                "Commented-out configuration block detected",
                                "Remove commented-out configuration or restore it - version control tracks history",
                            ));
                        }
                    }
                } else {
                    _consecutive_comments = 0;
                }
            } else {
                _consecutive_comments = 0;
            }
        } else {
            _consecutive_comments = 0;
        }
    }
}

fn make_finding(
    file: &Path,
    line: u32,
    kind: FindingKind,
    severity: Severity,
    confidence: f32,
    message: &str,
    suggestion: &str,
) -> Finding {
    let id = format!("k8s-{:?}-{}:{}", kind, file.display(), line);
    Finding {
        id,
        kind,
        severity,
        confidence,
        file: file.to_path_buf(),
        line_start: line,
        line_end: line,
        symbol: None,
        message: message.to_string(),
        suggestion: suggestion.to_string(),
        auto_fixable: false,
        related: Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn make_finding_with_id(
    id: &str,
    file: &Path,
    line: u32,
    kind: FindingKind,
    severity: Severity,
    confidence: f32,
    message: &str,
    suggestion: &str,
) -> Finding {
    Finding {
        id: id.to_string(),
        kind,
        severity,
        confidence,
        file: file.to_path_buf(),
        line_start: line,
        line_end: line,
        symbol: None,
        message: message.to_string(),
        suggestion: suggestion.to_string(),
        auto_fixable: false,
        related: Vec::new(),
    }
}

fn create_resource_symbol(
    ir: &mut Ir,
    path: &Path,
    kind: &str,
    name: &str,
    line_start: u32,
    line_end: u32,
) -> SymbolId {
    let fq = format!("k8s::{}/{}", kind, name);
    // Namespace the id by file path: a kustomize base and overlay defining the
    // same Deployment name must not collide when partial IRs are merged.
    let id = SymbolId(crate::stable_hash(&format!("{}::{}", fq, path.display())));

    ir.symbols.insert(
        id,
        Symbol {
            id,
            name: name.to_string(),
            fully_qualified: fq,
            kind: SymbolKind::Class,
            visibility: Visibility::Public,
            file: path.to_path_buf(),
            line_start,
            line_end,
            col_start: 0,
            col_end: 0,
            language: Language::Kubernetes,
            parent: None,
            hash: 0,
            normalized_hash: 0,
            flow_hash: 0,
            param_count: 0,
            is_entry_point: true,
            doc_comment: Some(format!("Kubernetes {} resource", kind)),
        },
    );
    ir.metadata.total_symbols += 1;

    id
}
