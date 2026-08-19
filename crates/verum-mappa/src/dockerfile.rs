use std::path::Path;

use anyhow::Result;
use regex::Regex;

use verum_nucleus::{
    FileId, FileInfo, Finding, FindingKind, Ir, Language, Severity, Symbol, SymbolId, SymbolKind,
    Visibility,
};

/// Parse a Dockerfile into IR. FROM stages become symbols; the scan covers
/// image pinning, root user, secrets, and build hygiene.
pub fn parse_file(path: &Path) -> Result<Ir> {
    let source = std::fs::read_to_string(path)?;
    let line_count = source.lines().count() as u32;
    let size_bytes = std::fs::metadata(path)?.len();

    let mut ir = Ir::new();
    let mut findings = Vec::new();
    let mut symbol_ids = Vec::new();

    let file_id = FileId(crate::stable_hash(path.to_string_lossy().as_ref()));

    // Skip any leading FROM options (e.g. `--platform=$TARGETOS/$TARGETARCH`)
    // before capturing the actual image reference.
    let from_re = Regex::new(r"(?i)^FROM\s+(?:--\S+\s+)*(\S+)(?:\s+[Aa][Ss]\s+(\S+))?").unwrap();
    let user_re = Regex::new(r"(?i)^USER\s+(\S+)").unwrap();
    let env_secret_re =
        Regex::new(r#"(?i)^ENV\s+\S*(?:password|secret|api_key|token|credential)\S*\s*=?\s*\S+"#)
            .unwrap();
    let arg_secret_re =
        Regex::new(r#"(?i)^ARG\s+\S*(?:password|secret|api_key|token|credential)\S*\s*=\s*\S+"#)
            .unwrap();
    let copy_env_re = Regex::new(r"(?i)^(?:COPY|ADD)\s+.*\.env\b").unwrap();
    let copy_cred_re =
        Regex::new(r"(?i)^(?:COPY|ADD)\s+.*(?:credentials|\.pem|\.key|id_rsa|\.pfx|\.p12)\b")
            .unwrap();
    let copy_all_re = Regex::new(r"(?i)^COPY\s+\.\s+\.").unwrap();
    let curl_pipe_re = Regex::new(r"(?i)(?:curl|wget)\s+.*\|\s*(?:sh|bash|zsh)").unwrap();
    let apt_get_install_re = Regex::new(r"(?i)apt-get\s+install").unwrap();
    let no_install_recommends_re = Regex::new(r"--no-install-recommends").unwrap();
    let run_sudo_re = Regex::new(r"(?i)^RUN\s+.*\bsudo\b").unwrap();
    let add_re = Regex::new(r"(?i)^ADD\s+").unwrap();
    let add_url_re = Regex::new(r"(?i)^ADD\s+https?://").unwrap();
    let volume_re = Regex::new(r"(?i)^VOLUME\s+").unwrap();
    let expose_re = Regex::new(r"(?i)^EXPOSE\s+(.*)").unwrap();
    let healthcheck_re = Regex::new(r"(?i)^HEALTHCHECK\s+").unwrap();
    let cmd_re = Regex::new(r"(?i)^CMD\s+").unwrap();
    let entrypoint_re = Regex::new(r"(?i)^ENTRYPOINT\s+").unwrap();
    let label_re = Regex::new(r"(?i)^LABEL\s+").unwrap();
    let run_re = Regex::new(r"(?i)^RUN\s+").unwrap();
    let build_arg_comment_re =
        Regex::new(r"(?i)#.*--build-arg\s+\S*(?:password|secret|api_key|token|credential)")
            .unwrap();

    let mut has_user_directive = false;
    let mut last_user_is_root = false;
    let mut last_user_line: u32 = 0;
    let mut has_healthcheck = false;
    let mut cmd_count = 0u32;
    let mut entrypoint_count = 0u32;
    let mut has_label = false;
    let mut from_count = 0u32;

    let logical_lines = join_continuation_lines(&source);

    for (line_num, trimmed) in &logical_lines {
        let line_num = *line_num;

        if trimmed.is_empty() || trimmed.starts_with('#') {
            // comments can still hint at secrets passed via --build-arg
            if build_arg_comment_re.is_match(trimmed) {
                findings.push(make_finding(
                    path,
                    line_num,
                    FindingKind::HardcodedCredential,
                    Severity::Medium,
                    0.70,
                    "Comment suggests passing secrets via --build-arg",
                    "Use Docker BuildKit secrets (--mount=type=secret) instead of --build-arg for sensitive values",
                ));
            }
            continue;
        }

        if let Some(caps) = from_re.captures(trimmed) {
            from_count += 1;
            let image = caps[1].to_string();
            let stage_name = caps
                .get(2)
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| format!("stage-{}", from_count));

            let fq = format!("docker::FROM/{}", stage_name);
            // Namespace the id by file path: unnamed stages are "stage-1",
            // "stage-2", ... in every Dockerfile, so without the path every
            // pair of single-stage Dockerfiles would collide on merge.
            let id = SymbolId(crate::stable_hash(&format!("{}::{}", fq, path.display())));
            ir.symbols.insert(
                id,
                Symbol {
                    id,
                    name: stage_name,
                    fully_qualified: fq,
                    kind: SymbolKind::Class,
                    visibility: Visibility::Public,
                    file: path.to_path_buf(),
                    line_start: line_num,
                    line_end: line_num,
                    col_start: 0,
                    col_end: 0,
                    language: Language::Docker,
                    parent: None,
                    hash: 0,
                    normalized_hash: 0,
                    flow_hash: 0,
                    param_count: 0,
                    is_entry_point: true,
                    doc_comment: Some(format!("Docker stage from {}", image)),
                },
            );
            ir.metadata.total_symbols += 1;
            symbol_ids.push(id);

            // scratch and FROM <earlier stage> aren't registry images
            if image != "scratch" && !is_build_stage_ref(&image, &ir) {
                if image.contains("@sha256:") {
                    // Pinned by digest -- good
                } else if !image.contains(':') || image.ends_with(":latest") {
                    findings.push(make_finding(
                        path,
                        line_num,
                        FindingKind::UnpinnedImage,
                        Severity::High,
                        0.95,
                        &format!("Base image '{}' uses :latest or no tag", image),
                        "Pin to a specific version tag (e.g. node:20.11-alpine) or SHA256 digest",
                    ));
                } else {
                    findings.push(make_finding(
                        path,
                        line_num,
                        FindingKind::UnpinnedImage,
                        Severity::Medium,
                        0.85,
                        &format!("Base image '{}' is not pinned to a SHA256 digest", image),
                        "Pin with @sha256: digest for reproducible builds",
                    ));
                }
            }
        }

        if let Some(caps) = user_re.captures(trimmed) {
            has_user_directive = true;
            let user = &caps[1];
            let is_root = user == "root" || user == "0";
            last_user_is_root = is_root;
            last_user_line = line_num;

            if is_root {
                // whether this was the *final* USER is judged after the scan
            }
        }

        if env_secret_re.is_match(trimmed) {
            findings.push(make_finding(
                path,
                line_num,
                FindingKind::HardcodedCredential,
                Severity::Critical,
                0.85,
                "Potential secret hardcoded in ENV directive",
                "Use runtime environment variables, Docker secrets, or a secrets manager instead",
            ));
        }

        if arg_secret_re.is_match(trimmed) {
            findings.push(make_finding(
                path,
                line_num,
                FindingKind::HardcodedCredential,
                Severity::High,
                0.85,
                "ARG with default value containing potential secret",
                "Remove default value and pass via --build-arg or BuildKit secrets",
            ));
        }

        if copy_env_re.is_match(trimmed) || copy_cred_re.is_match(trimmed) {
            findings.push(make_finding(
                path,
                line_num,
                FindingKind::HardcodedCredential,
                Severity::High,
                0.85,
                "COPY/ADD of sensitive file (.env, credentials, keys) into image",
                "Use Docker secrets or mount at runtime instead of baking into the image",
            ));
        }

        if trimmed.starts_with('#') && build_arg_comment_re.is_match(trimmed) {
            // already handled in the comment branch above
        }

        if run_re.is_match(trimmed) && curl_pipe_re.is_match(trimmed) {
            findings.push(make_finding(
                path,
                line_num,
                FindingKind::EvalUsage,
                Severity::Critical,
                0.95,
                "Piping curl/wget output directly to shell is a remote code execution risk",
                "Download the script first, verify its checksum, then execute it",
            ));
        }

        if run_re.is_match(trimmed) && apt_get_install_re.is_match(trimmed) {
            if !no_install_recommends_re.is_match(trimmed) {
                findings.push(make_finding(
                    path,
                    line_num,
                    FindingKind::ConventionViolation,
                    Severity::Low,
                    0.80,
                    "apt-get install without --no-install-recommends increases image size",
                    "Add --no-install-recommends to avoid pulling unnecessary packages",
                ));
            }
            // packages without =version aren't pinned
            let after_install = trimmed.split("install").nth(1).unwrap_or("");
            let packages: Vec<&str> = after_install
                .split_whitespace()
                .filter(|w| {
                    !w.starts_with('-') && !w.starts_with('\\') && !w.is_empty() && *w != "&&"
                })
                .collect();
            let unpinned: Vec<&&str> = packages.iter().filter(|p| !p.contains('=')).collect();
            if !unpinned.is_empty() {
                findings.push(make_finding(
                    path,
                    line_num,
                    FindingKind::UnpinnedImage,
                    Severity::Low,
                    0.70,
                    &format!(
                        "apt-get install without version pinning for: {}",
                        unpinned.iter().map(|p| **p).collect::<Vec<_>>().join(", ")
                    ),
                    "Pin package versions (e.g. curl=7.88.1-10+deb12u5) for reproducible builds",
                ));
            }
        }

        if run_sudo_re.is_match(trimmed) {
            findings.push(make_finding(
                path,
                line_num,
                FindingKind::RunningAsRoot,
                Severity::Medium,
                0.85,
                "RUN command uses sudo, indicating privilege escalation in container",
                "Run as root during build if needed, then switch to non-root USER for runtime",
            ));
        }

        if add_re.is_match(trimmed) && !from_re.is_match(trimmed) {
            if add_url_re.is_match(trimmed) {
                findings.push(make_finding(
                    path,
                    line_num,
                    FindingKind::EvalUsage,
                    Severity::High,
                    0.90,
                    "ADD from remote URL downloads and extracts content without verification",
                    "Use RUN curl/wget with checksum verification instead",
                ));
            } else {
                findings.push(make_finding(
                    path,
                    line_num,
                    FindingKind::ConventionViolation,
                    Severity::Medium,
                    0.80,
                    "ADD used instead of COPY - ADD can auto-extract tarballs and fetch URLs",
                    "Use COPY unless you specifically need ADD's extraction behavior",
                ));
            }
        }

        if copy_all_re.is_match(trimmed) {
            let dockerignore_exists = path
                .parent()
                .map(|p| p.join(".dockerignore").exists())
                .unwrap_or(false);
            if !dockerignore_exists {
                findings.push(make_finding(
                    path,
                    line_num,
                    FindingKind::ConventionViolation,
                    Severity::Medium,
                    0.80,
                    "COPY . . without a .dockerignore file may include sensitive or unnecessary files",
                    "Create a .dockerignore file to exclude .git, .env, node_modules, etc.",
                ));
            }
        }

        if volume_re.is_match(trimmed) {
            findings.push(make_finding(
                path,
                line_num,
                FindingKind::ConventionViolation,
                Severity::Low,
                0.70,
                "VOLUME directive creates anonymous volumes that can't be controlled at runtime",
                "Document volume mounts in docker-compose.yml or deployment configs instead",
            ));
        }

        if let Some(caps) = expose_re.captures(trimmed) {
            let ports_str = &caps[1];
            if ports_str
                .split_whitespace()
                .any(|p| p == "22" || p.starts_with("22/"))
            {
                findings.push(make_finding(
                    path,
                    line_num,
                    FindingKind::OpenSecurityGroup,
                    Severity::Medium,
                    0.90,
                    "Container exposes SSH port 22 - containers should not run SSH daemons",
                    "Use docker exec or kubectl exec for debugging instead of SSH",
                ));
            }
        }

        if healthcheck_re.is_match(trimmed) {
            has_healthcheck = true;
        }

        if cmd_re.is_match(trimmed) && !trimmed.starts_with('#') {
            cmd_count += 1;
        }
        if entrypoint_re.is_match(trimmed) && !trimmed.starts_with('#') {
            entrypoint_count += 1;
        }

        if label_re.is_match(trimmed) {
            has_label = true;
        }

        if run_re.is_match(trimmed) {
            let run_body = trimmed
                .strip_prefix("RUN ")
                .or_else(|| trimmed.strip_prefix("run "))
                .unwrap_or(trimmed);
            if run_body.contains(';') && !run_body.contains("&&") {
                findings.push(make_finding(
                    path,
                    line_num,
                    FindingKind::ConventionViolation,
                    Severity::Low,
                    0.65,
                    "RUN with semicolons instead of && - commands after ; run even if earlier ones fail",
                    "Chain commands with && to fail fast and reduce image layers",
                ));
            }
        }
    }

    if !has_user_directive {
        findings.push(make_finding(
            path,
            1,
            FindingKind::RunningAsRoot,
            Severity::High,
            0.90,
            "No USER directive found - container will run as root by default",
            "Add a USER directive to run as a non-root user",
        ));
    } else if last_user_is_root {
        findings.push(make_finding(
            path,
            last_user_line,
            FindingKind::RunningAsRoot,
            Severity::Critical,
            0.95,
            "Final USER directive is root - container will run as root at runtime",
            "Add a non-root USER directive after any root-required build steps",
        ));
    }

    if !has_healthcheck {
        findings.push(make_finding(
            path,
            1,
            FindingKind::MissingHealthProbes,
            Severity::Low,
            0.75,
            "No HEALTHCHECK directive - orchestrators cannot detect unhealthy containers",
            "Add HEALTHCHECK CMD to enable health monitoring",
        ));
    }

    if cmd_count > 1 {
        findings.push(make_finding(
            path,
            1,
            FindingKind::ConventionViolation,
            Severity::Low,
            0.90,
            &format!(
                "Multiple CMD directives ({}) - only the last one takes effect",
                cmd_count
            ),
            "Remove all but the final CMD directive",
        ));
    }
    if entrypoint_count > 1 {
        findings.push(make_finding(
            path,
            1,
            FindingKind::ConventionViolation,
            Severity::Low,
            0.90,
            &format!(
                "Multiple ENTRYPOINT directives ({}) - only the last one takes effect",
                entrypoint_count
            ),
            "Remove all but the final ENTRYPOINT directive",
        ));
    }

    if !has_label {
        findings.push(make_finding(
            path,
            1,
            FindingKind::ConventionViolation,
            Severity::Low,
            0.60,
            "No LABEL directives for image metadata (maintainer, version, etc.)",
            "Add LABEL directives for maintainer, version, and description",
        ));
    }

    ir.files.insert(
        path.to_path_buf(),
        FileInfo {
            id: file_id,
            path: path.to_path_buf(),
            language: Language::Docker,
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

/// Join lines ending with backslash into logical lines.
/// Returns (original_line_number, joined_content) pairs.
fn join_continuation_lines(source: &str) -> Vec<(u32, String)> {
    let mut result = Vec::new();
    let lines: Vec<&str> = source.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let start_line = (i + 1) as u32;
        let mut combined = lines[i].trim().to_string();

        while combined.ends_with('\\') && i + 1 < lines.len() {
            combined.pop();
            i += 1;
            combined.push(' ');
            combined.push_str(lines[i].trim());
        }

        result.push((start_line, combined));
        i += 1;
    }

    result
}

/// Check if an image reference is a build stage name (used in multi-stage FROM).
fn is_build_stage_ref(image: &str, ir: &Ir) -> bool {
    // Stage names are plain identifiers; match against stages seen so far.
    ir.symbols
        .values()
        .any(|s| s.language == Language::Docker && s.kind == SymbolKind::Class && s.name == image)
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
        id: format!("docker-{:?}-{}:{}", kind, path.display(), line_num),
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

    fn parse_dockerfile_str(content: &str) -> Ir {
        let id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("verum_docker_test_{}", id));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Dockerfile");
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
    fn test_unpinned_latest() {
        let ir = parse_dockerfile_str("FROM node:latest\nCMD [\"node\"]\n");
        assert!(has_finding_severity(
            &ir,
            FindingKind::UnpinnedImage,
            Severity::High
        ));
    }

    #[test]
    fn test_unpinned_no_tag() {
        let ir = parse_dockerfile_str("FROM ubuntu\nCMD [\"bash\"]\n");
        assert!(has_finding_severity(
            &ir,
            FindingKind::UnpinnedImage,
            Severity::High
        ));
    }

    #[test]
    fn test_pinned_tag_no_digest() {
        let ir = parse_dockerfile_str("FROM node:20-alpine\nCMD [\"node\"]\n");
        assert!(has_finding_severity(
            &ir,
            FindingKind::UnpinnedImage,
            Severity::Medium
        ));
    }

    #[test]
    fn test_platform_flag_tagged_image_is_medium_not_high() {
        // A `--platform` flag must not be mistaken for the image reference; a
        // tagged (but un-digested) image is MEDIUM, not HIGH.
        let ir = parse_dockerfile_str(
            "FROM --platform=$TARGETOS/$TARGETARCH node:22.13-alpine AS build\nCMD [\"node\"]\n",
        );
        assert!(has_finding_severity(
            &ir,
            FindingKind::UnpinnedImage,
            Severity::Medium
        ));
        assert!(!has_finding_severity(
            &ir,
            FindingKind::UnpinnedImage,
            Severity::High
        ));
    }

    #[test]
    fn test_pinned_digest_ok() {
        let ir = parse_dockerfile_str(
            "FROM node@sha256:abcdef1234567890abcdef1234567890\nCMD [\"node\"]\n",
        );
        assert!(!has_finding(&ir, FindingKind::UnpinnedImage));
    }

    #[test]
    fn test_no_user_directive() {
        let ir = parse_dockerfile_str("FROM node:20\nCMD [\"node\"]\n");
        assert!(has_finding(&ir, FindingKind::RunningAsRoot));
    }

    #[test]
    fn test_last_user_root() {
        let ir = parse_dockerfile_str(
            "FROM node:20\nUSER appuser\nRUN something\nUSER root\nCMD [\"node\"]\n",
        );
        assert!(has_finding_severity(
            &ir,
            FindingKind::RunningAsRoot,
            Severity::Critical
        ));
    }

    #[test]
    fn test_user_nonroot_ok() {
        let ir = parse_dockerfile_str("FROM node:20\nUSER appuser\nCMD [\"node\"]\n");
        assert!(!has_finding(&ir, FindingKind::RunningAsRoot));
    }

    #[test]
    fn test_env_secret() {
        let ir = parse_dockerfile_str("FROM node:20\nENV API_KEY=sk-secret123\nCMD [\"node\"]\n");
        assert!(has_finding(&ir, FindingKind::HardcodedCredential));
    }

    #[test]
    fn test_curl_pipe() {
        let ir = parse_dockerfile_str(
            "FROM node:20\nRUN curl -fsSL https://example.com/install.sh | bash\nCMD [\"node\"]\n",
        );
        assert!(has_finding_severity(
            &ir,
            FindingKind::EvalUsage,
            Severity::Critical
        ));
    }

    #[test]
    fn test_add_instead_of_copy() {
        let ir = parse_dockerfile_str("FROM node:20\nADD . /app\nCMD [\"node\"]\n");
        assert!(has_finding_severity(
            &ir,
            FindingKind::ConventionViolation,
            Severity::Medium
        ));
    }

    #[test]
    fn test_add_url() {
        let ir = parse_dockerfile_str(
            "FROM node:20\nADD https://example.com/file.tar.gz /app/\nCMD [\"node\"]\n",
        );
        assert!(has_finding_severity(
            &ir,
            FindingKind::EvalUsage,
            Severity::High
        ));
    }

    #[test]
    fn test_expose_ssh() {
        let ir = parse_dockerfile_str("FROM node:20\nEXPOSE 22 80\nCMD [\"node\"]\n");
        assert!(has_finding_severity(
            &ir,
            FindingKind::OpenSecurityGroup,
            Severity::Medium
        ));
    }

    #[test]
    fn test_missing_healthcheck() {
        let ir = parse_dockerfile_str("FROM node:20\nCMD [\"node\"]\n");
        assert!(has_finding(&ir, FindingKind::MissingHealthProbes));
    }

    #[test]
    fn test_has_healthcheck() {
        let ir = parse_dockerfile_str(
            "FROM node:20\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\nCMD [\"node\"]\n",
        );
        assert!(!has_finding(&ir, FindingKind::MissingHealthProbes));
    }

    #[test]
    fn test_sudo_in_run() {
        let ir = parse_dockerfile_str("FROM node:20\nRUN sudo apt-get update\nCMD [\"node\"]\n");
        assert!(has_finding_severity(
            &ir,
            FindingKind::RunningAsRoot,
            Severity::Medium
        ));
    }

    #[test]
    fn test_multiple_cmd() {
        let ir = parse_dockerfile_str(
            "FROM node:20\nCMD [\"echo\", \"first\"]\nCMD [\"echo\", \"second\"]\n",
        );
        assert!(ir.infra_findings.iter().any(|f| {
            f.kind == FindingKind::ConventionViolation && f.message.contains("Multiple CMD")
        }));
    }
}
