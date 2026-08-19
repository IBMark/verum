mod graph;
mod map;
mod mcp;

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};

use verum_arbiter::AiHandoff;
use verum_faber::{Forge, ForgeConfig};
use verum_lumen::{Prism, PrismResult, Standard};
use verum_mappa::{Atlas, AtlasConfig};
use verum_nucleus::{
    DecisionRequest, Finding, FindingKind, Language, PipelineResult, Score, Severity,
};

#[derive(Parser)]
#[command(name = "verum", version)]
#[command(about = "Deterministic code analysis pipeline")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Map codebase into IR only
    Analyse { path: PathBuf },

    /// Map + analyse - findings, no changes
    Audit { path: PathBuf },

    /// Map + analyse, and report what dead code/duplicates would be removed (report-only)
    Clean {
        path: PathBuf,
        /// Report what would change without modifying any file
        #[arg(long)]
        dry_run: bool,
    },

    /// Full pipeline including AI QA
    Full {
        path: PathBuf,
        /// Report what would change without modifying any file
        #[arg(long)]
        dry_run: bool,
    },

    /// Check deploy gate
    Gate { path: PathBuf },

    /// Snapshot current findings to verum.baseline.json so `gate` only fails
    /// on findings introduced afterwards (ratchet mode for existing codebases)
    Baseline { path: PathBuf },

    /// Generate a report (markdown, json, sarif, or a self-contained html web UI)
    Report {
        path: PathBuf,
        /// Output format: markdown | json | sarif | html
        #[arg(long, default_value = "markdown")]
        format: String,
        /// Write the report to a file instead of stdout
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Map the system: module & symbol graphs, data flows, cycles, routes
    Map {
        path: PathBuf,
        /// Output format: text | json | html (interactive explorer)
        #[arg(long, default_value = "text")]
        format: String,
        /// Optimisation lens for the perf signals:
        /// latency | throughput | memory | cpu | realtime | all
        #[arg(long, default_value = "all")]
        profile: String,
        /// Write the map to a file instead of stdout
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Scaffold verum.standard.json
    Init { path: Option<PathBuf> },

    /// Serve the fact layer over MCP (stdio) so AI agents can query the call
    /// graph, dead code, duplicates, and audit results as tools
    Mcp { path: Option<PathBuf> },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Logs go to stderr: `verum mcp` speaks a protocol on stdout, and the
    // human commands print their own formatted output there.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    // `gate` and `full` return whether the deploy gate passed; a failed gate
    // exits non-zero so CI can rely on the exit code, not output parsing.
    let gate_ok = match cli.command {
        Commands::Analyse { path } => cmd_analyse(&path).await.map(|_| true),
        Commands::Audit { path } => cmd_audit(&path).await.map(|_| true),
        Commands::Clean { path, dry_run } => cmd_clean(&path, dry_run).await.map(|_| true),
        Commands::Full { path, dry_run } => cmd_full(&path, dry_run).await,
        Commands::Gate { path } => cmd_gate(&path).await,
        Commands::Baseline { path } => cmd_baseline(&path).await.map(|_| true),
        Commands::Report { path, format, out } => cmd_report(&path, &format, out.as_deref())
            .await
            .map(|_| true),
        Commands::Map {
            path,
            format,
            profile,
            out,
        } => map::cmd_map(&path, &format, &profile, out.as_deref())
            .await
            .map(|_| true),
        Commands::Init { path } => cmd_init(path.as_deref()).await.map(|_| true),
        Commands::Mcp { path } => {
            mcp::cmd_mcp(path.as_deref().unwrap_or(Path::new("."))).map(|_| true)
        }
    }?;

    if !gate_ok {
        std::process::exit(1);
    }
    Ok(())
}

fn detect_language(root: &Path) -> Language {
    use walkdir::WalkDir;

    let mut php_count = 0u32;
    let mut rs_count = 0u32;
    let mut js_count = 0u32;
    let mut ts_count = 0u32;
    let mut py_count = 0u32;
    let mut go_count = 0u32;

    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        let path_str = p.to_string_lossy();
        if path_str.contains("vendor/")
            || path_str.contains("node_modules/")
            || path_str.contains(".git/")
            || path_str.contains("/target/")
        {
            continue;
        }
        match p.extension().and_then(|e| e.to_str()) {
            Some("php") => php_count += 1,
            Some("rs") => rs_count += 1,
            Some("js" | "jsx") => js_count += 1,
            Some("ts" | "tsx") => ts_count += 1,
            Some("py") => py_count += 1,
            Some("go") => go_count += 1,
            _ => {}
        }
    }

    // Manifest files weigh more than a stray source file or two
    if root.join("Cargo.toml").exists() {
        rs_count += 10;
    }
    if root.join("composer.json").exists() {
        php_count += 10;
    }
    if root.join("package.json").exists() {
        js_count += 5;
        ts_count += 5;
    }
    if root.join("go.mod").exists() {
        go_count += 10;
    }
    if root.join("requirements.txt").exists() || root.join("pyproject.toml").exists() {
        py_count += 10;
    }

    let max = *[php_count, rs_count, js_count, ts_count, py_count, go_count]
        .iter()
        .max()
        .unwrap_or(&0);

    if max == 0 {
        return Language::Php; // default
    }

    if max == rs_count {
        Language::Rust
    } else if max == php_count {
        Language::Php
    } else if max == ts_count {
        Language::TypeScript
    } else if max == js_count {
        Language::JavaScript
    } else if max == py_count {
        Language::Python
    } else if max == go_count {
        Language::Go
    } else {
        Language::Php
    }
}

pub(crate) fn make_atlas_config(path: &Path) -> AtlasConfig {
    let root = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let language = detect_language(&root);

    // Always excluded, regardless of config.
    let mut exclude_patterns = vec![
        "vendor".to_string(),
        "node_modules".to_string(),
        ".git".to_string(),
        "target".to_string(),
    ];

    // Honor exclude_paths declared in verum.standard.json so users can scope the
    // scan (e.g. skip compiled views, build artifacts, vendored assets).
    for pat in read_exclude_paths(&root) {
        if !exclude_patterns.contains(&pat) {
            exclude_patterns.push(pat);
        }
    }

    AtlasConfig {
        root,
        language,
        exclude_patterns,
        cache_path: None,
        delta_mode: false,
    }
}

/// Read the `exclude_paths` array from `verum.standard.json`, if present.
///
/// Trailing slashes are stripped so entries match the substring logic used by
/// the file collector, and `*.ext`-style globs are reduced to their suffix so a
/// `path.contains()` check still matches (e.g. `*.min.js` -> `.min.js`).
fn read_exclude_paths(root: &Path) -> Vec<String> {
    let standard_path = root.join("verum.standard.json");
    let Ok(content) = std::fs::read_to_string(&standard_path) else {
        return Vec::new();
    };
    let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) else {
        return Vec::new();
    };
    val.get("exclude_paths")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.trim_end_matches('/').trim_start_matches('*').to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Render a finding's path relative to the current working directory when
/// possible, falling back to the full path. Avoids ambiguous bare basenames
/// like `Dockerfile` when several exist in the tree.
fn display_path(path: &Path) -> String {
    if let Ok(cwd) = std::env::current_dir() {
        if let Ok(rel) = path.strip_prefix(&cwd) {
            return rel.to_string_lossy().into_owned();
        }
    }
    path.to_string_lossy().into_owned()
}

fn make_spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("  {spinner:.cyan} {msg}")
            .unwrap()
            .tick_chars("|/-\\"),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb
}

fn severity_label(s: &Severity) -> colored::ColoredString {
    match s {
        Severity::Critical => "CRITICAL".red().bold(),
        Severity::High => "HIGH".red(),
        Severity::Medium => "MEDIUM".yellow(),
        Severity::Low => "LOW".white(),
        Severity::Info => "INFO".dimmed(),
    }
}

fn finding_kind_label(k: &FindingKind) -> &'static str {
    match k {
        FindingKind::DeadFunction => "DeadFunction",
        FindingKind::DeadClass => "DeadClass",
        FindingKind::DeadFile => "DeadFile",
        FindingKind::UnreachableCode => "UnreachableCode",
        FindingKind::ExactDuplicate => "ExactDuplicate",
        FindingKind::RenamedDuplicate => "RenamedDuplicate",
        FindingKind::SemanticDuplicate => "SemanticDuplicate",
        FindingKind::SqlInjection => "SqlInjection",
        FindingKind::XssVulnerability => "XssVulnerability",
        FindingKind::WeakCrypto => "WeakCrypto",
        FindingKind::HardcodedSecret => "HardcodedSecret",
        FindingKind::EvalUsage => "EvalUsage",
        FindingKind::MissingAuthMiddleware => "MissingAuthMiddleware",
        FindingKind::MissingRoleCheck => "MissingRoleCheck",
        FindingKind::PotentialIdor => "PotentialIdor",
        FindingKind::WeakRandom => "WeakRandom",
        FindingKind::OpenRedirect => "OpenRedirect",
        FindingKind::GodClass => "GodClass",
        FindingKind::CircularDependency => "CircularDependency",
        FindingKind::HighComplexity => "HighComplexity",
        FindingKind::LongFunction => "LongFunction",
        FindingKind::TooManyParams => "TooManyParams",
        FindingKind::DeepNesting => "DeepNesting",
        FindingKind::NPlusOneQuery => "NPlusOneQuery",
        FindingKind::StringConcatInLoop => "StringConcatInLoop",
        FindingKind::ObjectInstantiationInLoop => "ObjectInstantiationInLoop",
        FindingKind::MissingHookDependencies => "MissingHookDependencies",
        FindingKind::NamingInconsistency => "NamingInconsistency",
        FindingKind::ConventionViolation => "ConventionViolation",
        FindingKind::OpenSecurityGroup => "OpenSecurityGroup",
        FindingKind::UnencryptedStorage => "UnencryptedStorage",
        FindingKind::PublicResource => "PublicResource",
        FindingKind::IamOverPermission => "IamOverPermission",
        FindingKind::RunningAsRoot => "RunningAsRoot",
        FindingKind::PrivilegedContainer => "PrivilegedContainer",
        FindingKind::MissingResourceLimits => "MissingResourceLimits",
        FindingKind::MissingHealthProbes => "MissingHealthProbes",
        FindingKind::UnpinnedImage => "UnpinnedImage",
        FindingKind::NoNetworkPolicy => "NoNetworkPolicy",
        FindingKind::SecretInEnvVar => "SecretInEnvVar",
        FindingKind::HardcodedCredential => "HardcodedCredential",
        FindingKind::PciViolation => "PciViolation",
        FindingKind::GdprViolation => "GdprViolation",
        FindingKind::Soc2Violation => "Soc2Violation",
        FindingKind::DangerousChain => "DangerousChain",
        FindingKind::UnsafeUsage => "UnsafeUsage",
        FindingKind::PanicRisk => "PanicRisk",
        FindingKind::BlockingInAsync => "BlockingInAsync",
        FindingKind::UnboundedChannel => "UnboundedChannel",
        FindingKind::HotPathAllocation => "HotPathAllocation",
        FindingKind::LockOnHotPath => "LockOnHotPath",
        FindingKind::LockAcrossAwait => "LockAcrossAwait",
        FindingKind::PathTraversal => "PathTraversal",
        FindingKind::VulnerableDependency => "VulnerableDependency",
        FindingKind::UnmaintainedDependency => "UnmaintainedDependency",
        FindingKind::DuplicateDependency => "DuplicateDependency",
        FindingKind::MissingSafetyComment => "MissingSafetyComment",
        FindingKind::CrateApiMisuse => "CrateApiMisuse",
        FindingKind::SplitDatagramMessage => "SplitDatagramMessage",
        FindingKind::OversizedDatagram => "OversizedDatagram",
        FindingKind::UnvalidatedLengthPrefix => "UnvalidatedLengthPrefix",
        FindingKind::NonConstantTimeComparison => "NonConstantTimeComparison",
        FindingKind::StaticAeadNonce => "StaticAeadNonce",
    }
}

fn is_dependency(k: &FindingKind) -> bool {
    matches!(
        k,
        FindingKind::VulnerableDependency
            | FindingKind::UnmaintainedDependency
            | FindingKind::DuplicateDependency
    )
}

fn is_transport(k: &FindingKind) -> bool {
    matches!(
        k,
        FindingKind::SplitDatagramMessage
            | FindingKind::OversizedDatagram
            | FindingKind::UnvalidatedLengthPrefix
    )
}

fn is_rust_insight(k: &FindingKind) -> bool {
    matches!(
        k,
        FindingKind::UnsafeUsage
            | FindingKind::PanicRisk
            | FindingKind::BlockingInAsync
            | FindingKind::UnboundedChannel
            | FindingKind::HotPathAllocation
            | FindingKind::LockOnHotPath
            | FindingKind::LockAcrossAwait
            | FindingKind::MissingSafetyComment
    )
}

fn is_chain(k: &FindingKind) -> bool {
    matches!(k, FindingKind::DangerousChain)
}

pub(crate) fn severity_rank(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Info => 0,
    }
}

fn is_dead_code(k: &FindingKind) -> bool {
    matches!(
        k,
        FindingKind::DeadFunction | FindingKind::DeadClass | FindingKind::DeadFile
    )
}

fn is_duplicate(k: &FindingKind) -> bool {
    matches!(
        k,
        FindingKind::ExactDuplicate
            | FindingKind::RenamedDuplicate
            | FindingKind::SemanticDuplicate
    )
}

fn is_security(k: &FindingKind) -> bool {
    matches!(
        k,
        FindingKind::SqlInjection
            | FindingKind::XssVulnerability
            | FindingKind::WeakCrypto
            | FindingKind::HardcodedSecret
            | FindingKind::EvalUsage
            | FindingKind::MissingAuthMiddleware
            | FindingKind::MissingRoleCheck
            | FindingKind::PotentialIdor
            | FindingKind::WeakRandom
            | FindingKind::OpenRedirect
            | FindingKind::PathTraversal
            | FindingKind::NonConstantTimeComparison
            | FindingKind::StaticAeadNonce
    )
}

fn is_infrastructure(k: &FindingKind) -> bool {
    matches!(
        k,
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
    )
}

fn print_audit_results(result: &PrismResult) {
    let dead: Vec<&Finding> = result
        .findings
        .iter()
        .filter(|f| is_dead_code(&f.kind))
        .collect();
    if dead.is_empty() {
        println!("  {}  Dead code:    0 findings", "✓".green());
    } else {
        let short_names: Vec<String> = dead
            .iter()
            .map(|f| {
                // Pull the symbol name out of "Dead code: `name` is never called"
                if let Some(start) = f.message.find('`') {
                    if let Some(end) = f.message[start + 1..].find('`') {
                        return f.message[start + 1..start + 1 + end].to_string();
                    }
                }
                let file_name = f
                    .file
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");
                format!("{}:{}", file_name, f.line_start)
            })
            .collect();
        println!(
            "  {}  Dead code:    {} findings ({})",
            "✓".green(),
            dead.len(),
            short_names.join(", ")
        );
    }

    let dups: Vec<&Finding> = result
        .findings
        .iter()
        .filter(|f| is_duplicate(&f.kind))
        .collect();
    if dups.is_empty() {
        println!("  {}  Duplicates:   0 groups", "✓".green());
    } else {
        println!(
            "  {}  Duplicates:   {} groups",
            "✓".green(),
            result.duplicate_groups.len()
        );
    }

    let sec: Vec<&Finding> = result
        .findings
        .iter()
        .filter(|f| is_security(&f.kind))
        .collect();
    if sec.is_empty() {
        println!("  {}  Security:     0 findings", "✓".green());
    } else {
        println!("  {}  Security:     {} findings", "✓".green(), sec.len());
        for f in &sec {
            println!(
                "     {} {}: {} -- {}:{}",
                "✗".red(),
                severity_label(&f.severity),
                finding_kind_label(&f.kind),
                display_path(&f.file),
                f.line_start
            );
        }
    }

    // Behavioural facts about specific crates (tokio interval semantics, etc.)
    let crate_notes: Vec<&Finding> = result
        .findings
        .iter()
        .filter(|f| f.kind == FindingKind::CrateApiMisuse)
        .collect();
    if !crate_notes.is_empty() {
        println!(
            "  {}  Crate semantics: {} notes",
            "◆".cyan(),
            crate_notes.len()
        );
        for f in crate_notes.iter().take(10) {
            println!(
                "     {} {}: {} -- {}:{}",
                "?".cyan(),
                severity_label(&f.severity),
                f.message,
                display_path(&f.file),
                f.line_start
            );
        }
    }

    let deps: Vec<&Finding> = result
        .findings
        .iter()
        .filter(|f| is_dependency(&f.kind))
        .collect();
    if !deps.is_empty() {
        let vuln = deps
            .iter()
            .filter(|f| f.kind == FindingKind::VulnerableDependency)
            .count();
        println!(
            "  {}  Dependencies: {} findings{}",
            if vuln > 0 {
                "✗".red()
            } else {
                "⚠".yellow()
            },
            deps.len(),
            if vuln > 0 {
                format!(" ({vuln} vulnerable)")
            } else {
                String::new()
            },
        );
        for f in &deps {
            println!(
                "     {} {}: {}",
                if f.kind == FindingKind::VulnerableDependency {
                    "✗".red()
                } else {
                    "⚠".yellow()
                },
                severity_label(&f.severity),
                f.message,
            );
        }
    }

    // Datagram framing, wire-length validation
    let transport: Vec<&Finding> = result
        .findings
        .iter()
        .filter(|f| is_transport(&f.kind))
        .collect();
    if !transport.is_empty() {
        println!(
            "  {}  Transport:    {} findings",
            "✗".red(),
            transport.len()
        );
        for f in &transport {
            println!(
                "     {} {}: {} -- {}:{}",
                "✗".red(),
                severity_label(&f.severity),
                f.message,
                display_path(&f.file),
                f.line_start
            );
        }
    }

    let complexity: Vec<&Finding> = result
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.kind,
                FindingKind::LongFunction
                    | FindingKind::TooManyParams
                    | FindingKind::HighComplexity
                    | FindingKind::DeepNesting
                    | FindingKind::GodClass
            )
        })
        .collect();
    if !complexity.is_empty() {
        println!(
            "  {}  Complexity:   {} findings",
            "⚠".yellow(),
            complexity.len()
        );
    }

    let naming: Vec<&Finding> = result
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.kind,
                FindingKind::NamingInconsistency | FindingKind::ConventionViolation
            )
        })
        .collect();
    if !naming.is_empty() {
        println!(
            "  {}  Naming:       {} findings",
            "⚠".yellow(),
            naming.len()
        );
    }

    // N+1 queries, missing hook dep arrays, loop anti-patterns
    let perf: Vec<&Finding> = result
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.kind,
                FindingKind::NPlusOneQuery
                    | FindingKind::StringConcatInLoop
                    | FindingKind::ObjectInstantiationInLoop
                    | FindingKind::MissingHookDependencies
            )
        })
        .collect();
    if !perf.is_empty() {
        println!("  {}  Performance:  {} findings", "⚠".yellow(), perf.len());
        for f in perf.iter().take(10) {
            println!(
                "     {} {}: {} -- {}:{}",
                "⚠".yellow(),
                severity_label(&f.severity),
                finding_kind_label(&f.kind),
                display_path(&f.file),
                f.line_start
            );
        }
        if perf.len() > 10 {
            println!("     ... {} more", perf.len() - 10);
        }
    }

    let infra: Vec<&Finding> = result
        .findings
        .iter()
        .filter(|f| is_infrastructure(&f.kind))
        .collect();
    if !infra.is_empty() {
        println!("  {}  Infra:        {} findings", "✗".red(), infra.len());
        for f in &infra {
            println!(
                "     {} {}: {} -- {}:{}",
                "✗".red(),
                severity_label(&f.severity),
                finding_kind_label(&f.kind),
                display_path(&f.file),
                f.line_start
            );
        }
    }

    // Rust systems insights
    let insights: Vec<&Finding> = result
        .findings
        .iter()
        .filter(|f| is_rust_insight(&f.kind))
        .collect();
    if !insights.is_empty() {
        use std::collections::BTreeMap;
        let mut by_kind: BTreeMap<&str, usize> = BTreeMap::new();
        for f in &insights {
            *by_kind.entry(finding_kind_label(&f.kind)).or_default() += 1;
        }
        let summary: Vec<String> = by_kind
            .iter()
            .map(|(k, n)| format!("{} {}", n, k))
            .collect();
        println!(
            "  {}  Performance signals: {} ({})",
            "◆".cyan(),
            insights.len(),
            summary.join(", ")
        );
        for f in insights.iter().take(14) {
            println!(
                "     {} {}: {} -- {}:{}",
                "?".cyan(),
                finding_kind_label(&f.kind),
                f.message,
                display_path(&f.file),
                f.line_start
            );
        }
        if insights.len() > 14 {
            println!(
                "     {} ... {} more (see report/map)",
                "?".cyan(),
                insights.len() - 14
            );
        }
    }

    // Daisychains: entry point -> sink call chains
    let mut chains: Vec<&Finding> = result
        .findings
        .iter()
        .filter(|f| is_chain(&f.kind))
        .collect();
    if !chains.is_empty() {
        // Most exploitable first; show the top few, summarize the rest
        chains.sort_by_key(|c| std::cmp::Reverse(severity_rank(&c.severity)));
        println!("  {}  Chains:       {} mapped", "⚠".yellow(), chains.len());
        for f in chains.iter().take(12) {
            println!(
                "     {} {}: {}",
                "->".cyan(),
                severity_label(&f.severity),
                f.message
            );
        }
        if chains.len() > 12 {
            println!(
                "     {} ... {} more (see report)",
                "->".cyan(),
                chains.len() - 12
            );
        }
    }

    println!();
    let score_color = if result.score.overall >= 85 {
        format!("{}/100", result.score.overall).green()
    } else if result.score.overall >= 50 {
        format!("{}/100", result.score.overall).yellow()
    } else {
        format!("{}/100", result.score.overall).red()
    };
    println!("  Score: {}", score_color);
}

pub(crate) fn load_standard_from_file(root: &Path) -> Standard {
    use std::collections::{HashMap, HashSet};
    use verum_lumen::{
        DeadCodeConfig, NamingConfig, NamingConvention, NamingRules, SecurityConfig,
    };

    let standard_path = root.join("verum.standard.json");
    if !standard_path.exists() {
        return Standard::default();
    }
    let content = match std::fs::read_to_string(&standard_path) {
        Ok(c) => c,
        Err(_) => return Standard::default(),
    };
    let val: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Standard::default(),
    };

    let max_function_lines = val
        .pointer("/code/architecture/max_function_lines")
        .and_then(|v| v.as_u64())
        .unwrap_or(50) as u32;
    let max_parameters = val
        .pointer("/code/architecture/max_parameters")
        .and_then(|v| v.as_u64())
        .unwrap_or(5) as u8;
    let max_class_methods = val
        .pointer("/code/architecture/max_class_methods")
        .and_then(|v| v.as_u64())
        .unwrap_or(20) as u16;
    let auto_fix = val
        .pointer("/confidence_thresholds/auto_fix")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.85) as f32;
    let ai_review = val
        .pointer("/confidence_thresholds/ai_review")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.50) as f32;

    let forbid_weak_crypto: Vec<String> = val
        .pointer("/code/security/forbid_weak_crypto")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let mut weak_crypto_allowlist: HashMap<String, HashSet<String>> = HashMap::new();
    if let Some(obj) = val
        .pointer("/code/security/weak_crypto_allowlist")
        .and_then(|v| v.as_object())
    {
        for (func, contexts) in obj {
            if let Some(arr) = contexts.as_array() {
                let set: HashSet<String> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
                weak_crypto_allowlist.insert(func.clone(), set);
            }
        }
    }

    let security = SecurityConfig {
        forbid_weak_crypto,
        weak_crypto_allowlist,
    };

    let laravel_entry_points: Vec<String> = val
        .pointer("/code/dead_code/laravel_entry_points")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let laravel_magic_patterns: Vec<String> = val
        .pointer("/code/dead_code/laravel_magic_patterns")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let react_ignore_patterns: Vec<String> = val
        .pointer("/code/dead_code/ignore_patterns")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let dead_code = DeadCodeConfig {
        laravel_entry_points,
        laravel_magic_patterns,
        react_ignore_patterns,
    };

    fn parse_convention(s: &str) -> Option<NamingConvention> {
        match s {
            "PascalCase" => Some(NamingConvention::PascalCase),
            "camelCase" => Some(NamingConvention::CamelCase),
            "snake_case" => Some(NamingConvention::SnakeCase),
            "SCREAMING_SNAKE_CASE" => Some(NamingConvention::ScreamingSnakeCase),
            _ => None,
        }
    }

    fn parse_naming_rules(val: &serde_json::Value) -> Option<NamingRules> {
        if !val.is_object() {
            return None;
        }
        Some(NamingRules {
            classes: val
                .get("classes")
                .and_then(|v| v.as_str())
                .and_then(parse_convention),
            methods: val
                .get("methods")
                .and_then(|v| v.as_str())
                .and_then(parse_convention),
            functions: val
                .get("functions")
                .and_then(|v| v.as_str())
                .and_then(parse_convention),
            variables: val
                .get("variables")
                .and_then(|v| v.as_str())
                .and_then(parse_convention),
            properties: val
                .get("properties")
                .and_then(|v| v.as_str())
                .and_then(parse_convention),
            constants: val
                .get("constants")
                .and_then(|v| v.as_str())
                .and_then(parse_convention),
            components: val
                .get("components")
                .and_then(|v| v.as_str())
                .and_then(parse_convention),
        })
    }

    // A flat `code.naming` object ("classes": "PascalCase", ...) is the legacy
    // config shape - treat it as rules for the C-style languages (PHP/JS/TS)
    // so existing configs keep working. Rust/Python/Go keep their idiomatic
    // per-language defaults unless configured explicitly.
    let flat_rules = val
        .pointer("/code/naming")
        .filter(|v| v.get("classes").is_some() || v.get("methods").is_some())
        .and_then(parse_naming_rules);

    let per_lang = |lang: &str| {
        val.pointer(&format!("/code/naming/{}", lang))
            .and_then(parse_naming_rules)
    };

    let naming = NamingConfig {
        php: per_lang("php").or_else(|| flat_rules.clone()),
        typescript: per_lang("typescript").or_else(|| flat_rules.clone()),
        javascript: per_lang("javascript").or_else(|| flat_rules.clone()),
        rust: per_lang("rust"),
        python: per_lang("python"),
        go: per_lang("go"),
    };

    Standard {
        max_function_lines,
        max_parameters,
        max_class_methods,
        auto_fix_threshold: auto_fix,
        ai_review_threshold: ai_review,
        naming,
        security,
        dead_code,
    }
}

async fn cmd_analyse(path: &Path) -> Result<()> {
    println!();
    let pb = make_spinner("Atlas     mapping...");

    let config = make_atlas_config(path);
    let atlas = Atlas::new(config);
    let ir = atlas.build().context("Atlas failed to map codebase")?;

    pb.finish_and_clear();

    println!(
        "  {}  {} files, ~{} lines, ~{} symbols",
        "✓".green(),
        ir.metadata.total_files,
        ir.metadata.total_lines,
        ir.symbol_count()
    );
    println!(
        "     Calls: {}, Routes: {}, Entry points: {}",
        ir.calls.len(),
        ir.routes.len(),
        ir.entry_points.len()
    );
    println!("     Build time: {}ms", ir.metadata.build_time_ms);
    println!();

    Ok(())
}

async fn cmd_audit(path: &Path) -> Result<()> {
    println!();

    let pb = make_spinner("Atlas     mapping...");
    let config = make_atlas_config(path);
    let standard = load_standard_from_file(path);
    let atlas = Atlas::new(config);
    let ir = atlas.build().context("Atlas failed to map codebase")?;
    pb.finish_and_clear();

    println!(
        "  {}  {} files, ~{} lines, ~{} symbols",
        "✓".green(),
        ir.metadata.total_files,
        ir.metadata.total_lines,
        ir.symbol_count()
    );
    println!();

    let pb = make_spinner("Prism     analysing...");
    let result = Prism::analyse_at(&ir, &standard, Some(path)).context("Prism analysis failed")?;
    pb.finish_and_clear();

    print_audit_results(&result);
    println!();

    Ok(())
}

async fn cmd_clean(path: &Path, _dry_run: bool) -> Result<()> {
    // Auto-fix is report-only in this release: `clean` shows what dead code and
    // duplicates it would remove, but never modifies files. Deterministic
    // removal is safe in principle, but a single missed dynamic caller can drop
    // live code, so applying changes is left to the caller for now.
    let dry_run = true;

    println!();
    println!("  {} Report only - no files will be modified", "->".cyan());

    let pb = make_spinner("Atlas     mapping...");
    let config = make_atlas_config(path);
    let standard = load_standard_from_file(path);
    let atlas = Atlas::new(config.clone());
    let ir = atlas.build().context("Atlas failed")?;
    pb.finish_and_clear();

    let before_symbols = ir.symbol_count();
    let before_lines = ir.metadata.total_lines;

    println!(
        "  {}  Before: {} files, ~{} lines, ~{} symbols",
        "✓".green(),
        ir.metadata.total_files,
        before_lines,
        before_symbols
    );

    let pb = make_spinner("Forge     cleaning...");
    let forge = Forge::new(ForgeConfig {
        auto_fix_threshold: standard.auto_fix_threshold,
        dry_run,
    });
    let forge_result = verum_faber::recursive::run_until_stable(&forge, &config, &standard)
        .context("Forge failed")?;
    pb.finish_and_clear();

    println!(
        "  {}  Forge: {} passes, {} symbols removed, {} lines removed",
        "✓".green(),
        forge_result.passes,
        forge_result.symbols_removed,
        forge_result.lines_removed
    );

    let pb = make_spinner("Prism     re-analysing...");
    let ir_after = Atlas::new(config).build()?;
    let result_after = Prism::analyse(&ir_after, &standard)?;
    pb.finish_and_clear();

    println!();
    println!("  {} After:", "->".cyan());
    print_audit_results(&result_after);
    println!();

    Ok(())
}

async fn cmd_full(path: &Path, _dry_run: bool) -> Result<bool> {
    // Report-only in this release (see cmd_clean): the pipeline runs and scores,
    // but forge never modifies files.
    let dry_run = true;

    let start = Instant::now();
    println!();
    println!(
        "  {} Full pipeline (report only - no files modified)",
        "->".cyan().bold()
    );

    let pb = make_spinner("Atlas     mapping...");
    let config = make_atlas_config(path);
    let standard = load_standard_from_file(path);
    let atlas = Atlas::new(config.clone());
    let ir = atlas.build().context("Atlas failed")?;
    pb.finish_and_clear();

    let _lines_before = ir.metadata.total_lines;
    println!(
        "  {}  Atlas: {} files, ~{} lines, ~{} symbols",
        "✓".green(),
        ir.metadata.total_files,
        ir.metadata.total_lines,
        ir.symbol_count()
    );

    let pb = make_spinner("Prism     analysing...");
    let result_before = Prism::analyse(&ir, &standard)?;
    pb.finish_and_clear();

    let score_before = result_before.score.clone();
    println!(
        "  {}  Prism: {} findings, score {}/100",
        "✓".green(),
        result_before.findings.len(),
        result_before.score.overall
    );

    let pb = make_spinner("Forge     auto-fixing...");
    let forge = Forge::new(ForgeConfig {
        auto_fix_threshold: standard.auto_fix_threshold,
        dry_run,
    });
    let forge_result = verum_faber::recursive::run_until_stable(&forge, &config, &standard)?;
    pb.finish_and_clear();

    let auto_fixed = forge_result.symbols_removed;
    println!(
        "  {}  Forge: {} symbols removed in {} passes",
        "✓".green(),
        forge_result.symbols_removed,
        forge_result.passes
    );

    let mut _ai_decisions = 0usize;
    let ai = AiHandoff::new();
    if ai.is_available() && !result_before.ai_review.is_empty() {
        let pb = make_spinner("AI    judging ambiguous findings...");
        let ir_current = Atlas::new(config.clone()).build()?;

        let decisions_needed: Vec<DecisionRequest> = result_before
            .ai_review
            .iter()
            .map(|f| DecisionRequest {
                id: f.id.clone(),
                kind: f.kind.clone(),
                confidence: f.confidence,
                finding: f.clone(),
                source_context: String::new(),
                options: vec![
                    "keep".to_string(),
                    "delete".to_string(),
                    "mark_deprecated".to_string(),
                ],
                recommendation: "keep".to_string(),
            })
            .collect();

        let request = verum_arbiter::HandoffRequest {
            verum_version: env!("CARGO_PKG_VERSION").to_string(),
            session_id: format!("session-{}", std::process::id()),
            score_before: score_before.overall,
            auto_fixed,
            decisions_needed,
        };

        match ai.send(&request).await {
            Ok(handoff_result) => {
                let forge_ai = Forge::new(ForgeConfig {
                    auto_fix_threshold: 0.0, // no gating - AI already judged these
                    dry_run,
                });
                let actions = verum_arbiter::executor::execute_decisions(
                    &handoff_result.decisions,
                    &request.decisions_needed,
                    &ir_current,
                    &forge_ai,
                )?;
                _ai_decisions = actions;
                pb.finish_and_clear();
                println!(
                    "  {}  AI: {} decisions, {} tokens",
                    "✓".green(),
                    handoff_result.decisions.len(),
                    handoff_result.tokens_used
                );
            }
            Err(e) => {
                pb.finish_and_clear();
                println!("  {}  AI: failed ({})", "⚠".yellow(), e);
            }
        }
    } else if !ai.is_available() && !result_before.ai_review.is_empty() {
        println!(
            "  {}  AI: skipped (VERUM_AI_ENDPOINT not set, {} findings need review)",
            "⚠".yellow(),
            result_before.ai_review.len()
        );
    } else {
        println!("  {}  AI: no ambiguous findings", "✓".green());
    }

    let pb = make_spinner("Prism     re-validating...");
    let ir_final = Atlas::new(config).build()?;
    let result_after = Prism::analyse(&ir_final, &standard)?;
    pb.finish_and_clear();

    let mut score_after = result_after.score.clone();
    // Only the code dimensions are measured here; UI/journey/visual and
    // compliance don't contribute.
    score_after.compute_overall_masked(true, false, false);

    println!();
    println!("  {} Results", "═".cyan().bold());
    print_audit_results(&result_after);

    println!();
    let (gate_passed, gate_reasons) = check_deploy_gate(path, &score_after, &result_after);
    if gate_passed {
        println!(
            "  {}  Deploy gate: {}",
            "✓".green(),
            "PASSED".green().bold()
        );
    } else {
        println!("  {}  Deploy gate: {}", "✗".red(), "FAILED".red().bold());
        for reason in &gate_reasons {
            println!("     {} {}", "->".red(), reason);
        }
    }

    let elapsed = start.elapsed();
    println!();
    println!("  Pipeline completed in {:.1}s", elapsed.as_secs_f64());
    println!(
        "  Score: {} -> {}",
        format!("{}/100", score_before.overall).yellow(),
        if score_after.overall >= 85 {
            format!("{}/100", score_after.overall).green()
        } else {
            format!("{}/100", score_after.overall).yellow()
        }
    );
    println!();

    Ok(gate_passed)
}

async fn cmd_gate(path: &Path) -> Result<bool> {
    println!();

    let pb = make_spinner("Running audit for deploy gate...");
    let config = make_atlas_config(path);
    let standard = load_standard_from_file(path);
    let ir = Atlas::new(config).build()?;
    let result = Prism::analyse_at(&ir, &standard, Some(path))?;
    pb.finish_and_clear();

    print_audit_results(&result);
    println!();

    // Ratchet mode: if a baseline exists, findings it already records don't
    // fail the gate - only newly-introduced ones do.
    let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if let Some(baseline) = load_baseline(&canon) {
        let new_findings = result
            .findings
            .iter()
            .filter(|f| is_baselineable(f))
            .filter(|f| !baseline.contains(&finding_fingerprint(f, &canon)))
            .count();
        println!(
            "  {}  Baseline active: {} known finding(s) waived, {} new",
            "->".cyan(),
            baseline.len(),
            new_findings,
        );
        let new_critical = result
            .findings
            .iter()
            .filter(|f| is_baselineable(f) && f.severity == Severity::Critical)
            .filter(|f| !baseline.contains(&finding_fingerprint(f, &canon)))
            .count();
        let new_high = result
            .findings
            .iter()
            .filter(|f| is_baselineable(f) && f.severity == Severity::High)
            .filter(|f| !baseline.contains(&finding_fingerprint(f, &canon)))
            .count();
        let passed = new_critical == 0 && new_high == 0;
        if passed {
            println!(
                "  {}  Deploy gate: {} (no new High/Critical findings)",
                "✓".green(),
                "PASSED".green().bold()
            );
        } else {
            println!("  {}  Deploy gate: {}", "✗".red(), "FAILED".red().bold());
            println!(
                "     {} {} new critical, {} new high vs baseline",
                "->".red(),
                new_critical,
                new_high
            );
        }
        println!();
        return Ok(passed);
    }

    let (passed, reasons) = check_deploy_gate(path, &result.score, &result);
    if passed {
        println!(
            "  {}  Deploy gate: {}",
            "✓".green(),
            "PASSED".green().bold()
        );
    } else {
        println!("  {}  Deploy gate: {}", "✗".red(), "FAILED".red().bold());
        for reason in &reasons {
            println!("     {} {}", "->".red(), reason);
        }
    }
    println!();

    Ok(passed)
}

fn check_deploy_gate(root: &Path, score: &Score, result: &PrismResult) -> (bool, Vec<String>) {
    let mut reasons = Vec::new();

    let standard_path = root.join("verum.standard.json");
    let (min_overall, min_security, max_critical) = if standard_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&standard_path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                let overall = val
                    .pointer("/deploy_gate/min_overall_score")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(85) as u8;
                let security = val
                    .pointer("/deploy_gate/min_security_score")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(90) as u8;
                let critical = val
                    .pointer("/deploy_gate/max_critical_issues")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as usize;
                (overall, security, critical)
            } else {
                (85, 90, 0)
            }
        } else {
            (85, 90, 0)
        }
    } else {
        (85, 90, 0)
    };

    if score.overall < min_overall {
        reasons.push(format!(
            "Overall score {} < minimum {}",
            score.overall, min_overall
        ));
    }

    if score.security < min_security {
        reasons.push(format!(
            "Security score {} < minimum {}",
            score.security, min_security
        ));
    }

    // Daisychains are an informational mapping aid (heuristic gate detection),
    // so they never fail the deploy gate on their own.
    let critical_count = result
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical && !is_chain(&f.kind))
        .count();
    if critical_count > max_critical {
        reasons.push(format!(
            "Critical issues {} > maximum {}",
            critical_count, max_critical
        ));
    }

    (reasons.is_empty(), reasons)
}

const BASELINE_FILE: &str = "verum.baseline.json";

/// A stable identity for a finding, resilient to line-number drift. Keyed on
/// the finding kind, the project-relative file, and the message with digits
/// stripped (so "13 chunks" and "14 chunks", or a shifted line cited in the
/// text, collapse to the same fingerprint). Deliberately ignores line numbers:
/// a baseline should survive unrelated edits above the finding.
fn finding_fingerprint(f: &Finding, root: &Path) -> String {
    let rel = f
        .file
        .strip_prefix(root)
        .unwrap_or(&f.file)
        .to_string_lossy()
        .replace('\\', "/");
    let message_no_digits: String = f.message.chars().filter(|c| !c.is_ascii_digit()).collect();
    format!(
        "{}|{}|{}",
        finding_kind_label(&f.kind),
        rel,
        message_no_digits.trim()
    )
}

/// Findings that represent the analysis surface a baseline should track.
/// Informational map/insight surfaces are excluded - a baseline is about
/// must-look findings, not the exploratory notes.
fn is_baselineable(f: &Finding) -> bool {
    !is_chain(&f.kind) && !is_rust_insight(&f.kind) && f.kind != FindingKind::CrateApiMisuse
}

fn load_baseline(root: &Path) -> Option<std::collections::HashSet<String>> {
    let text = std::fs::read_to_string(root.join(BASELINE_FILE)).ok()?;
    let val: serde_json::Value = serde_json::from_str(&text).ok()?;
    let arr = val.get("fingerprints")?.as_array()?;
    Some(
        arr.iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
    )
}

async fn cmd_baseline(path: &Path) -> Result<()> {
    println!();
    let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let config = make_atlas_config(path);
    let standard = load_standard_from_file(path);
    let pb = make_spinner("Snapshotting findings...");
    let ir = Atlas::new(config).build()?;
    let result = Prism::analyse_at(&ir, &standard, Some(path))?;
    pb.finish_and_clear();

    let mut fingerprints: Vec<String> = result
        .findings
        .iter()
        .filter(|f| is_baselineable(f))
        .map(|f| finding_fingerprint(f, &canon))
        .collect();
    fingerprints.sort();
    fingerprints.dedup();

    let doc = serde_json::json!({
        "version": 1,
        "note": "Generated by `verum baseline`. Gate fails only on findings not listed here.",
        "count": fingerprints.len(),
        "fingerprints": fingerprints,
    });
    let out = path.join(BASELINE_FILE);
    std::fs::write(&out, serde_json::to_string_pretty(&doc)?)?;
    println!(
        "  {}  Baseline written: {} findings snapshotted to {}",
        "✓".green(),
        doc["count"],
        BASELINE_FILE
    );
    println!(
        "     {} `verum gate` will now fail only on findings introduced after this snapshot.",
        "->".cyan()
    );
    println!();
    Ok(())
}

/// The embedded, self-contained web UI template. `__VERUM_DATA__` is replaced
/// with the report JSON at generation time; the page has no external
/// dependencies and can be opened directly from disk.
const REPORT_HTML_TEMPLATE: &str = include_str!("../assets/report.html");

#[derive(serde::Serialize)]
struct ReportMeta {
    files: usize,
    lines: u64,
    symbols: usize,
    calls: usize,
    routes: usize,
    entry_points: usize,
    build_ms: u64,
}

#[derive(serde::Serialize)]
struct ReportGate {
    passed: bool,
    reasons: Vec<String>,
}

#[derive(serde::Serialize)]
struct ReportTriage {
    auto_fixable: usize,
    ai_review: usize,
    human_review: usize,
}

#[derive(serde::Serialize)]
struct ReportDupGroup {
    similarity: String,
    canonical_name: String,
    duplicate_names: Vec<String>,
    call_sites: usize,
    confidence: f32,
}

/// One resolved cross-language seam: a frontend HTTP call linked to the backend
/// route (and controller) that serves it.
#[derive(serde::Serialize)]
struct ReportSeam {
    method: String,
    path: String,
    client_file: String,
    client_line: u32,
    server_file: String,
    server_line: u32,
    controller: String,
    server_lang: String,
}

/// A client HTTP call hitting a path no route serves, or a route no client
/// reaches - the two orphan classes from endpoint reconciliation.
#[derive(serde::Serialize)]
struct ReportOrphan {
    method: String,
    path: String,
    file: String,
    line: u32,
}

#[derive(serde::Serialize)]
struct ReportEndpoints {
    seams: Vec<ReportSeam>,
    orphan_calls: Vec<ReportOrphan>,
    orphan_routes: Vec<ReportOrphan>,
}

#[derive(serde::Serialize)]
struct ReportData {
    version: String,
    generated_epoch: u64,
    root: String,
    meta: ReportMeta,
    score: Score,
    gate: ReportGate,
    triage: ReportTriage,
    findings: Vec<Finding>,
    duplicate_groups: Vec<ReportDupGroup>,
    endpoints: ReportEndpoints,
}

async fn cmd_report(path: &Path, format: &str, out: Option<&Path>) -> Result<()> {
    let config = make_atlas_config(path);
    let root_display = config.root.to_string_lossy().into_owned();
    let standard = load_standard_from_file(path);
    let ir = Atlas::new(config).build()?;
    let result = Prism::analyse_at(&ir, &standard, Some(path))?;
    let (gate_passed, gate_reasons) = check_deploy_gate(path, &result.score, &result);

    let rendered = match format {
        "json" => {
            let pipeline_result = PipelineResult {
                score_before: result.score.clone(),
                score_after: result.score.clone(),
                lines_before: ir.metadata.total_lines,
                lines_after: ir.metadata.total_lines,
                passes: 0,
                findings: result.findings.clone(),
                auto_fixed: 0,
                ai_decisions: 0,
                human_review: result.human_review.len(),
                duplicate_groups: result.duplicate_groups.clone(),
                duration_ms: ir.metadata.build_time_ms,
                deploy_gate_passed: gate_passed,
                deploy_gate_reasons: gate_reasons,
            };
            serde_json::to_string_pretty(&pipeline_result)?
        }
        "html" => {
            let dup_groups: Vec<ReportDupGroup> = result
                .duplicate_groups
                .iter()
                .map(|g| ReportDupGroup {
                    similarity: format!("{:?}", g.similarity),
                    canonical_name: ir
                        .symbols
                        .get(&g.canonical)
                        .map(|s| s.fully_qualified.clone())
                        .unwrap_or_else(|| format!("#{}", g.canonical.0)),
                    duplicate_names: g
                        .duplicates
                        .iter()
                        .map(|id| {
                            ir.symbols
                                .get(id)
                                .map(|s| s.fully_qualified.clone())
                                .unwrap_or_else(|| format!("#{}", id.0))
                        })
                        .collect(),
                    call_sites: g.call_sites_to_remap.len(),
                    confidence: g.confidence,
                })
                .collect();

            let method_str = |m: &verum_nucleus::HttpMethod| -> String {
                match m {
                    verum_nucleus::HttpMethod::Get => "GET",
                    verum_nucleus::HttpMethod::Post => "POST",
                    verum_nucleus::HttpMethod::Put => "PUT",
                    verum_nucleus::HttpMethod::Patch => "PATCH",
                    verum_nucleus::HttpMethod::Delete => "DELETE",
                    verum_nucleus::HttpMethod::Any => "ANY",
                }
                .to_string()
            };
            let (seam_pairs, orphan_calls, orphan_routes) =
                verum_mappa::endpoints::reconcile_seams(&ir);
            let seams: Vec<ReportSeam> = seam_pairs
                .iter()
                .map(|s| {
                    let ctrl = s.route.controller.and_then(|id| ir.symbols.get(&id));
                    // Prefer the controller's language; fall back to the route
                    // file's language (Rust/Go/Java routes carry no controller
                    // symbol, but the file still tells us the backend language -
                    // which is the whole point of a *cross-language* seam).
                    let server_lang = ctrl
                        .map(|c| c.language.clone())
                        .or_else(|| ir.files.get(&s.route.file).map(|f| f.language.clone()));
                    ReportSeam {
                        method: method_str(&s.call.method),
                        path: s.route.path.clone(),
                        client_file: display_path(&s.call.file),
                        client_line: s.call.line,
                        server_file: display_path(&s.route.file),
                        server_line: s.route.line,
                        controller: ctrl
                            .map(|c| c.fully_qualified.clone())
                            .unwrap_or_else(|| "-".to_string()),
                        server_lang: server_lang
                            .map(|l| format!("{:?}", l))
                            .unwrap_or_else(|| "-".to_string()),
                    }
                })
                .collect();
            let endpoints = ReportEndpoints {
                seams,
                orphan_calls: orphan_calls
                    .iter()
                    .map(|c| ReportOrphan {
                        method: method_str(&c.method),
                        path: c.path.clone(),
                        file: display_path(&c.file),
                        line: c.line,
                    })
                    .collect(),
                orphan_routes: orphan_routes
                    .iter()
                    .map(|r| ReportOrphan {
                        method: method_str(&r.method),
                        path: r.path.clone(),
                        file: display_path(&r.file),
                        line: r.line,
                    })
                    .collect(),
            };

            let data = ReportData {
                version: env!("CARGO_PKG_VERSION").to_string(),
                generated_epoch: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                root: root_display,
                meta: ReportMeta {
                    files: ir.metadata.total_files,
                    lines: ir.metadata.total_lines,
                    symbols: ir.symbol_count(),
                    calls: ir.calls.len(),
                    routes: ir.routes.len(),
                    entry_points: ir.symbols.values().filter(|s| s.is_entry_point).count(),
                    build_ms: ir.metadata.build_time_ms,
                },
                score: result.score.clone(),
                gate: ReportGate {
                    passed: gate_passed,
                    reasons: gate_reasons,
                },
                triage: ReportTriage {
                    auto_fixable: result.auto_fixable.len(),
                    ai_review: result.ai_review.len(),
                    human_review: result.human_review.len(),
                },
                findings: result.findings.clone(),
                duplicate_groups: dup_groups,
                endpoints,
            };
            // `</` must not appear verbatim inside the inline <script> block.
            let json = serde_json::to_string(&data)?.replace("</", "<\\/");
            REPORT_HTML_TEMPLATE.replace("__VERUM_DATA__", &json)
        }
        "sarif" => render_sarif(&result.findings)?,
        _ => {
            let mut md = String::new();
            use std::fmt::Write;
            writeln!(md, "# Verum Report\n")?;
            writeln!(md, "## Summary")?;
            writeln!(md, "- Root: `{}`", root_display)?;
            writeln!(md, "- Files: {}", ir.metadata.total_files)?;
            writeln!(md, "- Lines: {}", ir.metadata.total_lines)?;
            writeln!(md, "- Symbols: {}", ir.symbol_count())?;
            writeln!(md, "- Overall Score: {}/100", result.score.overall)?;
            writeln!(
                md,
                "- Deploy gate: {}",
                if gate_passed { "PASSED" } else { "FAILED" }
            )?;
            for reason in &gate_reasons {
                writeln!(md, "  - {}", reason)?;
            }
            writeln!(md, "\n## Scores")?;
            writeln!(md, "| Category | Score |")?;
            writeln!(md, "|----------|-------|")?;
            writeln!(md, "| Security | {}/100 |", result.score.security)?;
            writeln!(md, "| Architecture | {}/100 |", result.score.architecture)?;
            writeln!(md, "| Performance | {}/100 |", result.score.performance)?;
            writeln!(md, "| Naming | {}/100 |", result.score.naming)?;
            writeln!(md, "| Complexity | {}/100 |", result.score.complexity)?;
            writeln!(
                md,
                "| Infrastructure | {}/100 |",
                result.score.infrastructure
            )?;
            writeln!(md, "\n## Findings ({})", result.findings.len())?;
            for f in &result.findings {
                writeln!(
                    md,
                    "- **{:?}** {:?}: {} ({}:{})",
                    f.severity,
                    f.kind,
                    f.message,
                    display_path(&f.file),
                    f.line_start
                )?;
            }
            md
        }
    };

    match out {
        Some(out_path) => {
            std::fs::write(out_path, &rendered)
                .with_context(|| format!("Failed to write {}", out_path.display()))?;
            println!(
                "  {}  Report written to {}",
                "✓".green(),
                out_path.display()
            );
        }
        None => println!("{}", rendered),
    }

    Ok(())
}

/// Map a severity onto a SARIF result level.
fn severity_to_sarif_level(sev: &verum_nucleus::Severity) -> &'static str {
    use verum_nucleus::Severity::*;
    match sev {
        Critical | High => "error",
        Medium => "warning",
        Low | Info => "note",
    }
}

/// A path GitHub code scanning can map to a file in the checkout: relative to
/// the repository root, forward slashes, no leading `./`.
fn to_relative_uri(file: &Path) -> String {
    let path = if file.is_absolute() {
        std::env::current_dir()
            .ok()
            .and_then(|cwd| file.strip_prefix(&cwd).ok().map(Path::to_path_buf))
            .unwrap_or_else(|| file.to_path_buf())
    } else {
        file.to_path_buf()
    };
    path.to_string_lossy()
        .replace('\\', "/")
        .trim_start_matches("./")
        .to_string()
}

/// Render findings as SARIF 2.1.0, the format GitHub code scanning ingests
/// (findings then surface as PR annotations and in the Security tab).
fn render_sarif(findings: &[verum_nucleus::Finding]) -> Result<String> {
    use std::collections::BTreeSet;

    let mut rule_ids: BTreeSet<String> = BTreeSet::new();
    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let rule = format!("{:?}", f.kind);
            rule_ids.insert(rule.clone());
            let start = f.line_start.max(1);
            let end = f.line_end.max(start);
            serde_json::json!({
                "ruleId": rule,
                "level": severity_to_sarif_level(&f.severity),
                "message": { "text": f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": to_relative_uri(&f.file) },
                        "region": { "startLine": start, "endLine": end }
                    }
                }]
            })
        })
        .collect();

    let rules: Vec<serde_json::Value> = rule_ids
        .iter()
        .map(|id| {
            serde_json::json!({
                "id": id,
                "name": id,
                "shortDescription": { "text": id },
                "helpUri": "https://github.com/IBMark/verum"
            })
        })
        .collect();

    let doc = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "Verum",
                "informationUri": "https://github.com/IBMark/verum",
                "version": env!("CARGO_PKG_VERSION"),
                "rules": rules
            }},
            "results": results
        }]
    });
    Ok(serde_json::to_string_pretty(&doc)?)
}

async fn cmd_init(path: Option<&Path>) -> Result<()> {
    let target = path.unwrap_or_else(|| Path::new("."));
    let target = std::fs::canonicalize(target).unwrap_or_else(|_| target.to_path_buf());

    println!();
    println!("  {} Initializing Verum in {:?}", "->".cyan(), target);

    let standard_path = target.join("verum.standard.json");
    if !standard_path.exists() {
        std::fs::write(&standard_path, STANDARD_JSON)?;
        println!("  {}  Created verum.standard.json", "✓".green());
    } else {
        println!("  {}  verum.standard.json already exists", "⚠".yellow());
    }

    println!();
    println!("  Done. Edit verum.standard.json to match your project.");
    println!();

    Ok(())
}

const STANDARD_JSON: &str = r#"{
  "version": "1.0.0",
  "exclude_paths": [],
  "code": {
    "security": {
      "forbid_weak_crypto": ["md5", "sha1", "des", "rc4"],
      "weak_crypto_allowlist": {}
    },
    "architecture": {
      "max_function_lines": 50,
      "max_parameters": 5,
      "max_class_methods": 20
    },
    "naming": {
      "php": {
        "classes": "PascalCase",
        "methods": "camelCase",
        "functions": "camelCase",
        "variables": "camelCase",
        "constants": "SCREAMING_SNAKE_CASE"
      },
      "typescript": {
        "classes": "PascalCase",
        "methods": "camelCase",
        "functions": "camelCase",
        "components": "PascalCase"
      },
      "rust": {
        "classes": "PascalCase",
        "functions": "snake_case",
        "methods": "snake_case",
        "constants": "SCREAMING_SNAKE_CASE"
      },
      "python": {
        "classes": "PascalCase",
        "functions": "snake_case",
        "methods": "snake_case"
      }
    },
    "dead_code": {
      "laravel_entry_points": [],
      "laravel_magic_patterns": [],
      "ignore_patterns": []
    },
    "rbac": {
      "require_auth_middleware": true
    }
  },
  "confidence_thresholds": {
    "auto_fix": 0.85,
    "ai_review": 0.50,
    "human_review": 0.0
  },
  "deploy_gate": {
    "min_overall_score": 85,
    "min_security_score": 90,
    "max_critical_issues": 0
  }
}"#;
