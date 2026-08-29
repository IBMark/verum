//! Keeps the shipped integration snippets and the agent-facing command
//! reference honest.
//!
//! Two failure modes this guards against: a snippet in `integrations/` that
//! does not parse as the JSON/YAML its consumer expects, and `docs/agents.md`
//! documenting a flag the CLI does not have (or missing one it does). The
//! second check runs against `--help` in both directions, so the docs cannot
//! rot in either.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Run the just-built `verum` binary, retrying on ETXTBSY: on CI another
/// process can transiently hold the freshly linked executable open for
/// writing, which makes exec fail with "text file busy".
fn run_verum(args: &[&str]) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_verum");
    let mut attempts = 0u32;
    loop {
        match Command::new(bin).args(args).output() {
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy && attempts < 50 => {
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            other => return other.expect("run verum"),
        }
    }
}

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    // Windows runners check the repo out with CRLF endings; every assertion
    // below reasons about `\n`-delimited structure, so normalise here.
    text.replace("\r\n", "\n")
}

// ---------------------------------------------------------------------------
// integrations/ snippets
// ---------------------------------------------------------------------------

#[test]
fn integration_json_snippets_parse() {
    for rel in [
        "integrations/claude-code/settings.json",
        "integrations/claude-code/mcp.json",
    ] {
        let text = read(rel);
        serde_json::from_str::<serde_json::Value>(&text)
            .unwrap_or_else(|e| panic!("{rel} is not valid JSON: {e}"));
    }
}

#[test]
fn integration_yaml_snippets_parse() {
    for rel in [
        "integrations/pre-commit/.pre-commit-config.yaml",
        "integrations/github-actions/verum.yml",
    ] {
        let text = read(rel);
        serde_yaml::from_str::<serde_yaml::Value>(&text)
            .unwrap_or_else(|e| panic!("{rel} is not valid YAML: {e}"));
    }
}

/// A Cursor rule is markdown with a YAML frontmatter block; the frontmatter is
/// the part a parser has to accept.
#[test]
fn cursor_rule_frontmatter_parses() {
    let text = read("integrations/cursor/verum.mdc");
    let rest = text
        .strip_prefix("---\n")
        .expect("verum.mdc starts with a frontmatter fence");
    let (front, _body) = rest
        .split_once("\n---\n")
        .expect("verum.mdc frontmatter is closed");
    let value: serde_yaml::Value =
        serde_yaml::from_str(front).expect("verum.mdc frontmatter is valid YAML");
    assert!(
        value.get("description").is_some(),
        "cursor rule needs a description"
    );
    assert_eq!(
        value.get("alwaysApply"),
        Some(&serde_yaml::Value::Bool(true))
    );
}

/// Words following a literal `verum ` that look like a subcommand. Prose
/// mentions of the tool are written "`verum`" or "Verum", neither of which
/// leaves a space after a lowercase `verum`, so this picks out invocations
/// without dragging sentences in.
fn invoked_subcommands(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    text.match_indices("verum ")
        .filter(|(i, _)| {
            // Not the tail of a longer identifier ("myverum gate").
            *i == 0 || !(bytes[i - 1] as char).is_ascii_alphanumeric()
        })
        .filter_map(|(i, m)| text[i + m.len()..].split_whitespace().next())
        .filter(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase()))
        .map(str::to_string)
        .collect()
}

/// The snippets are only useful if they invoke commands that exist.
#[test]
fn integration_snippets_reference_real_commands() {
    let subcommands = subcommands_from_help();
    let mut seen = 0usize;
    for rel in [
        "integrations/claude-code/settings.json",
        "integrations/claude-code/mcp.json",
        "integrations/claude-code/verum-hook.sh",
        "integrations/cursor/verum.mdc",
        "integrations/pre-commit/.pre-commit-config.yaml",
        "integrations/github-actions/verum.yml",
        "integrations/README.md",
    ] {
        for word in invoked_subcommands(&read(rel)) {
            seen += 1;
            assert!(
                subcommands.contains(&word),
                "{rel} invokes `verum {word}`, which is not a subcommand"
            );
        }
    }
    assert!(
        seen > 5,
        "expected the snippets to invoke verum; found {seen}"
    );
}

// ---------------------------------------------------------------------------
// docs/agents.md vs the actual CLI
// ---------------------------------------------------------------------------

fn subcommands_from_help() -> BTreeSet<String> {
    let out = run_verum(&["--help"]);
    let text = String::from_utf8_lossy(&out.stdout);
    let body = text.split("Commands:").nth(1).expect("help lists commands");
    let body = body.split("Options:").next().unwrap();
    body.lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|w| w.chars().all(|c| c.is_ascii_lowercase()) && !w.is_empty())
        .filter(|w| *w != "help")
        .map(str::to_string)
        .collect()
}

/// Long flags `--help` advertises for a subcommand, minus `--help` itself.
fn flags_from_help(subcommand: &str) -> BTreeSet<String> {
    let out = run_verum(&[subcommand, "--help"]);
    let text = String::from_utf8_lossy(&out.stdout);
    let options = match text.split("Options:").nth(1) {
        Some(o) => o,
        None => return BTreeSet::new(),
    };
    // Long flags start their own line ("      --format <FORMAT>  ..."); short
    // aliases render as "-h, --help", and wrapped descriptions never begin
    // with a dash - so a leading "--" is exactly the set we want.
    options
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("--"))
        .map(|rest| {
            rest.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
                .next()
                .unwrap_or("")
                .to_string()
        })
        .filter(|f| !f.is_empty() && f != "help")
        .map(|f| format!("--{f}"))
        .collect()
}

/// Split `docs/agents.md` into `verum <cmd>` sections keyed by subcommand.
fn agents_md_sections() -> Vec<(String, String)> {
    let text = read("docs/agents.md");
    let mut sections: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("## `verum ") {
            let name = rest.trim_end_matches('`').trim().to_string();
            sections.push((name, String::new()));
        } else if line.starts_with("## ") {
            // A non-command heading closes the current section.
            sections.push((String::new(), String::new()));
        } else if let Some(last) = sections.last_mut() {
            last.1.push_str(line);
            last.1.push('\n');
        }
    }
    sections.retain(|(name, _)| !name.is_empty());
    sections
}

/// Flags a section claims, i.e. bullets of the form "- `--flag` ...".
fn flags_documented(section: &str) -> BTreeSet<String> {
    section
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("- `--"))
        .map(|rest| {
            rest.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
                .next()
                .unwrap_or("")
                .to_string()
        })
        .filter(|f| !f.is_empty())
        .map(|f| format!("--{f}"))
        .collect()
}

#[test]
fn agents_md_documents_every_subcommand() {
    let documented: BTreeSet<String> = agents_md_sections().into_iter().map(|(n, _)| n).collect();
    let actual = subcommands_from_help();
    assert_eq!(
        actual,
        documented,
        "docs/agents.md sections must match `verum --help` exactly \
         (missing: {:?}, stale: {:?})",
        actual.difference(&documented).collect::<Vec<_>>(),
        documented.difference(&actual).collect::<Vec<_>>(),
    );
}

#[test]
fn agents_md_flags_match_the_cli() {
    for (name, body) in agents_md_sections() {
        let actual = flags_from_help(&name);
        let documented = flags_documented(&body);
        assert_eq!(
            actual,
            documented,
            "`verum {name}`: docs/agents.md flags disagree with --help \
             (undocumented: {:?}, documented but absent: {:?})",
            actual.difference(&documented).collect::<Vec<_>>(),
            documented.difference(&actual).collect::<Vec<_>>(),
        );
    }
}

#[test]
fn readme_links_the_agent_reference() {
    let readme = read("README.md");
    assert!(
        readme.contains("docs/agents.md"),
        "README should link docs/agents.md so agents and CI users can find it"
    );
    assert!(
        readme.contains("integrations/"),
        "README should point at the integrations directory"
    );
}
