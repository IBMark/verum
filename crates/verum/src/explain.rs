//! `verum explain` - the detector reference, rendered for a terminal.
//!
//! Every word printed here comes from the table in
//! `verum_nucleus::reference`, the same table `docs/detectors.md` is
//! generated from, so the CLI and the docs cannot disagree.

use anyhow::{bail, Result};
use colored::Colorize;
use verum_nucleus::reference::{self, DetectorReference};

/// `verum explain [kind] [--all] [--format text|markdown]`.
pub fn cmd_explain(kind: Option<&str>, all: bool, format: &str) -> Result<()> {
    let markdown = match format {
        "text" => false,
        "markdown" | "md" => true,
        other => bail!("unknown format `{other}` (expected `text` or `markdown`)"),
    };

    // A named kind wins over --all: `verum explain --all sql-injection` asks
    // about one detector, however the flags were typed.
    if let Some(query) = kind {
        let Some(entry) = reference::lookup(query) else {
            return Err(unknown_kind(query));
        };
        if markdown {
            print!("{}", reference::markdown_entry(entry));
        } else {
            print_entry(entry);
        }
        return Ok(());
    }

    match (all, markdown) {
        // The whole reference, in the format `docs/detectors.md` is generated
        // from. The index is markdown-only in that shape too: a one-line-per
        // -kind markdown list would be a second, drifting rendering.
        (_, true) => print!("{}", reference::markdown_document()),
        (true, false) => {
            for k in reference::ALL_KINDS {
                print_entry(reference::reference(k));
            }
        }
        (false, false) => print_index(),
    }
    Ok(())
}

/// The error for an unrecognised kind, with the closest names Verum knows.
fn unknown_kind(query: &str) -> anyhow::Error {
    let close = reference::close_matches(query);
    if close.is_empty() {
        anyhow::anyhow!(
            "unknown finding kind `{query}`\n       \
             run `verum explain` with no argument to list all {} kinds",
            reference::ALL_KINDS.len()
        )
    } else {
        let suggestions: Vec<String> = close
            .iter()
            .map(|name| {
                let entry = reference::lookup(name).expect("close match is a known kind");
                format!("         {} ({})", entry.kind, entry.alias())
            })
            .collect();
        anyhow::anyhow!(
            "unknown finding kind `{query}`\n       did you mean:\n{}",
            suggestions.join("\n")
        )
    }
}

/// One line per kind: the name and its one-line summary.
fn print_index() {
    let width = reference::ALL_KINDS
        .iter()
        .map(|k| reference::reference(k).kind.len())
        .max()
        .unwrap_or(0);
    for k in reference::ALL_KINDS {
        let entry = reference::reference(k);
        println!(
            "  {:<width$}  {}",
            entry.kind.bold(),
            entry.summary.dimmed(),
            width = width
        );
    }
    println!();
    println!(
        "  {} detectors. `verum explain <kind>` for the full entry; the kebab alias",
        reference::ALL_KINDS.len()
    );
    println!("  (e.g. `verum explain non-constant-time-comparison`) works too.");
}

/// The full entry for one detector.
fn print_entry(entry: &DetectorReference) {
    println!();
    println!("  {}  {}", entry.kind.bold(), entry.alias().dimmed());
    println!("  {}", entry.summary);
    println!("  {}: {}", "category".dimmed(), entry.category);
    println!();
    print_paragraph("Detects", entry.detects);
    print_paragraph("Why it matters", entry.why);
    print_example("Flagged", &entry.bad_example(), true);
    print_example("Fixed", &entry.good_example(), false);
    print_paragraph("Reasonable to suppress", entry.suppress);
}

/// A labelled paragraph, wrapped to a readable width.
fn print_paragraph(label: &str, body: &str) {
    println!("  {}", label.bold());
    for line in wrap(body, 78) {
        println!("    {line}");
    }
    println!();
}

/// An example block. The flagged example gets a red gutter, the fix a green
/// one; with colour off both are plain ASCII gutters.
fn print_example(label: &str, body: &str, flagged: bool) {
    let color = colored::control::SHOULD_COLORIZE.should_colorize();
    let gutter = if flagged { "-" } else { "+" };
    println!("  {}", label.bold());
    for line in body.lines() {
        let text = format!("    {gutter} {line}");
        if !color {
            println!("{text}");
        } else if flagged {
            println!("{}", text.red());
        } else {
            println!("{}", text.green());
        }
    }
    println!();
}

/// Greedy word wrap. Deterministic and dependency-free; long tokens (paths,
/// identifiers) are never broken.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.chars().count() + 1 + word.chars().count() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_respects_width_and_keeps_every_word() {
        let text = "the quick brown fox jumps over the lazy dog";
        let lines = wrap(text, 15);
        assert!(lines.iter().all(|l| l.chars().count() <= 15));
        assert_eq!(lines.join(" "), text);
    }

    #[test]
    fn unknown_kind_lists_close_matches() {
        let err = unknown_kind("sqlinjektion").to_string();
        assert!(err.contains("SqlInjection"), "{err}");
        assert!(err.contains("sql-injection"), "{err}");
    }

    #[test]
    fn unknown_kind_falls_back_to_the_index_hint() {
        let err = unknown_kind("zzzzzzzzzzzzzzzz").to_string();
        assert!(err.contains("verum explain"), "{err}");
    }
}
