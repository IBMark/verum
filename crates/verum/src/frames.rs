//! Source code frames for the human-readable output.
//!
//! A finding that says `security.rs:412` makes the reader go and look. A
//! frame puts the offending line, and two lines either side of it, directly
//! under the finding so the judgement can be made in place.
//!
//! Rules this module holds to:
//!
//! - Frames are a presentation layer only. They never appear in the JSON or
//!   SARIF reports, which machines diff and which must stay byte-stable.
//! - A file that cannot be read is not an error: the frame is skipped
//!   silently. Findings routinely name generated, moved, or deleted files.
//! - Colour is opt-out. `NO_COLOR`, a non-tty stdout, or `CLICOLOR=0` all
//!   drop the ANSI codes *and* switch the gutter marker to plain ASCII, so
//!   piped output stays readable and greppable.
//! - Frames are capped per run so a thousand-finding audit does not bury its
//!   own summary; the cap is reported rather than silently applied.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use colored::Colorize;
use verum_nucleus::{Finding, Severity};

/// How many findings in one run get a frame before the rest are elided.
pub const MAX_FRAMES: usize = 50;

/// Lines of context shown either side of the finding line.
const CONTEXT: u32 = 2;

/// Source lines above this length are truncated - a minified bundle would
/// otherwise wrap for pages.
const MAX_LINE_CHARS: usize = 200;

/// Files above this size are not read for frames. Frames are a convenience;
/// paging a huge generated file into memory to print five lines is not.
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Renders at most [`MAX_FRAMES`] frames per run, caching the files it reads.
pub struct Frames {
    remaining: usize,
    elided: usize,
    cache: HashMap<PathBuf, Option<Vec<String>>>,
}

impl Default for Frames {
    fn default() -> Self {
        Self::new()
    }
}

impl Frames {
    pub fn new() -> Self {
        Frames {
            remaining: MAX_FRAMES,
            elided: 0,
            cache: HashMap::new(),
        }
    }

    /// Print a frame for `finding` to stdout, indented under it. Silently
    /// does nothing when the source is unavailable or the budget is spent.
    pub fn print(&mut self, finding: &Finding) {
        if self.remaining == 0 {
            self.elided += 1;
            return;
        }
        let Some(window) = self.window(finding) else {
            return;
        };
        self.remaining -= 1;
        let color = colored::control::SHOULD_COLORIZE.should_colorize();
        for line in render(&window, &finding.severity, color) {
            println!("{line}");
        }
    }

    /// The same frame as an indented markdown block, or `None` when the
    /// source is unavailable or the budget is spent. Never coloured.
    pub fn markdown(&mut self, finding: &Finding) -> Option<String> {
        if self.remaining == 0 {
            self.elided += 1;
            return None;
        }
        let window = self.window(finding)?;
        self.remaining -= 1;
        let body = render(&window, &finding.severity, false).join("\n");
        Some(format!("\n  ```text\n{body}\n  ```\n"))
    }

    /// The one-line note to print when frames were capped, if any.
    pub fn cap_note(&self) -> Option<String> {
        (self.elided > 0).then(|| {
            format!(
                "     ... source frames shown for the first {} findings; {} more elided",
                MAX_FRAMES, self.elided
            )
        })
    }

    /// Gather the lines around a finding, or `None` when there is nothing
    /// sensible to show.
    fn window(&mut self, finding: &Finding) -> Option<Window> {
        // Line 0 means "the file as a whole" (dead files, parse failures,
        // dependency findings): there is no line to point at.
        if finding.line_start == 0 {
            return None;
        }
        let lines = self.lines(&finding.file)?;
        let total = lines.len() as u32;
        if finding.line_start > total {
            return None;
        }
        let first = finding.line_start.saturating_sub(CONTEXT).max(1);
        let last = finding.line_start.saturating_add(CONTEXT).min(total);
        let highlight_end = finding.line_end.max(finding.line_start).min(last);
        Some(Window {
            first,
            marked: finding.line_start,
            marked_end: highlight_end,
            lines: lines[(first - 1) as usize..last as usize].to_vec(),
        })
    }

    /// Read and cache a file's lines. Unreadable, oversized, and binary files
    /// cache as `None` so they are attempted only once.
    fn lines(&mut self, path: &Path) -> Option<&Vec<String>> {
        let entry = self.cache.entry(path.to_path_buf()).or_insert_with(|| {
            let meta = std::fs::metadata(path).ok()?;
            if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
                return None;
            }
            let text = std::fs::read_to_string(path).ok()?;
            Some(text.lines().map(str::to_string).collect())
        });
        entry.as_ref()
    }
}

/// The lines to draw, and which of them the finding points at.
struct Window {
    /// 1-based line number of `lines[0]`.
    first: u32,
    marked: u32,
    marked_end: u32,
    lines: Vec<String>,
}

/// Accent colour for the marked line, by severity. Mirrors `severity_label`
/// in the audit output so a frame reads as part of the same finding.
fn accent(severity: &Severity, text: String) -> colored::ColoredString {
    match severity {
        Severity::Critical => text.red().bold(),
        Severity::High => text.red(),
        Severity::Medium => text.yellow(),
        Severity::Low => text.normal(),
        Severity::Info => text.dimmed(),
    }
}

/// Render the frame as lines of text. With `color` false the output is pure
/// ASCII: no escape codes, and `>` in place of the pointer glyph.
fn render(window: &Window, severity: &Severity, color: bool) -> Vec<String> {
    let last = window.first + window.lines.len() as u32 - 1;
    let width = last.to_string().len();
    let marker = if color { "▸" } else { ">" };

    window
        .lines
        .iter()
        .enumerate()
        .map(|(offset, raw)| {
            let number = window.first + offset as u32;
            let marked = number >= window.marked && number <= window.marked_end;
            let text = truncate(raw);
            let gutter = format!(
                "       {} {:>width$} |",
                if marked { marker } else { " " },
                number,
                width = width
            );
            // A blank source line prints as a bare gutter: no trailing
            // whitespace, so the output stays diff- and copy-paste-clean.
            if text.is_empty() {
                return if color {
                    format!("{}", gutter.dimmed())
                } else {
                    gutter
                };
            }
            if !color {
                return format!("{gutter} {text}");
            }
            if marked {
                format!("{} {}", accent(severity, gutter), accent(severity, text))
            } else {
                format!("{} {}", gutter.dimmed(), text.dimmed())
            }
        })
        .collect()
}

/// Trim a source line to a printable width, counting characters rather than
/// bytes so a multi-byte line is never cut mid-codepoint. Tabs become spaces
/// so the gutter stays aligned.
fn truncate(line: &str) -> String {
    let expanded = line.replace('\t', "    ");
    let expanded = expanded.trim_end();
    if expanded.chars().count() <= MAX_LINE_CHARS {
        return expanded.to_string();
    }
    let kept: String = expanded.chars().take(MAX_LINE_CHARS).collect();
    format!("{kept} ...")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window() -> Window {
        Window {
            first: 10,
            marked: 12,
            marked_end: 12,
            lines: vec![
                "fn a() {}".to_string(),
                "".to_string(),
                "let x = compare(a, b);".to_string(),
                "".to_string(),
                "fn b() {}".to_string(),
            ],
        }
    }

    #[test]
    fn plain_render_is_ascii_and_marks_the_line() {
        let out = render(&window(), &Severity::High, false);
        assert_eq!(out.len(), 5);
        assert!(!out.iter().any(|l| l.contains('\u{1b}')), "ANSI leaked");
        assert!(out[2].contains("> 12 | let x = compare(a, b);"));
        assert!(out[0].contains("  10 | fn a() {}"));
    }

    #[test]
    fn coloured_render_keeps_the_same_text() {
        let out = render(&window(), &Severity::Critical, true);
        assert!(out[2].contains("12"));
        assert!(out[2].contains("compare(a, b)"));
    }

    #[test]
    fn long_lines_are_truncated_on_character_boundaries() {
        let line = "é".repeat(MAX_LINE_CHARS + 50);
        let out = truncate(&line);
        assert_eq!(out.chars().count(), MAX_LINE_CHARS + 4);
        assert!(out.ends_with(" ..."));
    }

    #[test]
    fn missing_files_are_skipped_silently() {
        let mut frames = Frames::new();
        let finding = Finding {
            id: "x".into(),
            kind: verum_nucleus::FindingKind::PanicRisk,
            severity: Severity::Low,
            confidence: 1.0,
            file: PathBuf::from("/nonexistent/verum/does-not-exist.rs"),
            line_start: 3,
            line_end: 3,
            symbol: None,
            message: String::new(),
            suggestion: String::new(),
            auto_fixable: false,
            related: Vec::new(),
            fingerprint: String::new(),
        };
        assert!(frames.markdown(&finding).is_none());
        // A missing file is not an elision: it spends no budget and adds no
        // "frames were capped" note.
        assert!(frames.cap_note().is_none());
    }
}
