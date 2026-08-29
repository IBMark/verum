//! Line-of-code metrics: per file, rolled up per language and per top-level
//! directory.
//!
//! Counting is line-based, the way `cloc` and friends do it, over the lines
//! [`ScanContext`] has already read for the other passes - no file is opened a
//! second time. Every line of every file falls into exactly one of three
//! buckets, so `code + comment + blank == total` always holds:
//!
//! * **blank**   - the line is empty after trimming (including inside a block
//!   comment: a blank line is blank wherever it sits);
//! * **comment** - the line carries only comment text;
//! * **code**    - anything else. A line with code *and* a trailing comment is
//!   code: it would still be there with the comment stripped.
//!
//! Comment syntax is chosen per language family: `//` plus `/* */` for the
//! C family (Rust, JS/TS, Go, Java, PHP, Terraform), `#` for Python, YAML
//! manifests and Dockerfiles, and PHP/Terraform additionally accept `#`.
//!
//! Known, deliberate limitation, shared with every line-based counter:
//! **Python docstrings count as code.** A `"""..."""` block is a string
//! expression, not comment syntax, and telling a module docstring from a
//! multi-line string assigned to a variable needs the parse tree rather than
//! the raw lines. Counting them as code never over-reports comments, which is
//! the direction that would flatter a codebase.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use verum_nucleus::{Ir, Language};

use crate::scan::ScanContext;

/// Line counts for one file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileLoc {
    /// Path relative to the analysed tree's root, `/`-separated.
    pub path: String,
    /// Language name as the IR labels it (`Rust`, `Python`, ...).
    pub language: String,
    pub total: u32,
    pub code: u32,
    pub comment: u32,
    pub blank: u32,
}

/// Line counts summed over a group of files - one language, or one top-level
/// directory.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocRollup {
    /// Language name, or top-level directory (`.` for files at the root).
    pub key: String,
    pub files: usize,
    pub total: u32,
    pub code: u32,
    pub comment: u32,
    pub blank: u32,
}

impl LocRollup {
    fn add(&mut self, file: &FileLoc) {
        self.files += 1;
        self.total += file.total;
        self.code += file.code;
        self.comment += file.comment;
        self.blank += file.blank;
    }
}

/// Per-file line counts plus the two rollups.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocReport {
    /// Every file in the IR, ascending by relative path.
    pub files: Vec<FileLoc>,
    /// Ascending by language name.
    pub by_language: Vec<LocRollup>,
    /// Ascending by top-level directory.
    pub by_directory: Vec<LocRollup>,
    /// The whole tree, under the key `TOTAL`.
    pub totals: LocRollup,
}

/// Count every file in `ir`, reusing the lines `ctx` already holds.
///
/// Deterministic: the per-file work is parallel but collected in the fixed,
/// sorted path order the paths were laid out in, and both rollups are emitted
/// sorted by key.
pub fn analyse(ir: &Ir, ctx: &ScanContext, root: Option<&Path>) -> LocReport {
    let root = resolve_root(ir, root);

    let mut paths: Vec<&PathBuf> = ir.files.keys().collect();
    paths.sort();

    let files: Vec<FileLoc> = paths
        .par_iter()
        .filter_map(|path| {
            let info = ir.files.get(*path)?;
            let lines = ctx.lines(path)?;
            let (code, comment, blank) = count_lines(&lines, syntax_for(&info.language));
            Some(FileLoc {
                path: relative_display(path, &root),
                language: format!("{:?}", info.language),
                total: code + comment + blank,
                code,
                comment,
                blank,
            })
        })
        .collect();

    let mut by_language: HashMap<String, LocRollup> = HashMap::new();
    let mut by_directory: HashMap<String, LocRollup> = HashMap::new();
    let mut totals = LocRollup {
        key: "TOTAL".to_string(),
        ..Default::default()
    };
    for file in &files {
        by_language
            .entry(file.language.clone())
            .or_insert_with(|| LocRollup {
                key: file.language.clone(),
                ..Default::default()
            })
            .add(file);
        let dir = top_level_dir(&file.path).to_string();
        by_directory
            .entry(dir.clone())
            .or_insert_with(|| LocRollup {
                key: dir,
                ..Default::default()
            })
            .add(file);
        totals.add(file);
    }

    let sorted = |map: HashMap<String, LocRollup>| {
        let mut out: Vec<LocRollup> = map.into_values().collect();
        out.sort_by(|a, b| a.key.cmp(&b.key));
        out
    };

    LocReport {
        files,
        by_language: sorted(by_language),
        by_directory: sorted(by_directory),
        totals,
    }
}

/// The directory report paths are shown relative to.
///
/// The analysed root when the caller supplied one and every file in the IR is
/// under it - canonicalized first, because the IR's paths are canonical while
/// the root a caller passes need not be (`.`), and the two must agree for a
/// relative path to come out right. Otherwise the longest common ancestor of
/// the IR's files, which is all the information available.
///
/// Deterministic: `all` over a `HashMap` and a longest-common-prefix fold are
/// both independent of iteration order.
pub fn resolve_root(ir: &Ir, root: Option<&Path>) -> PathBuf {
    if let Some(root) = root {
        let canonical = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
        if ir.files.keys().all(|path| path.starts_with(&canonical)) {
            return canonical;
        }
        // On Windows `canonicalize` returns a `\\?\`-prefixed verbatim path
        // while the IR walked the root as the caller spelled it, so the two
        // never prefix-match. Give the root as given the same chance before
        // the common-ancestor fallback swallows a shared directory (`src/`).
        if ir.files.keys().all(|path| path.starts_with(root)) {
            return root.to_path_buf();
        }
    }
    common_root(ir)
}

/// The longest directory prefix every file in the IR shares.
fn common_root(ir: &Ir) -> PathBuf {
    let mut iter = ir.files.keys();
    let Some(first) = iter.next() else {
        return PathBuf::new();
    };
    let mut prefix: Vec<Component> = first
        .parent()
        .map(|p| p.components().collect())
        .unwrap_or_default();
    for path in iter {
        let components: Vec<Component> = path.components().collect();
        let shared = prefix
            .iter()
            .zip(components.iter())
            .take_while(|(a, b)| a == b)
            .count();
        prefix.truncate(shared);
        if prefix.is_empty() {
            break;
        }
    }
    prefix.iter().collect()
}

/// `path` relative to `root`, `/`-separated so the output is identical on
/// Windows and Unix. Falls back to the full path when `path` is not under
/// `root`.
pub fn relative_display(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// The first path segment of a relative path; `.` for a file at the root.
fn top_level_dir(relative: &str) -> &str {
    match relative.split_once('/') {
        Some((dir, _)) => dir,
        None => ".",
    }
}

/// How a language family writes comments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommentSyntax {
    /// `//` line comments and `/* ... */` blocks. `hash` additionally accepts
    /// `#` line comments (PHP, Terraform); `single_quote_strings` is false for
    /// languages where `'` opens a char literal rather than a string (Rust,
    /// Go, Java), because a Rust lifetime (`&'a str`) is not a string start.
    CFamily {
        hash: bool,
        single_quote_strings: bool,
    },
    /// `#` line comments only.
    Hash,
    /// No comment syntax known - every non-blank line counts as code.
    Unknown,
}

fn syntax_for(language: &Language) -> CommentSyntax {
    match language {
        Language::Rust | Language::Go | Language::Java | Language::CSharp | Language::Cpp => {
            CommentSyntax::CFamily {
                hash: false,
                single_quote_strings: false,
            }
        }
        Language::JavaScript | Language::TypeScript => CommentSyntax::CFamily {
            hash: false,
            single_quote_strings: true,
        },
        Language::Php | Language::Terraform => CommentSyntax::CFamily {
            hash: true,
            single_quote_strings: true,
        },
        Language::Python | Language::Kubernetes | Language::Docker => CommentSyntax::Hash,
        // ML-family (`(* *)`) and Haskell (`-- {- -}`) comment counting is not
        // yet modelled; treated as code-only until their extractors refine it.
        Language::Ocaml | Language::Haskell | Language::Fstar | Language::Unknown => {
            CommentSyntax::Unknown
        }
    }
}

/// Classify every line as code, comment or blank. Returns
/// `(code, comment, blank)`; the three always sum to `lines.len()`.
fn count_lines(lines: &[String], syntax: CommentSyntax) -> (u32, u32, u32) {
    let (mut code, mut comment, mut blank) = (0u32, 0u32, 0u32);
    // Block comments span lines, so the state carries between iterations.
    let mut in_block = false;
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            blank += 1;
            continue;
        }
        let has_code = match syntax {
            CommentSyntax::Unknown => true,
            // Only a line that *starts* with `#` is a comment; `x = "#"` is
            // code, and so - deliberately - is a docstring.
            CommentSyntax::Hash => !trimmed.starts_with('#'),
            CommentSyntax::CFamily {
                hash,
                single_quote_strings,
            } => scan_c_line(trimmed, &mut in_block, hash, single_quote_strings),
        };
        if has_code {
            code += 1;
        } else {
            comment += 1;
        }
    }
    (code, comment, blank)
}

/// Walk one C-family line, updating the block-comment state, and report
/// whether any non-comment code sits on it.
///
/// String literals are skipped so a `/*` inside `"...\"/*\"..."` does not open
/// a phantom block comment that swallows the rest of the file.
fn scan_c_line(line: &str, in_block: &mut bool, hash: bool, single_quote: bool) -> bool {
    let bytes = line.as_bytes();
    let mut i = 0;
    let mut has_code = false;
    while i < bytes.len() {
        if *in_block {
            if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
                *in_block = false;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        match bytes[i] {
            b'/' if bytes.get(i + 1) == Some(&b'/') => return has_code,
            b'#' if hash => return has_code,
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                *in_block = true;
                i += 2;
            }
            b'"' => {
                has_code = true;
                i = skip_string(bytes, i, b'"');
            }
            b'\'' if single_quote => {
                has_code = true;
                i = skip_string(bytes, i, b'\'');
            }
            c => {
                if !c.is_ascii_whitespace() {
                    has_code = true;
                }
                i += 1;
            }
        }
    }
    has_code
}

/// Index just past the string literal opening at `start`, honouring backslash
/// escapes. An unterminated literal consumes the rest of the line.
fn skip_string(bytes: &[u8], start: usize, quote: u8) -> usize {
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            c if c == quote => return i + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(src: &str) -> Vec<String> {
        src.lines().map(str::to_string).collect()
    }

    fn c_family() -> CommentSyntax {
        CommentSyntax::CFamily {
            hash: false,
            single_quote_strings: false,
        }
    }

    #[test]
    fn rust_line_and_block_comments_are_comments() {
        let src = "\
// a line comment
fn main() {
    /* a block
       spanning lines */
    println!(\"hi\"); // trailing comment is still code

}
";
        let (code, comment, blank) = count_lines(&lines(src), c_family());
        assert_eq!(comment, 3, "the line comment plus both block lines");
        assert_eq!(code, 3, "fn, println, closing brace");
        assert_eq!(blank, 1);
    }

    #[test]
    fn code_after_a_block_comment_ends_counts_as_code() {
        let src = "\
/* opening
   still comment */ let x = 1;
";
        let (code, comment, blank) = count_lines(&lines(src), c_family());
        assert_eq!((code, comment, blank), (1, 1, 0));
    }

    #[test]
    fn a_comment_marker_inside_a_string_does_not_open_a_block() {
        // The regression this exists for: a phantom block comment swallows
        // every following line of the file.
        let src = "\
let pattern = \"/*\";
let a = 1;
let b = 2;
";
        let (code, comment, blank) = count_lines(&lines(src), c_family());
        assert_eq!((code, comment, blank), (3, 0, 0));
    }

    #[test]
    fn rust_lifetimes_are_not_string_literals() {
        let src = "fn f<'a>(s: &'a str) -> &'a str { s } // doc\n";
        let (code, comment, _) = count_lines(&lines(src), c_family());
        assert_eq!((code, comment), (1, 0));
    }

    #[test]
    fn python_hash_comments_and_docstrings() {
        let src = "\
# a comment
def f():
    \"\"\"A docstring.

    Still a docstring.
    \"\"\"
    return 1  # trailing
";
        let (code, comment, blank) = count_lines(&lines(src), CommentSyntax::Hash);
        assert_eq!(comment, 1, "only the leading # line is a comment");
        assert_eq!(code, 5, "docstrings count as code, by documented choice");
        assert_eq!(blank, 1);
    }

    #[test]
    fn php_accepts_hash_comments_too() {
        let src = "\
<?php
# hash comment
// slash comment
$x = 1; # trailing
";
        let syntax = CommentSyntax::CFamily {
            hash: true,
            single_quote_strings: true,
        };
        let (code, comment, blank) = count_lines(&lines(src), syntax);
        assert_eq!((code, comment, blank), (2, 2, 0));
    }

    #[test]
    fn hash_is_not_a_comment_in_the_c_family() {
        // `#include` / `#[derive]` are code, not comments.
        let src = "#[derive(Debug)]\nstruct S;\n";
        let (code, comment, _) = count_lines(&lines(src), c_family());
        assert_eq!((code, comment), (2, 0));
    }

    #[test]
    fn unknown_language_counts_every_non_blank_line_as_code() {
        let src = "something\n\n// not known to be a comment\n";
        let (code, comment, blank) = count_lines(&lines(src), CommentSyntax::Unknown);
        assert_eq!((code, comment, blank), (2, 0, 1));
    }

    #[test]
    fn buckets_always_sum_to_the_line_count() {
        let src = "\
/* block */
code();

// comment
";
        for syntax in [c_family(), CommentSyntax::Hash, CommentSyntax::Unknown] {
            let ls = lines(src);
            let (code, comment, blank) = count_lines(&ls, syntax);
            assert_eq!(code + comment + blank, ls.len() as u32, "{syntax:?}");
        }
    }

    #[test]
    fn top_level_dir_of_a_root_file_is_dot() {
        assert_eq!(top_level_dir("main.rs"), ".");
        assert_eq!(top_level_dir("src/main.rs"), "src");
        assert_eq!(top_level_dir("crates/verum/src/main.rs"), "crates");
    }
}
