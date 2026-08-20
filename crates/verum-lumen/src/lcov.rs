//! Ingestion of an `lcov` coverage file produced by a real test run.
//!
//! Verum never runs a test suite and never emits coverage data. What it can do
//! is *read* the file a coverage tool already wrote (`cargo llvm-cov
//! --lcov`, `nyc`, `pytest-cov`, `gcov`, ...) and report the measured numbers
//! alongside its own static analysis - clearly labelled as measured, so it is
//! never confused with the static reachability upper bound in
//! [`crate::reachability`].
//!
//! Only the records that carry the facts are read:
//!
//! | record                  | meaning                                  |
//! |-------------------------|------------------------------------------|
//! | `SF:<path>`             | start of a file's section                |
//! | `DA:<line>,<hits>[,..]` | line `<line>` was executed `<hits>` times|
//! | `FN:<line>,<name>` or `FN:<start>,<end>,<name>` | a function |
//! | `FNDA:<hits>,<name>`    | that function was called `<hits>` times  |
//! | `end_of_record`         | end of a file's section                  |
//!
//! Summary records (`LF`/`LH`/`FNF`/`FNH`) are deliberately ignored and the
//! totals recomputed from `DA`/`FNDA`: a summary that disagrees with the
//! detail would otherwise decide the score. Every other record type (`TN`,
//! `BRDA`, `BRF`, ...) is skipped.
//!
//! Malformed input is an error, never a silent zero - a coverage file that
//! failed to parse must not read as "no coverage".
//!
//! Deterministic: files are emitted sorted by path, and a file that appears in
//! more than one section is merged by taking the highest hit count seen for
//! each line and function, so section order cannot change the totals.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::reachability::percent;

/// Measured coverage for one source file.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MeasuredFile {
    /// The path exactly as the coverage file records it.
    pub path: String,
    pub lines_found: usize,
    pub lines_hit: usize,
    pub line_percent: f32,
    pub functions_found: usize,
    pub functions_hit: usize,
    pub function_percent: f32,
}

/// Measured coverage for a whole run, as read from an `lcov` file.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MeasuredCoverage {
    /// Where the data came from, so a report can say so.
    pub source: String,
    /// The format ingested. Only `lcov` today; recorded so a future format is
    /// distinguishable in the JSON without a breaking change.
    pub format: String,
    pub lines_found: usize,
    pub lines_hit: usize,
    pub line_percent: f32,
    pub functions_found: usize,
    pub functions_hit: usize,
    pub function_percent: f32,
    /// Per file, ascending by path.
    pub files: Vec<MeasuredFile>,
}

/// What went wrong, and on which line, so the failure is actionable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LcovError {
    pub line_number: usize,
    pub line: String,
    pub reason: String,
}

impl std::fmt::Display for LcovError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "line {}: {} (in `{}`)",
            self.line_number, self.reason, self.line
        )
    }
}

impl std::error::Error for LcovError {}

/// Per-file accumulator. `BTreeMap` so merging is order-independent and the
/// output is sorted without a separate pass.
#[derive(Default)]
struct FileAccumulator {
    /// line number -> highest hit count seen.
    lines: BTreeMap<u32, u64>,
    /// function name -> highest hit count seen. A declared-but-never-called
    /// function is present with 0.
    functions: BTreeMap<String, u64>,
}

/// Parse the contents of an `lcov` file.
pub fn parse(text: &str, source: &str) -> Result<MeasuredCoverage, LcovError> {
    let mut files: BTreeMap<String, FileAccumulator> = BTreeMap::new();
    let mut current: Option<String> = None;

    for (index, raw) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if line == "end_of_record" {
            current = None;
            continue;
        }
        let Some((record, value)) = line.split_once(':') else {
            // `end_of_record` is the only valid record without a colon.
            if line.starts_with('#') {
                continue;
            }
            return Err(err(line_number, raw, "not a `KEY:value` lcov record"));
        };

        match record {
            "SF" => {
                if value.is_empty() {
                    return Err(err(line_number, raw, "`SF` names no file"));
                }
                files.entry(value.to_string()).or_default();
                current = Some(value.to_string());
            }
            "DA" => {
                let acc = section(&mut files, &current, line_number, raw)?;
                let mut fields = value.split(',');
                let line_no = number::<u32>(fields.next(), line_number, raw, "`DA` line number")?;
                let hits = number::<u64>(fields.next(), line_number, raw, "`DA` hit count")?;
                let entry = acc.lines.entry(line_no).or_insert(0);
                *entry = (*entry).max(hits);
            }
            "FN" => {
                let acc = section(&mut files, &current, line_number, raw)?;
                // `FN:<line>,<name>` and the newer `FN:<start>,<end>,<name>`;
                // the name is always the last field, and a name may itself
                // contain commas (`Vec<A,B>::push`), so split from the front by
                // the known number of leading numeric fields.
                let name = fn_name(value, line_number, raw)?;
                acc.functions.entry(name).or_insert(0);
            }
            "FNDA" => {
                let acc = section(&mut files, &current, line_number, raw)?;
                let (hits_text, name) = value
                    .split_once(',')
                    .ok_or_else(|| err(line_number, raw, "`FNDA` needs `<hits>,<name>`"))?;
                let hits = number::<u64>(Some(hits_text), line_number, raw, "`FNDA` hit count")?;
                if name.is_empty() {
                    return Err(err(line_number, raw, "`FNDA` names no function"));
                }
                let entry = acc.functions.entry(name.to_string()).or_insert(0);
                *entry = (*entry).max(hits);
            }
            // Summary and branch records: recomputed or not modelled.
            _ => {}
        }
    }

    if files.is_empty() {
        return Err(LcovError {
            line_number: 0,
            line: String::new(),
            reason: "no `SF:` records - this is not an lcov file".to_string(),
        });
    }

    let mut coverage = MeasuredCoverage {
        source: source.to_string(),
        format: "lcov".to_string(),
        ..Default::default()
    };
    for (path, acc) in files {
        let lines_found = acc.lines.len();
        let lines_hit = acc.lines.values().filter(|hits| **hits > 0).count();
        let functions_found = acc.functions.len();
        let functions_hit = acc.functions.values().filter(|hits| **hits > 0).count();
        coverage.lines_found += lines_found;
        coverage.lines_hit += lines_hit;
        coverage.functions_found += functions_found;
        coverage.functions_hit += functions_hit;
        coverage.files.push(MeasuredFile {
            path,
            lines_found,
            lines_hit,
            line_percent: percent(lines_hit, lines_found),
            functions_found,
            functions_hit,
            function_percent: percent(functions_hit, functions_found),
        });
    }
    coverage.line_percent = percent(coverage.lines_hit, coverage.lines_found);
    coverage.function_percent = percent(coverage.functions_hit, coverage.functions_found);
    Ok(coverage)
}

fn err(line_number: usize, line: &str, reason: &str) -> LcovError {
    LcovError {
        line_number,
        line: line.to_string(),
        reason: reason.to_string(),
    }
}

/// The accumulator for the section currently open, or an error naming the
/// record that appeared outside one.
fn section<'a>(
    files: &'a mut BTreeMap<String, FileAccumulator>,
    current: &Option<String>,
    line_number: usize,
    raw: &str,
) -> Result<&'a mut FileAccumulator, LcovError> {
    let path = current
        .as_ref()
        .ok_or_else(|| err(line_number, raw, "record before any `SF:` file section"))?;
    Ok(files.entry(path.clone()).or_default())
}

fn number<T: std::str::FromStr>(
    field: Option<&str>,
    line_number: usize,
    raw: &str,
    what: &str,
) -> Result<T, LcovError> {
    let text = field.ok_or_else(|| err(line_number, raw, &format!("missing {what}")))?;
    text.trim()
        .parse::<T>()
        .map_err(|_| err(line_number, raw, &format!("{what} is not a number")))
}

/// The function name from an `FN` value, tolerating both the two-field and
/// three-field forms and names containing commas.
fn fn_name(value: &str, line_number: usize, raw: &str) -> Result<String, LcovError> {
    let (first, rest) = value
        .split_once(',')
        .ok_or_else(|| err(line_number, raw, "`FN` needs `<line>,<name>`"))?;
    number::<u32>(Some(first), line_number, raw, "`FN` line number")?;
    // Three-field form: a second purely-numeric field is the end line.
    let name = match rest.split_once(',') {
        Some((second, tail)) if !second.is_empty() && second.parse::<u32>().is_ok() => tail,
        _ => rest,
    };
    if name.is_empty() {
        return Err(err(line_number, raw, "`FN` names no function"));
    }
    Ok(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
TN:
SF:src/lib.rs
FN:3,parse_config
FN:11,unused_helper
FNDA:4,parse_config
FNDA:0,unused_helper
FNF:2
FNH:1
DA:3,4
DA:4,4
DA:5,0
DA:11,0
LF:4
LH:2
end_of_record
SF:src/main.rs
FN:1,10,main
FNDA:1,main
DA:1,1
DA:2,1
end_of_record
";

    #[test]
    fn parses_line_and_function_coverage() {
        let coverage = parse(SAMPLE, "lcov.info").expect("valid lcov");
        assert_eq!(coverage.format, "lcov");
        assert_eq!((coverage.lines_found, coverage.lines_hit), (6, 4));
        assert_eq!(coverage.line_percent, 66.7);
        assert_eq!((coverage.functions_found, coverage.functions_hit), (3, 2));
        assert_eq!(coverage.function_percent, 66.7);
    }

    #[test]
    fn reports_per_file_sorted_by_path() {
        let coverage = parse(SAMPLE, "lcov.info").expect("valid lcov");
        let paths: Vec<&str> = coverage.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, vec!["src/lib.rs", "src/main.rs"]);
        let lib = &coverage.files[0];
        assert_eq!((lib.lines_found, lib.lines_hit), (4, 2));
        assert_eq!(lib.line_percent, 50.0);
        assert_eq!((lib.functions_found, lib.functions_hit), (2, 1));
    }

    #[test]
    fn summary_records_never_override_the_detail() {
        // `LF`/`LH` here claim full coverage; the `DA` records say otherwise.
        let text = "SF:a.rs\nDA:1,0\nDA:2,0\nLF:2\nLH:2\nend_of_record\n";
        let coverage = parse(text, "x").expect("valid lcov");
        assert_eq!(coverage.lines_hit, 0);
        assert_eq!(coverage.line_percent, 0.0);
    }

    #[test]
    fn repeated_sections_merge_by_highest_hit_count() {
        // Two test binaries, each writing a section for the same file: the
        // line is covered if either run hit it, whichever order they appear.
        let forward = "SF:a.rs\nDA:1,0\nend_of_record\nSF:a.rs\nDA:1,3\nend_of_record\n";
        let reverse = "SF:a.rs\nDA:1,3\nend_of_record\nSF:a.rs\nDA:1,0\nend_of_record\n";
        let a = parse(forward, "x").expect("valid lcov");
        let b = parse(reverse, "x").expect("valid lcov");
        assert_eq!(a, b, "section order must not change the result");
        assert_eq!((a.lines_found, a.lines_hit), (1, 1));
    }

    #[test]
    fn function_names_may_contain_commas() {
        let text = "SF:a.rs\nFN:1,<Vec<A,B> as Trait>::push\nFNDA:2,<Vec<A,B> as Trait>::push\nend_of_record\n";
        let coverage = parse(text, "x").expect("valid lcov");
        assert_eq!((coverage.functions_found, coverage.functions_hit), (1, 1));
    }

    #[test]
    fn parse_errors_are_reported_not_swallowed() {
        let cases = [
            ("SF:a.rs\nDA:notanumber,1\nend_of_record\n", 2),
            ("SF:a.rs\nDA:1,notanumber\nend_of_record\n", 2),
            ("DA:1,1\n", 1),
            ("SF:a.rs\nFNDA:1\nend_of_record\n", 2),
            ("this is not lcov\n", 1),
        ];
        for (text, expected_line) in cases {
            let error = parse(text, "x").expect_err("must not parse");
            assert_eq!(error.line_number, expected_line, "for input {text:?}");
            assert!(!error.reason.is_empty());
        }
    }

    #[test]
    fn an_empty_file_is_an_error_not_zero_coverage() {
        let error = parse("", "x").expect_err("empty input is not coverage data");
        assert!(error.reason.contains("not an lcov file"), "{error}");
    }

    #[test]
    fn parsing_is_repeatable() {
        assert_eq!(
            parse(SAMPLE, "lcov.info").expect("valid"),
            parse(SAMPLE, "lcov.info").expect("valid")
        );
    }
}
