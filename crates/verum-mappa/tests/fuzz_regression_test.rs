//! Regression cases for crashes found by the fuzz targets in `fuzz/`.
//!
//! Every input here once panicked a front-end. The fuzzers need nightly and
//! are not part of the normal gate, so each finding is pinned by a plain test
//! as well as by a seed in `fuzz/seeds/`. The assertion is only "this returns
//! rather than panicking" - what the extractor makes of malformed source is
//! not contractual, but that it survives it is.

use std::path::{Path, PathBuf};

/// Write `source` to a uniquely named file under a per-test temp dir and hand
/// back the path. The front-ends all take a `&Path` and read it themselves.
fn write_case(name: &str, source: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "verum-fuzz-regression-{}-{}",
        std::process::id(),
        name
    ));
    std::fs::create_dir_all(&dir).expect("temp dir is creatable");
    let path = dir.join(name);
    std::fs::write(&path, source).expect("temp file is writable");
    path
}

/// `expand_use` looked for the closing `}` of a use-group with `rfind` over
/// the *whole* spec, so a stray `}` sitting before the `{` produced an
/// inverted byte range and panicked the slice. Malformed source reaches this
/// path easily: tree-sitter still reports a `use_declaration` for a `use` line
/// that ran into a string literal containing a brace.
#[test]
fn rust_use_group_with_brace_before_the_opening_one() {
    let source = concat!(
        "use stdb fname: {str) -> Self { Self { name: name.i(&self) -> String; }\n",
        "\n",
        "pub enum MFast, Slow }\n",
        "\n",
        "fn main() { leuse stdb\"z}\", c.name); }\n",
    );
    let path = write_case("case.rs", source);
    let _ = verum_mappa::rust_lang::parse_file(&path);
}

/// The same shape reduced to the one construct that matters, so the case
/// survives any future rewrite of the surrounding source.
#[test]
fn rust_use_group_minimal_inverted_braces() {
    for spec in [
        "use a\"}\"::{b};\n",
        "use }{;\n",
        "use }a::{b, c};\n",
        "use a::{b}}{;\n",
    ] {
        let path = write_case("minimal.rs", spec);
        let _ = verum_mappa::rust_lang::parse_file(&path);
    }
}

/// Every front-end must return rather than panic on an empty file and on a
/// file that is nothing but a truncated construct.
#[test]
fn every_front_end_survives_empty_and_truncated_input() {
    type ParseFn = fn(&Path) -> anyhow::Result<verum_nucleus::Ir>;
    let cases: &[(&str, ParseFn, &str)] = &[
        (
            "case.rs",
            verum_mappa::rust_lang::parse_file,
            "impl C { pub fn n(x: &str) -> Self { Self { na",
        ),
        (
            "case.py",
            verum_mappa::python::parse_file,
            "class S:\n    def __init__(self, name:\n",
        ),
        (
            "case.go",
            verum_mappa::go_lang::parse_file,
            "package main\n\nfunc (s *S) Serve(w http.ResponseWriter,",
        ),
        (
            "Case.java",
            verum_mappa::java::parse_file,
            "public class S {\n    public S(String n) { this.n =",
        ),
        (
            "case.php",
            verum_mappa::php::parse_file,
            "<?php\nclass C\n{\n    public function i(Request $r",
        ),
        (
            "Dockerfile",
            verum_mappa::dockerfile::parse_file,
            "FROM --platform=$TARGETOS/$TARGETARCH\n",
        ),
        (
            "case.tf",
            verum_mappa::terraform::parse_file,
            "resource \"aws_security_group\" \"o\" {\n  ingress {\n    cidr_blocks = [\"0.0.0.0/0\"\n",
        ),
        (
            "case.yaml",
            verum_mappa::kubernetes::parse_file,
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name:\n",
        ),
        (
            "case.html",
            verum_mappa::html::parse_file,
            "<html><body><script>function b(){return fetch(",
        ),
    ];

    for (name, parse, truncated) in cases {
        let empty = write_case(name, "");
        let _ = parse(&empty);
        let cut = write_case(name, truncated);
        let _ = parse(&cut);
    }
}
