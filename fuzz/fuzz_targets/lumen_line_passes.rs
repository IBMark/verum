#![no_main]

//! Fuzzes `verum-lumen`'s per-file line detectors - `security`, `taint`,
//! `transport`, `crypto_hygiene` and `rust_insights` - straight on a synthetic
//! line array. No parser and no filesystem sit in front of them here, so a
//! crash is unambiguously the detector's.
//!
//! Case layout, so seeds can be written by hand: one byte of language, one
//! byte of path variant, eight bytes of function spans (four big-endian-ish
//! `u16`s decoded by `arbitrary`), then the file text, split on newlines.
//! The spans are deliberately unconstrained - zero, inverted, or past the end
//! of the file are all reachable from a truncated parse, and all reach the
//! detectors through the IR.

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;

use verum_lumen::fuzz_api::{self, FuzzFile};

#[derive(Arbitrary, Debug)]
struct Case<'a> {
    language: u8,
    path_variant: u8,
    spans: [(u16, u16); 2],
    source: &'a str,
}

fuzz_target!(|case: Case| {
    let language = fuzz_api::language_from_byte(case.language);
    let file = FuzzFile {
        path: fuzz_api::path_for(&language, case.path_variant),
        lines: case.source.lines().map(str::to_string).collect(),
        language,
        fn_spans: case
            .spans
            .iter()
            .map(|(a, b)| (*a as u32, *b as u32))
            .collect(),
    };
    let _ = fuzz_api::run_line_passes(&file);
});
