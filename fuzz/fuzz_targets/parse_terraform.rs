#![no_main]

//! Fuzzes the Terraform front-end: a regex-driven line scanner with block
//! nesting state, so unbalanced braces and truncated blocks are the payload.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let path = verum_fuzz::scratch_file("case.tf", data.as_bytes());
    let _ = verum_mappa::terraform::parse_file(path);
});
