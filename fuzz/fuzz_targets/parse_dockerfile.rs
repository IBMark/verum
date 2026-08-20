#![no_main]

//! Fuzzes the Dockerfile front-end: a regex-driven line scanner, so the
//! interesting failures are slicing and index arithmetic rather than grammar
//! recursion.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let path = verum_fuzz::scratch_file("Dockerfile", data.as_bytes());
    let _ = verum_mappa::dockerfile::parse_file(path);
});
