#![no_main]

//! Fuzzes the JavaScript extractor. Goes through `parse_source`, the
//! in-memory entry point `parse_file` delegates to, so no filesystem is
//! involved and every case is pure grammar plus extraction.

use libfuzzer_sys::fuzz_target;
use std::path::Path;

fuzz_target!(|data: &str| {
    let _ = verum_mappa::javascript::parse_source(data, Path::new("fuzz/case.js"), false, None);
});
