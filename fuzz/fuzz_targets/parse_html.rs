#![no_main]

//! Fuzzes the HTML front-end, which also drives inline-`<script>` extraction
//! into the JavaScript extractor - so a case here can reach two parsers and
//! the fragment-seeding logic between them.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let path = verum_fuzz::scratch_file("case.html", data.as_bytes());
    let _ = verum_mappa::html::parse_file(path);
});
