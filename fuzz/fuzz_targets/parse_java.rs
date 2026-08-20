#![no_main]

//! Fuzzes the Java front-end end to end: source in, IR or a clean `Err` out,
//! never a panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let path = verum_fuzz::scratch_file("Case.java", data.as_bytes());
    let _ = verum_mappa::java::parse_file(path);
});
