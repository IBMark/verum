#![no_main]

//! Fuzzes the Python front-end end to end: source in, IR or a clean `Err` out,
//! never a panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let path = verum_fuzz::scratch_file("case.py", data.as_bytes());
    let _ = verum_mappa::python::parse_file(path);
});
