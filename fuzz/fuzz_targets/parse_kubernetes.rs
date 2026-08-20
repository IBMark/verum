#![no_main]

//! Fuzzes the Kubernetes/YAML front-end. Covers both halves: `serde_yaml`
//! document parsing (anchors, aliases, tags, multi-document streams) and the
//! line scanner that runs alongside it.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let path = verum_fuzz::scratch_file("case.yaml", data.as_bytes());
    let _ = verum_mappa::kubernetes::parse_file(path);
});
