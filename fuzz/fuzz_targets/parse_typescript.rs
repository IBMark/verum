#![no_main]

//! Fuzzes the TypeScript extractor over both grammars it can select: plain TS
//! and TSX. The leading `bool` picks which, because the choice is made from
//! the file extension and TSX is a materially different grammar (JSX elements,
//! and the type-assertion syntax it gives up to get them).

use libfuzzer_sys::fuzz_target;
use std::path::Path;

fuzz_target!(|input: (bool, &str)| {
    let (tsx, source) = input;
    let path = if tsx {
        Path::new("fuzz/case.tsx")
    } else {
        Path::new("fuzz/case.ts")
    };
    let _ = verum_mappa::javascript::parse_source(source, path, true, None);
});
