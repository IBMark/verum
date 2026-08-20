#![no_main]

//! Fuzzes `cfg_test_ranges`, the brace-counting scanner that every line pass
//! runs first to blank out inline `#[cfg(test)]` items. It is pure line and
//! index arithmetic over unbalanced input, so it gets its own target rather
//! than being reached only incidentally.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let lines: Vec<String> = data.lines().map(str::to_string).collect();
    let _ = verum_lumen::fuzz_api::cfg_test_ranges(&lines);
});
