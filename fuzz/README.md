# Fuzzing Verum's front-ends

Verum is built to point at repositories nobody vetted first. Every language
front-end therefore has to treat its input as hostile: a truncated file, a
minified one-liner, an identifier made of astral-plane codepoints, an
expression nested a thousand deep. These targets exist to make "it must not
panic" a property that gets tested rather than asserted.

`fuzz/` is a **separate crate with its own workspace**, deliberately not a
member of the root workspace. `cargo build`, `cargo test`, `cargo clippy` and
`cargo fmt` at the repo root do not see it, do not build libFuzzer, and do not
need nightly. Fuzzing is entirely opt-in.

## Setup

`cargo-fuzz` drives libFuzzer, which needs a nightly toolchain:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Running

From this directory:

```sh
cargo +nightly fuzz list                # the targets
cargo +nightly fuzz run parse_rust      # run one, until you stop it
```

Give a target the committed seeds as a second, read-only corpus so new finds
land in `corpus/` (ignored) and the seeds (committed) stay as they are:

```sh
mkdir -p corpus/parse_rust
cargo +nightly fuzz run parse_rust corpus/parse_rust seeds/parse_rust -- \
  -max_total_time=120 -max_len=8192 -timeout=25
```

Useful libFuzzer flags, after the `--`:

| Flag | Why |
| --- | --- |
| `-max_total_time=N` | bound the session to N seconds |
| `-max_len=N` | cap case size; the front-ends are line-oriented, so large cases mostly add cost |
| `-timeout=N` | a case taking longer than N seconds is a hang, and a hang at fleet scale is an outage |
| `-rss_limit_mb=N` | catch runaway allocation on pathological nesting |
| `-jobs=N -workers=N` | parallel sessions |

On some hosts LeakSanitizer cannot start (`LeakSanitizer has encountered a
fatal error` before the first case runs) - it needs `ptrace`, which container
runtimes and hardened kernels often deny. Leak detection is not what these
targets are for, so turn it off:

```sh
ASAN_OPTIONS=detect_leaks=0 cargo +nightly fuzz run parse_rust corpus/parse_rust
```

Throughput varies by two orders of magnitude between targets, and that is
expected rather than a sign something is stuck. The tree-sitter front-ends run
at a few thousand cases a second; `lumen_cfg_test_ranges`, which is pure line
arithmetic, runs at tens of thousands. The infrastructure front-ends
(`parse_dockerfile`, `parse_terraform`, `parse_kubernetes`) manage only tens,
because each `parse_file` call compiles its regex set from scratch - so give
them a longer wall clock to reach comparable depth.

## When a target crashes

libFuzzer writes the input to `artifacts/<target>/`. Reproduce and minimize it:

```sh
cargo +nightly fuzz run parse_rust artifacts/parse_rust/crash-<hash>
cargo +nightly fuzz tmin parse_rust artifacts/parse_rust/crash-<hash>
```

Then fix it the same way every other bug here gets fixed:

1. Add the minimized input to `seeds/<target>/` under a name that says what it
   is, so the case is fuzzed forever after.
2. Add a plain `#[test]` regression case next to the code that broke, so the
   fix is enforced by `cargo test` in normal CI - the fuzzer is not CI, and a
   regression must not need nightly to catch.
3. Fix the extractor, minimally and at the point of the fault.

## The targets

| Target | Entry point | Notes |
| --- | --- | --- |
| `parse_rust` | `verum_mappa::rust_lang::parse_file` | |
| `parse_python` | `verum_mappa::python::parse_file` | |
| `parse_javascript` | `verum_mappa::javascript::parse_source` | in-memory, no temp file |
| `parse_typescript` | `verum_mappa::javascript::parse_source` | leading byte picks TS vs TSX - two different grammars |
| `parse_go` | `verum_mappa::go_lang::parse_file` | |
| `parse_java` | `verum_mappa::java::parse_file` | |
| `parse_php` | `verum_mappa::php::parse_file` | |
| `parse_dockerfile` | `verum_mappa::dockerfile::parse_file` | regex line scanner |
| `parse_terraform` | `verum_mappa::terraform::parse_file` | regex line scanner with block nesting |
| `parse_kubernetes` | `verum_mappa::kubernetes::parse_file` | `serde_yaml` documents plus a line scan |
| `parse_html` | `verum_mappa::html::parse_file` | also reaches the JS extractor via inline `<script>` |
| `lumen_line_passes` | `verum_lumen::fuzz_api::run_line_passes` | `security`, `taint`, `transport`, `crypto_hygiene`, `rust_insights` on a synthetic line array |
| `lumen_cfg_test_ranges` | `verum_lumen::fuzz_api::cfg_test_ranges` | brace counting over unbalanced input |

The `lumen_*` targets go through `verum-lumen`'s `fuzz_api` module, which is
behind the crate's off-by-default `fuzzing` feature. It builds the smallest
`Ir` and `ScanContext` that make the per-file passes scan lines held in memory,
so those detectors are fuzzed as the pure functions they are - no parser and no
filesystem in front of them to blur where a crash came from.

## Seeds

`seeds/<target>/` holds small, committed starting points - each under 1 KB.
Per language they cover: a valid file, an empty file, a truncated construct,
unicode identifiers and string escapes, a deeply nested expression, and a
minified one-liner, plus whatever that grammar makes uniquely awkward (PHP
heredocs, TSX's generic-vs-JSX ambiguity, YAML anchors and multi-document
streams, Dockerfile line continuations).

Two targets take structured input rather than raw source, so their seeds carry
a small binary header:

- `parse_typescript`: one byte, low bit set selects the TSX grammar, then the
  source.
- `lumen_line_passes`: language byte, path-variant byte, then four `u16`s
  giving two function line spans, then the source. The spans are deliberately
  allowed to be zero, inverted, or past the end of the file - a truncated parse
  produces exactly those, and they reach the detectors through the IR.

## Not part of CI

These targets are not run by the repo's normal checks, and are not required to
pass before a commit. What *is* required is that every crash a session finds
leaves behind a seed and a `#[test]`, so the fix is defended by the normal gate.
