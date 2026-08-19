# Contributing to Verum

Thanks for taking the time to contribute.

## Building

Verum is a standard Cargo workspace. You need a recent stable Rust toolchain.

```
cargo build --workspace
cargo test --workspace
```

## Before opening a pull request

CI runs formatting, lints, a build, and the test suite, all denying warnings.
Run the same checks locally so your PR goes green on the first try:

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

If `clippy` flags something on a newer toolchain than yours, run
`rustup update stable` first - the CI uses the current stable.

## Guidelines

- Keep analysis deterministic. The same input tree must always produce the same
  ids, findings, and score; nothing may depend on wall-clock time, iteration
  order of a hash map, or the environment.
- New findings need test coverage, including a case that must *not* fire, so a
  detector cannot regress into false positives.
- Match the style of the surrounding code. `cargo fmt` settles formatting.
- Keep commits focused and write a clear message explaining the why.

## Reporting bugs and requesting features

Open an issue using the templates. For security issues, see
[SECURITY.md](SECURITY.md) instead of the public tracker.

## License

By contributing you agree that your contributions are dual-licensed under the
MIT and Apache-2.0 licenses that cover this project.
