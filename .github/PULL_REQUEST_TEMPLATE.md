<!-- Describe what this change does and why. -->

## Summary

## Checklist

- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] New or changed detectors include a test that fires and one that must not
- [ ] Analysis stays deterministic (no time, RNG, or hash-order dependence)
