# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4] - 2026-08-19

### Fixed
False positives found by running the analyzer across ~90 real-world repositories:
- Taint: drop parameterized ORM/driver methods (`->query`, `.execute`, `db.query`)
  from the SQL sink list, skip interprocedural flows through ambiguously-named
  callees (a `sort()`/`count()` name-collision was reporting SQLi/path-traversal),
  and remove Express `res.send`/`res.write` from the XSS sinks.
- Length-prefix: recognize validation helpers and macros (`ensure_size!`,
  `validate_*`, `verify_*`, `require_*`, `assert!`, `bail!`) as bound checks, and
  treat counts read as 16 bits or fewer as bounded rather than unbounded
  allocations. IronRDP dropped from 20 findings to 2.
- Hardcoded secrets: treat web-asset directories (`public/`, `static/`, `assets/`,
  `plugins/`) and vendored code as auxiliary, and skip templated/interpolated
  values (`ADMIN_TOKEN='{hash}'`).
- Findings in a project's own test/fixture corpus are auxiliary again (the
  `fixtures` carve-out is scoped to Verum's own suite).
- `BlockingInAsync` no longer flags tokio's async `.lock().await`.

### Added
- `VERUM_PROFILE` environment variable prints per-pass timing to stderr.

## [0.1.3] - 2026-08-19

### Added
- SARIF 2.1.0 report output (`verum report --format sarif`), so findings can be
  uploaded to GitHub code scanning and surface as pull-request annotations and in
  the repository Security tab.
- Read-only / idempotent annotations on every MCP tool, so clients can safely
  auto-approve and cache the calls.
- `cargo binstall verum` support (fetches the prebuilt binary) and a published
  container image at `ghcr.io/ibmark/verum`.

## [0.1.2] - 2026-08-19

### Changed
- Link TLS with rustls instead of OpenSSL. OpenSSL cannot cross-compile for the
  musl and aarch64 Linux targets and blocks `cargo install` on Alpine; rustls
  removes the system dependency, so every release target builds and the crate
  installs everywhere.

## [0.1.1] - 2026-08-19

### Fixed
- Filter code-quality and security findings out of test, example, vendored, and
  generated files - they are not shipped code.
- Skip Go framework hooks (`init` and the standard interface methods) in
  dead-code analysis, and skip Go naming, whose MixedCaps rules a single
  cross-language convention cannot express.
- Drop argv from the Rust taint sources; a CLI acting on its own arguments is by
  design, not attacker input.
- Collapse duplicate findings reported at the same kind and location.

## [0.1.0] - 2026-08-19

### Added
- First public release. Deterministic, whole-program analysis for PHP, Rust,
  JavaScript, TypeScript, Python, Go, and Java, plus Kubernetes, Dockerfile, and
  Terraform.
- Analyses: dead code, duplicates, taint-based security, complexity, naming,
  dependency audit, and infrastructure checks.
- Three surfaces: the `verum` CLI, a library facade, and an MCP server.

[0.1.4]: https://github.com/IBMark/verum/releases/tag/v0.1.4
[0.1.3]: https://github.com/IBMark/verum/releases/tag/v0.1.3
[0.1.2]: https://github.com/IBMark/verum/releases/tag/v0.1.2
[0.1.1]: https://github.com/IBMark/verum/releases/tag/v0.1.1
[0.1.0]: https://crates.io/crates/verum/0.1.0
