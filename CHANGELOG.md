# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Python/TypeScript/JavaScript security parity.** The app-security
  detectors that used to be PHP-first now cover the languages most new
  services ship in:
  - `HardcodedSecret` also fires on provider-shaped token literals
    (`sk_live_`, `AKIA`, `ghp_`, `github_pat_`, `xoxb-`/`xoxp-`, `glpat-`,
    and PEM private-key blocks with actual key material) regardless of the
    variable name, with env-read, template-interpolation, placeholder, and
    pattern-table exclusions.
  - `WeakCrypto` also fires on `crypto.createHash('md5'|'sha1')` - only when
    the line's identifiers carry a sensitive word (password, token, secret,
    ...), so cache keys and etags stay silent.
  - `WeakRandom` now has an emitting detector: `Math.random()` /
    `random.random()`/`randint`/`getrandbits` feeding a value whose name
    says password/secret/token/otp/nonce/salt. Word-component matching, so a
    parser's `tokens` never matches `token`.
  - `NonConstantTimeComparison` extends from Rust to Python and JS/TS,
    including `===`/`!==` and camelCase identifier splitting
    (`computedSignature === header` is the canonical webhook miss), with
    `hmac.compare_digest`/`crypto.timingSafeEqual`/`hash_equals` recognized
    as safe, and new metadata guards (`signature.length == 64`,
    `digest_size == 32` stay silent) applied across all languages.
  - `EvalUsage` also fires on bare Python `exec(` with a non-literal
    argument (method calls like PyQt's `dialog.exec()` are excluded).
- **`TlsVerificationDisabled` (High).** `rejectUnauthorized: false`,
  `NODE_TLS_REJECT_UNAUTHORIZED=0`, `verify=False` on a `requests`/`httpx`
  call, `ssl._create_unverified_context()`, `verify_mode = ssl.CERT_NONE`.
- **`UnsafeDeserialization` (High).** `pickle.load(s)` on non-literal input,
  `yaml.load` without a safe loader, `yaml.unsafe_load`, and `new Function`
  built from non-literal text.
- All of the above verified against the 22-repo false-positive corpus with
  zero new findings.

## [0.1.6] - 2026-08-20

### Added
- **`verum check` - the machine verdict.** One command shaped for a tool loop:
  analyse and print a single JSON verdict (`pass`, severity counts, findings
  each carrying a one-sentence `why` and a concrete `fix_hint`) with stable
  exit codes (0 pass, 1 fail at/above `--fail-on`, 2 operational error).
  Fix hints for dead code and duplicates come from the fix planner's actual
  plan (symbol, exact lines, safe-to-delete verdict); every other kind has a
  concrete remediation template. ~0.2s on a 56k-line tree. With `VERUM_STATS=1`,
  one local JSON line per invocation (never code text) is appended to
  `$VERUM_STATS_FILE` for adoption metrics.
- **Stable finding fingerprints.** Every finding carries a `fingerprint` -
  a stable hash of kind, repo-relative path, symbol, and digit-stripped
  message - that survives edits elsewhere in the file and the repo living at
  a different path. Also emitted as SARIF `partialFingerprints`.
- **Baseline mode.** `gate --baseline` and `report --baseline` compare against
  a previous report (or the minimal file `verum baseline` writes) by
  fingerprint and partition findings into new/existing/resolved; the gate then
  fails only on new High/Critical findings, so a legacy codebase can adopt the
  gate without first fixing its inherited debt. Missing or corrupt baselines
  are loud errors, never an empty comparison.
- **Inline suppressions.** `verum:ignore` / `verum:ignore[Kind,...] reason` on
  the finding line or the line above waives it, per language comment syntax.
  Suppressed findings leave the score and gate but are counted
  (`suppressed_count`, `--show-suppressed`), and a suppression that matches
  nothing becomes a Low `StaleSuppression` finding so waivers cannot rot.
- Fuzzing harnesses for every language front-end (13 libFuzzer targets, seed
  corpora committed, opt-in via `cargo fuzz`, not part of default builds).
- CI now builds and tests on macOS and Windows alongside Linux.

### Fixed
- **`gate` and `check` fail closed on an empty analysis.** An unreadable,
  empty, or mistyped path used to analyse zero files, score 100, and pass -
  so a typo'd hook path waved every change through. Zero analysable files is
  now an operational error.
- Robustness against hostile input, ahead of scanning untrusted repositories
  at scale: a file that panics an extractor or analysis pass becomes a Low
  `ParseFailure` diagnostic instead of killing the run; recursive AST walks
  are depth-capped so pathological nesting cannot overflow the stack (a 10k-
  paren expression aborted the process before); overlong generated lines and
  unbounded tracked state are cut off by fixed, deterministic input-size
  limits - never wall-clock timeouts. Two fuzzer-found crashes fixed (a
  malformed Rust use-group slice panic, an inverted-span underflow in the
  line passes), each with its reproducer committed as a seed and a regression
  test.
- Path matching is now separator-portable: every `/`-delimited path check
  (vendored-code exclusion, test-file detection, the auto-fix delete guard,
  framework entry-point detection) normalizes `\` first, so Windows analyses
  match Linux instead of silently skipping the checks.
- Go generic calls (`GetState[T](x)`, `pkg.Fn[T](x)`) now produce call edges;
  functions only ever invoked through generic instantiation were reported
  dead. On the corpus this removes two long-standing false positives in fiber.
- **The test-coverage score dimension no longer reports 100 unconditionally.** A
  repository without a single test used to score full marks on it. It is now
  driven by static test-reachability: 0 when no test suite is found, rising
  linearly to 100 at 35% of shipped functions reachable from a test (calibrated
  against the pinned corpus, where well-tested repos measure 11-35%). The
  dimension is reported but stays out of the weighted `overall`, so no existing
  score moves.

### Added
- `verum explain <kind>` documents every finding kind Verum can report: what the
  detector looks for, the concrete consequence of leaving it, a flagged and a
  fixed example, and when suppressing it is reasonable. It accepts the name as
  reported (`NonConstantTimeComparison`) or its kebab alias
  (`non-constant-time-comparison`), case-insensitively; with no argument it
  lists every kind with a one-line summary, and an unknown kind suggests the
  closest names. Entries come from one table in the code, so `docs/detectors.md`
  is generated (`verum explain --all --format markdown`) and a test fails if the
  two drift apart.
- Source frames in the human-readable output: `audit` and the markdown report now
  print the finding's line with two lines of context either side, line-numbered
  and marked, coloured by severity. `NO_COLOR` (or a non-tty stdout) drops the
  colour and uses ASCII markers; frames are capped at the first 50 findings per
  run, with a note when the cap applies. The JSON and SARIF reports are
  unchanged.
- `docs/agents.md`, a machine-oriented command reference written to be read
  in-context by a coding agent: one screen per command with when to use it, the
  exact invocation, the JSON schema field by field, the exit codes, and a worked
  example of real output. A test asserts every flag it documents against
  `--help` in both directions, so the reference cannot drift from the CLI.
- `integrations/`, ready-to-copy configuration for wiring Verum into the places
  code changes: a Claude Code `PostToolUse` hook (plus `.mcp.json` registration),
  a Cursor rule, a `pre-commit` hook, and a GitHub Actions workflow that uploads
  SARIF to code scanning and runs the gate. Every snippet is syntax-checked in
  CI and asserted to invoke commands that exist.
- Line-of-code metrics in `report`: total, code, comment and blank lines per
  file, rolled up per language and per top-level directory, with an nyc-style
  per-file table in the markdown report and a `loc` section in the JSON.
- Static test-reachability in `report` and `audit`: which functions the test
  suite provably reaches through the resolved call graph, per file and overall,
  and the files that no test reaches at all. This is reachability, not coverage -
  it is an estimate of what the tests can reach, never a claim about what ran.
  Exposed as a `test_reachability` section in the JSON report.
- `verum report --coverage <file>` ingests measured coverage from an `lcov` file
  a real test run produced (`DA`/`FN`/`FNDA` records). The measured numbers are
  reported as measured, appear as `measured_coverage` in the JSON, and replace
  the static reachability estimate in the score dimension. A file that does not
  parse fails loudly with the offending line, rather than reading as zero
  coverage. Verum still never runs tests and never emits coverage data.

### Changed
- Dependencies moved to current majors, most notably tree-sitter 0.26 with the
  current grammar releases for all seven languages. Corpus-verified: findings
  byte-identical on 21 of 22 pinned repos; the 22nd only improves (the Go
  generics fix above).

### Performance
- Roughly 3x faster and 38% less peak memory than 0.1.5 on large trees (ruff:
  ~6.8s to ~2.3s, 1.10GB to 0.68GB), from an audited set of algorithmic fixes:
  chains precomputes per-edge sink/gate classification instead of recomputing
  it five million times, duplicates sorts its call-site buckets once instead
  of per member, per-file regexes are compiled once, the resolver memoizes
  repeated (name, file) lookups and drops SipHash for FxHash, the independent
  analysis passes run concurrently, the tree is walked once (gitignore-aware,
  with early binary/size skips) and read once, release builds use thin LTO,
  and the JSON report streams to its destination instead of building a
  hundreds-of-MB String first. Output byte-identical throughout, verified
  against golden reports and the corpus after every step.

## [0.1.5] - 2026-08-19

### Changed
- **Scores are recalibrated.** The size-sensitive penalties (dead code,
  duplicates, naming, complexity) now measure issue *density* — each saturates
  when its finding class touches 10% of the codebase's symbols — instead of raw
  finding count, which pinned every repo beyond a few hundred symbols to the
  same cap. Healthy large repos now score 88–96 (previously bunched at 83–85)
  and very large codebases are no longer punished for their size alone. All
  scores shift with this release; re-baseline any `verum gate` thresholds.

### Added
- Two Rust crypto-hygiene detectors: `NonConstantTimeComparison` (Medium) flags
  `==`/`!=` on secret-bearing values (HMACs, signatures, secrets, digests, and
  compounds like `auth_tag`/`access_token`) and suggests
  `subtle::ConstantTimeEq`; `StaticAeadNonce` (High) flags a constant nonce/IV
  literal reaching `.encrypt(`/`.seal(`/`Nonce::from_slice(`, staying quiet on
  CSPRNG-filled nonces. Word choice is calibrated against the FP corpus: one
  finding total across its 22 pinned repos.
- An opt-in false-positive regression corpus (`corpus/`): 22 well-known repos
  pinned to exact SHAs, a committed findings-by-kind baseline, and a `--diff`
  mode that fails on any drift. Not part of default CI (it clones over the
  network); see `corpus/README.md`.

### Fixed
- Two determinism bugs: Rust `impl` targets whose type name collides across
  modules resolved by `HashMap` iteration order (hash-seed dependent, visible
  as run-to-run drift in `verum map` and occasional `GodClass` count flips);
  now broken deterministically by earliest declaration. Test temp dirs built
  from the process id alone collided across parallel test threads — the source
  of intermittent CI test failures — and are now unique per test.

### Performance
- The three line-scanning passes (taint, transport, rust_insights) share one
  parallel whole-tree read and one per-file symbol index instead of each
  re-scanning every symbol per file (the per-file lookup was quadratic).
  Large-repo analysis drops accordingly: ruff 166s → 12.8s, laravel/framework
  ~104s → ~13s. Findings are byte-identical.

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

[0.1.6]: https://github.com/IBMark/verum/releases/tag/v0.1.6
[0.1.5]: https://github.com/IBMark/verum/releases/tag/v0.1.5
[0.1.4]: https://github.com/IBMark/verum/releases/tag/v0.1.4
[0.1.3]: https://github.com/IBMark/verum/releases/tag/v0.1.3
[0.1.2]: https://github.com/IBMark/verum/releases/tag/v0.1.2
[0.1.1]: https://github.com/IBMark/verum/releases/tag/v0.1.1
[0.1.0]: https://crates.io/crates/verum/0.1.0
