# Verum

[![CI](https://github.com/IBMark/verum/actions/workflows/ci.yml/badge.svg)](https://github.com/IBMark/verum/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/verum.svg)](https://crates.io/crates/verum)
[![docs.rs](https://img.shields.io/docsrs/verum)](https://docs.rs/verum)
[![Marketplace](https://img.shields.io/badge/Marketplace-Verum%20Code%20Analyzer-2088FF?logo=githubactions&logoColor=white)](https://github.com/marketplace/actions/verum-code-analyzer)
[![Glama](https://glama.ai/mcp/servers/IBMark/verum/badges/score.svg)](https://glama.ai/mcp/servers/IBMark/verum)

Verum is a deterministic, whole-program code analyzer. It maps a codebase into
a single intermediate representation - symbols, call graph, routes, data flows -
then runs a set of analyses over that map: dead code, duplicates, taint-based
security checks, complexity, naming, and infrastructure (Kubernetes, Dockerfile,
Terraform). It's a single static binary with no build step and no language
server, so it runs on a fresh checkout in a fraction of a second.

Same input, same output. Every symbol id, finding, and report is derived from a
stable hash of the source, so two runs on the same tree produce byte-identical
results. That makes Verum usable as a CI gate, a baseline you can diff against,
and a fact layer that tools and agents can rely on.

Supported languages: PHP, Rust, JavaScript, TypeScript, Python, Go, and Java,
plus Kubernetes YAML, Dockerfiles, and Terraform.

## Example

![verum audit on a vulnerable PHP fixture: dead code, security findings, and a score](assets/demo.gif)

## Install

```
cargo install verum                 # compile from crates.io
cargo binstall verum                 # or grab the prebuilt binary, no compile
docker run --rm -v "$PWD:/work" ghcr.io/ibmark/verum audit .   # or no install
```

Prebuilt binaries for Linux (gnu/musl), macOS (x86_64/arm64), and Windows are
attached to each [release](https://github.com/IBMark/verum/releases).

`cargo install` builds a `verum` binary on your PATH (Verum builds on stable Rust
1.82 or newer). To build from a checkout instead, use
`cargo install --path crates/verum`. For a static Linux binary you can copy
anywhere:

```
cargo build --release --target x86_64-unknown-linux-musl
```

The same crate is a library. Add `verum` as a dependency to parse a tree into
the IR and run the analyses programmatically:

```rust
use verum::{Atlas, AtlasConfig, Prism, Standard};

let ir = Atlas::new(AtlasConfig { root: ".".into(), ..Default::default() }).build()?;
let result = Prism::analyse(&ir, &Standard::default())?;
println!("score: {}", result.score.overall);
```

## Usage

```
verum analyse <path>    # map the code into the IR - symbol/call/route counts
verum audit <path>      # map + analyse - findings and a score, no changes
verum clean <path>      # audit + preview the dead-code/duplicate fixes
verum map <path>        # module/symbol graphs, cycles, SPOFs, data flows
verum gate <path>       # exit non-zero if the deploy-gate thresholds fail
verum baseline <path>   # snapshot findings so gate only fails on new ones
verum report <path>     # markdown | json | sarif | a self-contained html report
verum explain [kind]    # what a finding kind means, why it matters, how to fix it
verum init [path]       # write a default verum.standard.json
```

`audit` scores the code and lists findings by severity, and prints the offending
source line with two lines of context under each one. `clean` reports the fixes
it would apply - symbols with no caller, duplicate bodies to remap - and
identifies each by file and line. It runs report-only and does not modify your
files; treat its output as a worklist to apply by hand.

## Understanding a finding

`verum explain <kind>` prints what a detector looks for, the concrete
consequence of ignoring it, a flagged and a fixed example, and when suppressing
it is a defensible call. It takes the name as reported or its kebab alias:

```
verum explain NonConstantTimeComparison
verum explain non-constant-time-comparison
verum explain                    # every kind, one line each
```

The same entries, for every detector Verum has, are in
[docs/detectors.md](docs/detectors.md). That file is generated from the table
the command reads (`verum explain --all --format markdown`), so the docs and the
tool cannot disagree.

## Lines of code and test reachability

`report` counts every file - total, code, comment and blank lines - and rolls
the counts up per language and per top-level directory. Alongside them it walks
the resolved call graph from the test suite and reports, per file and overall,
how many functions a test provably reaches, plus the files that no test reaches
at all.

That number is **reachability, not coverage**. It says what the tests demonstrably
reach by name; it cannot see code driven through trait dispatch, generics or
macros, and a reachable function need not actually run. Verum never runs your
tests and never invents a coverage figure.

When you have measured coverage, hand it over and it supersedes the estimate:

```
verum report . --coverage lcov.info
```

The file is read in `lcov` format (`DA`/`FN`/`FNDA` records, as written by
`cargo llvm-cov --lcov`, `nyc`, `pytest-cov` or `gcov`). The measured numbers
appear in the report labelled as measured and replace reachability in the score.
A coverage file that does not parse is an error, never a silent zero.

## Continuous integration

`verum gate <path>` exits `1` when the deploy-gate thresholds fail and `0` when
they pass, so a pipeline can rely on the exit code rather than parsing output.
`verum report <path> --format json` emits the findings and score as JSON for a
dashboard or a custom check.

```yaml
# .github/workflows/verum.yml
name: verum
on: [push, pull_request]
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: IBMark/verum-action@v1   # runs `verum gate .` by default
```

On an existing codebase, snapshot the current findings once with
`verum baseline .` and commit the result; the gate then fails only on findings
that are *new* relative to that baseline, so you can adopt it without first
fixing everything it reports.

`verum report <path> --format sarif` emits SARIF 2.1.0, so findings show up as
inline pull-request annotations and in the repository's Security tab:

```yaml
      - run: verum report . --format sarif --out verum.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: verum.sarif
```

## Agent / MCP

`verum mcp <path>` serves the analysis as an MCP tool server over stdio, so an
agent can query the map instead of grepping. It exposes the call graph
(`callers_of`, `callees_of`, `impact_of`), `dead_code`, `duplicates`, `audit`,
`audit_delta` (findings only in files changed vs a git ref), and `endpoints`
(which client HTTP calls hit which routes). The map is re-checked against the
tree's mtimes on each call, so answers track your edits.

Any MCP-capable client can connect over stdio. For example, with Claude Code:

```
claude mcp add verum -- verum mcp /path/to/project
```

## For coding agents & CI

[`docs/agents.md`](docs/agents.md) is the command reference written to be read
in-context by an agent: one screen per command with when to use it, the exact
invocation, the JSON schema field by field, the exit codes, and a worked example
of real output. A test asserts every flag it documents against `--help`, so it
cannot drift from the CLI.

[`integrations/`](integrations/) holds ready-to-copy configuration for the
places code actually changes - a Claude Code `PostToolUse` hook and MCP
registration, a Cursor rule, a `pre-commit` hook, and a GitHub Actions workflow
that uploads SARIF and runs the gate. Every snippet is syntax-checked in CI.

## Cross-language

Verum parses every supported language into one IR, so a `fetch('/api/users')` in
a TypeScript frontend links to the route handler that serves it - even when that
handler is in another language. `verum mcp`'s `endpoints` tool reports the
matches, plus frontend calls that hit no route (likely 404s) and routes that no
client calls (possibly dead).

## Optional AI layer

`verum full` can send the *ambiguous* findings - the ones deterministic analysis
can't resolve on its own - to a language model for a keep/delete/deprecate
decision. It's provider-neutral: it speaks the OpenAI-compatible chat API and is
configured entirely through the environment, so it works with a hosted API or a
local runner (ollama, llama.cpp, vLLM, LM Studio). Nothing is contacted unless
you set an endpoint.

```
export VERUM_AI_ENDPOINT="http://localhost:11434/v1/chat/completions"
export VERUM_AI_MODEL="qwen2.5-coder"
verum full <path>
```

## Configuration

`verum init` writes `verum.standard.json` - analysis thresholds, per-language
naming rules, the weak-crypto allowlist, and the deploy-gate limits. Everything
has a sensible default, so the file is optional.

## How it works

```
files -> map (mappa) -> IR -> analyse (lumen) -> findings + score
                            -> plan (faber)    -> fix worklist
```

`mappa` parses files in parallel via tree-sitter and merges them into one IR.
Ids are a stable FNV-1a hash of the path, which keeps them reproducible and lets
files be parsed independently without a shared counter. `lumen` runs the
analyses over the merged IR; `faber` turns the safe findings into a concrete
list of edits (report-only in this release).

The workspace splits along that pipeline: `verum-nucleus` (shared IR and finding
types), `verum-mappa` (parsers), `verum-lumen` (analyses), `verum-faber` (fix
planner), `verum-arbiter` (optional AI layer), and `verum` (the binary and the
library facade).

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
