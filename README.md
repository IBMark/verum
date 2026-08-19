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

```
$ verum audit tests/fixtures/php_security

  ✓  1 files, ~36 lines, ~6 symbols

  ✓  Dead code:    5 findings (getUser, login, render, runScript, getSecret)
  ✓  Duplicates:   0 groups
  ✓  Security:     5 findings
     ✗ CRITICAL: SqlInjection      vulnerable.php:8
     ✗ CRITICAL: WeakCrypto        vulnerable.php:15
     ✗ HIGH:     XssVulnerability  vulnerable.php:22
     ✗ CRITICAL: EvalUsage         vulnerable.php:28
     ✗ CRITICAL: HardcodedSecret   vulnerable.php:33

  Score: 72/100
```

## Install

```
cargo install verum
```

This puts a `verum` binary on your PATH (Verum builds on stable Rust 1.82 or
newer). To build from a checkout instead, use `cargo install --path crates/verum`.
To run against any Linux box without a toolchain, build a static musl binary and
copy it across:

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
verum report <path>     # markdown | json | a self-contained html report
verum init [path]       # write a default verum.standard.json
```

`audit` scores the code and lists findings by severity. `clean` reports the
fixes it would apply - symbols with no caller, duplicate bodies to remap - and
identifies each by file and line. It runs report-only and does not modify your
files; treat its output as a worklist to apply by hand.

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
