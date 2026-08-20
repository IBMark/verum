# Verum for coding agents

Command reference written to be read in-context by an agent. Every example is
real output from the binary. Every documented flag is asserted against
`--help` by `crates/verum/tests/docs_test.rs`, so this file cannot drift from
the CLI.

## Invariants

- Same tree in, same findings out. Symbol ids and finding ids are stable hashes
  of the source, so two runs on an unchanged tree are byte-identical. You can
  diff runs; you can cache results keyed on the tree.
- Every command takes exactly one positional `<PATH>` - a directory. Analysis is
  whole-program over that directory; there is no per-file mode.
- `gate` and `full` exit `1` when the deploy gate fails. Every other command
  exits `0` unless it hit a real error (unreadable coverage file, unwritable
  `--out`), which also exits `1` with the reason on stderr. Nothing exits
  non-zero on findings alone.
- Logs and errors go to stderr, results to stdout. `2>/dev/null` is safe on
  every command as long as you still check the exit code.
- Speed: ~0.15s for 25k lines across 7 languages; sub-second below ~100k lines.
  Re-running after each edit is cheaper than deciding whether to re-run.

## Pick a command

| You want | Command |
|---|---|
| A pass/fail verdict for CI or a hook | `verum gate` |
| The list of what is wrong, for a human | `verum audit` |
| The list of what is wrong, to filter in code | `verum report --format json` |
| Findings in GitHub code scanning | `verum report --format sarif` |
| To adopt the gate without fixing everything first | `verum baseline`, once |
| To orient in unfamiliar code before editing | `verum map` |
| Counts only - is this tree even parsed? | `verum analyse` |
| A worklist of removable dead code and duplicates | `verum clean` |
| Interactive queries over the call graph | `verum mcp` |

---

## `verum gate`

WHEN TO USE: the only command whose exit code is a verdict - use it to decide
whether a change is finished, in a pre-commit hook, or as a CI job.

```
verum gate <PATH>
```

No flags beyond `-h`.

Exit codes:

- `0` - deploy gate passed.
- `1` - deploy gate failed; the reasons are printed after `Deploy gate: FAILED`.

Thresholds, from `verum.standard.json` if present, else these defaults:
`deploy_gate.min_overall_score` 85, `deploy_gate.min_security_score` 90,
`deploy_gate.max_critical_issues` 0. If `verum.baseline.json` exists the
thresholds are bypassed entirely and the gate instead fails only on *new*
High or Critical findings (see `verum baseline`).

Worked example:

```console
$ verum gate ./demo; echo "exit=$?"
  ✓  Dead code:    2 findings (get_user, unused_helper)
  ✓  Security:     1 findings
     ✗ CRITICAL: HardcodedSecret -- ./demo/src/app.py:3
  Score: 79/100
  ✗  Deploy gate: FAILED
     -> Overall score 79 < minimum 85
     -> Security score 85 < minimum 90
     -> Critical issues 1 > maximum 0
exit=1
```

---

## `verum audit`

WHEN TO USE: you want to see and read the findings. It never fails, so it is
for diagnosis, not for deciding you are done - use `gate` for that.

```
verum audit <PATH>
```

No flags beyond `-h`.

Exit code: always `0`, findings or not.

Output is human-formatted text on stdout: file/line/symbol counts, then a
section per analysis (dead code, duplicates, security, infrastructure,
performance signals, test reachability), then `Score: N/100`. Findings past the
first few per section collapse to `... N more (see report/map)` - for the
complete set use `report --format json`.

Worked example:

```console
$ verum audit ./demo
  ✓  1 files, ~13 lines, ~2 symbols
  ✓  Dead code:    2 findings (get_user, unused_helper)
  ✓  Duplicates:   0 groups
  ✓  Security:     1 findings
     ✗ CRITICAL: HardcodedSecret -- ./demo/src/app.py:3
  Score: 79/100
```

---

## `verum report`

WHEN TO USE: you need the findings as data - to filter them in code, to upload
them to code scanning, or to hand a human a document.

```
verum report <PATH> --format json
verum report <PATH> --format sarif --out verum.sarif
```

Flags:

- `--format <FORMAT>` - `markdown` (default) | `json` | `sarif` | `html`.
  An unrecognised value falls back to markdown rather than erroring.
- `--out <OUT>` - write to this file instead of stdout.
- `--coverage <FILE>` - read measured coverage from an lcov file. Replaces the
  static test-reachability estimate in the score, and is labelled as measured.
  A file that does not parse is an error, never a silent zero.

Exit codes: `0` normally; `1` only when `--coverage` cannot be read or parsed,
or `--out` cannot be written. Never `1` for findings.

### `--format json` schema

Top level:

| Field | Type | Meaning |
|---|---|---|
| `score_before`, `score_after` | object | Identical for `report`; both are the scores of the tree as it is. |
| `lines_before`, `lines_after` | int | Total lines; identical for `report`. |
| `passes` | int | Fix passes applied - always `0` for `report`. |
| `findings` | array | Every finding. See below. |
| `auto_fixed`, `ai_decisions` | int | Always `0` for `report`. |
| `human_review` | int | Findings the analyzer could not resolve on its own. |
| `duplicate_groups` | array | `{ canonical, duplicates[], similarity, call_sites_to_remap[], confidence }`, symbols as ids. |
| `duration_ms` | int | Map time. Not deterministic - exclude it before diffing runs. |
| `deploy_gate_passed` | bool | What `verum gate` would return. |
| `deploy_gate_reasons` | array of string | Empty when passed. |
| `loc` | object | `files[]`, `by_language[]`, `by_directory[]`, `totals`. |
| `test_reachability` | object | `test_roots`, `functions`, `reachable`, `percent`, `files[]`, `files_without_reachable_functions[]`. |

`score_before` / `score_after` fields, each `0`-`100`: `security`,
`architecture`, `performance`, `naming`, `complexity`, `test_coverage`,
`ui_consistency`, `journey_coverage`, `visual_accuracy`, `infrastructure`,
`compliance`, `overall`.

Each element of `findings`:

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Stable across runs. `dead-<name>`, `sec-secret-<file>:<line>`, etc. |
| `kind` | string | `HardcodedSecret`, `SqlInjection`, `DeadFunction`, `DeadClass`, `DeadFile`, `UnreachableCode`, `Duplicate*`, `PanicRisk`, `BlockingInAsync`, ... |
| `severity` | string | `Critical` \| `High` \| `Medium` \| `Low` \| `Info`. |
| `confidence` | float | `0.0`-`1.0`. Dynamic dispatch lowers dead-code confidence. |
| `file` | string | As given: relative if you passed a relative `<PATH>`. |
| `line_start`, `line_end` | int | 1-based, inclusive. |
| `symbol` | int \| null | Symbol id, when the finding is about one. |
| `message` | string | What is wrong. |
| `suggestion` | string | What to do about it. |
| `auto_fixable` | bool | Whether `clean` could plan a fix for it. |
| `related` | array | Related finding ids. |

Worked example:

```console
$ verum report ./demo --format json | jq '.deploy_gate_passed, (.findings[] | "\(.severity) \(.kind) \(.file):\(.line_start)")'
false
"Critical HardcodedSecret src/app.py:3"
"Medium DeadFunction src/app.py:6"
"Medium DeadFunction src/app.py:12"
```

### `--format sarif`

SARIF 2.1.0: `runs[0].results[]` with `ruleId` (the finding kind), `level`
(`error` for Critical, `warning` below), `message.text`, and
`locations[0].physicalLocation` carrying `artifactLocation.uri` and
`region.startLine` / `region.endLine`.

The `uri` inherits the `<PATH>` you passed. Pass `.` from the repository root -
code scanning can only place inline annotations on repo-relative URIs, and an
absolute path uploads cleanly while annotating nothing.

```console
$ cd repo && verum report . --format sarif | jq -r '.runs[0].results[0] | .ruleId, .level, .locations[0].physicalLocation.artifactLocation.uri'
HardcodedSecret
error
src/app.py
```

---

## `verum baseline`

WHEN TO USE: once, when adopting the gate on a codebase that does not pass it
yet - so the gate blocks new problems without demanding you fix the old ones.

```
verum baseline <PATH>
```

No flags beyond `-h`.

Exit code: always `0`.

Writes `verum.baseline.json` in `<PATH>`. Commit it. A fingerprint is
`kind|relative/path|message-with-digits-stripped`, so a finding survives being
moved down a file but a genuinely new one does not match. Advisory kinds -
daisychains, Rust perf insights, `CrateApiMisuse`, `ParseFailure` - are excluded
from both the snapshot and the comparison.

Once the file exists, `verum gate` stops applying score thresholds and fails
only on new `Critical` or `High` findings. Do not edit or delete it to make a
gate pass; regenerate it deliberately when you have fixed a batch.

Worked example:

```console
$ verum baseline ./demo && cat ./demo/verum.baseline.json
  ✓  Baseline written: 3 findings snapshotted to verum.baseline.json
{"count":3,"fingerprints":["DeadFunction|src/app.py|Dead code: `get_user` is never called", ...],"version":1}
$ verum gate ./demo; echo "exit=$?"
  ->  Baseline active: 3 known finding(s) waived, 0 new
  ✓  Deploy gate: PASSED (no new High/Critical findings)
exit=0
```

---

## `verum analyse`

WHEN TO USE: to confirm the tree parsed at all, or to get symbol/call/route
counts without paying for analysis.

```
verum analyse <PATH>
```

No flags beyond `-h`.

Exit code: always `0`. Mapping only - no findings, no score.

Worked example:

```console
$ verum analyse ./demo
  ✓  1 files, ~13 lines, ~2 symbols
     Calls: 3, Routes: 0, Entry points: 0
     Build time: 0ms
```

---

## `verum map`

WHEN TO USE: before editing unfamiliar code - what depends on what, where the
cycles and single points of failure are, which routes exist.

```
verum map <PATH>
verum map <PATH> --format json
```

Flags:

- `--format <FORMAT>` - `text` (default) | `json` | `html` (interactive explorer).
- `--profile <PROFILE>` - perf lens: `latency` | `throughput` | `memory` | `cpu` |
  `realtime` | `all` (default).
- `--out <OUT>` - write to this file instead of stdout.

Exit code: always `0`.

`--format json` top-level keys: `version`, `generated_epoch`, `root`, `meta`,
`modules`, `module_edges`, `seam_edges`, `cycles`, `symbols`, `sym_edges`,
`unresolved_calls`, `chains`, `taints`, `routes`, `analytics`, `perf`.
`generated_epoch` is wall-clock; exclude it before diffing runs.

Worked example:

```console
$ verum map ./demo
  -> System map - 1 modules, 2 symbols, 3 calls (0 resolved, 3 unresolved)
  -> Architecture analytics:
     call-graph depth 0, module-graph depth 0, 1 communities
     0 layering violations, 0 single-point-of-failure modules, 2 unreachable symbols
```

---

## `verum clean`

WHEN TO USE: you want the worklist of dead code and duplicate bodies that could
be removed. Report-only in this release - it does not modify files.

```
verum clean <PATH>
```

Flags:

- `--dry-run` - explicit report-only. Currently the behaviour either way; pass
  it if you want the intent recorded in a script.

Exit code: always `0`.

Worked example:

```console
$ verum clean ./demo
  -> Report only - no files will be modified
  ✓  Before: 1 files, ~13 lines, ~2 symbols
  ✓  Forge: 1 passes, 0 symbols removed, 6 lines removed
  ✓  Dead code:    2 findings (get_user, unused_helper)
  Score: 79/100
```

---

## `verum mcp`

WHEN TO USE: your client speaks MCP and you want to query the map
interactively - callers, callees, blast radius - instead of re-running a whole
report and grepping it.

```
verum mcp [PATH]
```

No flags beyond `-h`. `PATH` is optional and defaults to `.`.

Speaks newline-delimited JSON-RPC 2.0 on stdin/stdout; it does not return. The
map is re-fingerprinted against file mtimes on every call, so answers track
edits made mid-session. Every tool is annotated read-only and idempotent.

Tools: `overview`, `find_symbol`, `definition_of`, `references_of`,
`callers_of`, `callees_of`, `impact_of`, `dead_code`, `duplicates`, `audit`,
`audit_delta`, `endpoints`, `perf_advice`.

Register it with Claude Code:

```console
$ claude mcp add verum -- verum mcp .
```

---

## `verum init`

WHEN TO USE: you need to change a threshold, a naming rule, or the weak-crypto
allowlist. Everything has a default, so the file is optional.

```
verum init [PATH]
```

No flags beyond `-h`. `PATH` is optional and defaults to `.`.

Exit code: always `0`. Writes `verum.standard.json`.

---

## `verum full`

WHEN TO USE: essentially never in an automated loop - it is the only
non-deterministic command. It sends findings the analyzer could not resolve to
a language model, and contacts nothing unless `VERUM_AI_ENDPOINT` is set.

```
verum full <PATH>
```

Flags:

- `--dry-run` - report what would change without modifying any file.

Exit codes: `0` if the deploy gate passed, `1` if it failed - same rule as
`gate`.

---

## Gotchas

- A path Verum cannot read is not an error. It reports `0 files`, scores
  `100/100`, and exits `0`. A hook pointed at the wrong directory therefore
  passes forever - check the file count, not just the exit code.
- An unrecognised `--format` silently renders markdown. There is no error.
- `verum audit` truncates long finding lists in its text output. Counts in the
  section headers are exact; the listing is not. Use `report --format json` when
  you need every finding.
- `duration_ms` (JSON report) and `generated_epoch` (JSON map) are wall-clock.
  Everything else is deterministic; strip those two before diffing two runs.
- Findings inherit the path form you passed. Pass `.` for repo-relative output,
  which is what SARIF upload and most tooling wants.
- `test_coverage` in the score is *reachability* - what the tests provably
  reach through the resolved call graph - unless you supplied `--coverage`.
  It is not a claim that the code ran.
