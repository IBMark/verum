# Integrations

Ready-to-copy configuration for wiring Verum into the places code actually
changes. Every file here is syntax-checked by `crates/verum/tests/docs_test.rs`,
so what is in the repository is what parses.

One adoption decision each: after the copy, the verdict arrives on its own -
on every edit, every commit, or every pull request - with nobody having to
remember to ask for it.

For the command reference these configs call into, see
[`docs/agents.md`](../docs/agents.md).

---

## `claude-code/`

**`settings.json`** - a `PostToolUse` hook that runs `verum gate` over the
project after every `Edit`, `Write`, `MultiEdit` or `NotebookEdit`. Merge the
`hooks` key into `.claude/settings.json` (project) or `~/.claude/settings.json`
(all projects).

The command is a one-liner rather than a bare `verum gate` on purpose:

```sh
out=$(verum gate "$CLAUDE_PROJECT_DIR" 2>&1) || { printf '%s\n' "$out" >&2; exit 2; }
```

A hook that exits `0` is invisible to the agent - its output only reaches the
transcript. Exit `2` is the code that feeds stderr back to the model, so this
wrapper stays silent while the gate passes and hands the agent the failure
reasons the moment it does not.

**`verum-hook.sh`** - the same logic as an installable script, for when you want
to extend it (scope the analysis to a subdirectory, skip on a branch, and so
on). Copy to `.claude/hooks/verum-hook.sh`, `chmod +x`, and set the hook command
to `"$CLAUDE_PROJECT_DIR/.claude/hooks/verum-hook.sh"`.

**Repo-size expectations.** Verum re-analyses the whole tree on every hook fire,
which is affordable because a run is a fraction of a second: this repository
(~25k lines, 7 languages) audits in ~0.15s on a laptop, and trees under ~100k
lines stay comfortably sub-second. Past a few hundred thousand lines, point the
hook at the subtree you are working in rather than the repository root, or move
the check to `pre-commit`.

**MCP.** `mcp.json` is a project-scoped `.mcp.json` that registers the fact
layer as a tool server, so the agent can query the call graph instead of
grepping. Copy it to the repository root, or register it with one line:

```sh
claude mcp add verum -- verum mcp .
```

---

## `cursor/`

**`verum.mdc`** - a rule file for `.cursor/rules/verum.mdc`. `alwaysApply: true`
puts it in context for every request; the body tells the agent to run
`verum gate .` before concluding, what each exit code means, which commands to
reach for while working, and - importantly - not to make the gate pass by
editing `verum.baseline.json` or lowering the thresholds in
`verum.standard.json`.

---

## `pre-commit/`

**`.pre-commit-config.yaml`** - a `repo: local` hook running `verum gate .`.
Merge the `repos` entry into your existing config.

```sh
pre-commit install
```

`pass_filenames: false` is deliberate. Verum is a whole-program analyzer - dead
code and cross-file taint are only decidable over the whole tree - so the
`files:` pattern decides *whether* the hook runs, while the analysis always
covers the repository. pre-commit stashes unstaged work first, so the tree
Verum sees is exactly the tree being committed.

Verum also publishes itself as a hook repository, so you can point at it instead
of vendoring the definition:

```yaml
repos:
  - repo: https://github.com/IBMark/verum
    rev: v0.1.5
    hooks:
      - id: verum-gate
```

The published hook uses `always_run: true`; the local copy here runs only when a
source file is staged. Both are `language: system` and need `verum` on PATH.

**Fail behaviour:** a failing gate exits `1`, which aborts the commit and prints
the reasons. `git commit --no-verify` bypasses it. Adopting on an existing
codebase without first fixing everything: run `verum baseline .` once, commit
`verum.baseline.json`, and the gate then fails only on findings introduced after
that snapshot.

---

## `github-actions/`

**`verum.yml`** - copy to `.github/workflows/verum.yml`. Two independent jobs:

- **`sarif`** installs Verum (`cargo binstall verum || cargo install verum`),
  runs `verum report . --format sarif --out verum.sarif`, and uploads it with
  `github/codeql-action/upload-sarif@v3`. Findings land in the Security tab and
  as inline pull-request annotations. Needs `security-events: write`.
- **`gate`** runs `verum gate .` and fails the job on a non-zero exit.

They are separate so a red gate never suppresses the findings list.

Run Verum against `.`, not an absolute path: SARIF locations inherit the path
you pass, and code scanning can only place inline annotations on repo-relative
ones. An absolute path uploads cleanly and annotates nothing.

If you would rather not manage the install step, the published action does it
for you:

```yaml
- uses: IBMark/verum-action@v1   # runs `verum gate .` by default
```
