# FP-regression corpus

A reusable, opt-in harness that runs Verum against ~20 well-known open-source
repositories and tracks how many findings of each kind it reports on each one.
Its only job is to catch a **false-positive regression**: a detector change
that suddenly makes Verum noisier on real, idiomatic code it was previously
quiet on.

This is not correctness testing (that's what the unit tests in each crate
are for) and it is not wired into CI - it clones real repositories over the
network, which is slow and non-hermetic, so it only runs when you ask for it.

## What's here

- `manifest` - the list of repos, one per line: `name group sha url`. Every
  repo is pinned to a commit SHA, never a branch or tag, because the whole
  point is a byte-identical input tree run over run.
- `run.py` - clones each pinned repo into a temp dir, runs the release
  `verum report <dir> --format json` over it, tallies findings by `kind`,
  deletes the clone, and either writes `snapshot.json` or diffs against it.
- `snapshot.json` - the committed baseline: per repo, the finding count by
  kind and the overall score, as of the manifest's current pins and the
  current state of `verum-lumen`'s detectors.

## Running it

You need a release `verum` binary. From the repo root:

```
cargo build --release -p verum
```

Then, from the repo root:

```
# Regenerate corpus/snapshot.json from a fresh run over every repo in the manifest.
python3 corpus/run.py

# Compare a fresh run against the committed corpus/snapshot.json without
# overwriting it. Exits 0 if nothing moved, 1 if any count changed.
python3 corpus/run.py --diff
```

Useful flags (both modes):

- `--only ripgrep,serde` - run a subset of the manifest, for fast iteration
  while working on a single detector.
- `--manifest path/to/other-manifest` - use a different manifest file.

`run.py` uses only the Python standard library (no pip install needed) and
picks up the binary from, in order: the `VERUM_BIN` environment variable,
`target/release/verum` relative to the repo root, or `verum` on `PATH`.

Each repo is fetched with `git init && git remote add && git fetch --depth 1
origin <sha> && git checkout FETCH_HEAD`, which pulls down exactly the one
pinned commit (no history, no other branches) into a `tempfile.mkdtemp()`
directory. The directory is removed again as soon as that repo's report has
been generated, whether it succeeded or not - nothing is left behind, and
nothing here touches this repository's own git history or working tree.

A full run clones and audits 22 repositories, including some large ones
(tokio, tree-sitter, hickory-dns); expect it to take several minutes and to
use real bandwidth. `--only` is your friend if you just want a quick sanity
check.

Very large monorepos can also legitimately exceed `run.py`'s per-repo
analysis timeout (900s) rather than fail outright - that's why symfony
was swapped for the smaller slimphp/Slim in the manifest. Prefer a
representative-but-tractable repo over the biggest one available.

## Interpreting a `--diff` run

For every repo in the manifest, `--diff` prints every finding kind whose
count changed since the baseline, plus any change to the overall score:

```
~ ripgrep:
    PanicRisk: 103 -> 118 (+15)
    score_overall: 83 -> 81
```

- A **kind count going up** on a repo that previously had zero (or very few)
  of that kind is the signal this harness exists to catch: go read the new
  findings on that repo and confirm they're real, not noise from a detector
  that's now too aggressive.
- A **kind count going down** is usually a genuine false-positive fix -
  worth a quick sanity check that nothing real was silenced along with it.
- `+ name: new repo in manifest` / `- name: repo removed from manifest` means
  the manifest and `snapshot.json` are out of sync - regenerate the baseline
  (see below).
- `! name: run failed this time` means the clone or the `verum report` run
  itself errored (network issue, moved repo, binary crash) - this is a hard
  failure, not a finding-count regression; investigate before trusting the
  rest of the diff for that repo.

`--diff` exits non-zero if anything changed, so it's suitable as a manual
gate (e.g. run it after any change to a detector, before opening a PR) even
though it isn't wired into automated CI.

## Updating the baseline

After a detector change that deliberately adds, removes, or reshapes
findings, regenerate the baseline and commit it alongside the code change:

```
cargo build --release -p verum
python3 corpus/run.py
git add corpus/snapshot.json
git commit -m "..."
```

Review the diff in `snapshot.json` itself (or run `--diff` against the old
baseline first, before regenerating) so the commit message can say *why*
each count moved - that history is what makes this harness useful later.

## Bumping a pin

Repos move; occasionally you'll want to pull in a newer commit (e.g. to pick
up a rename that was breaking the clone, or just to keep the corpus fresh).
Resolve the new SHA and update the manifest line:

```
git ls-remote https://github.com/BurntSushi/ripgrep.git HEAD
```

then regenerate the baseline as above. Bumping a pin can change finding
counts on its own (the repo's source changed, not just Verum), so don't
mix a pin bump with a detector change in the same commit if you can help it.

## Adding a repo

Add a line to `manifest` with a name, a group tag (`rust`, `web`, `parsers`,
or `network` - loose, only used to group results, not enforced), a pinned
SHA, and a `git`-fetchable URL, then regenerate the baseline. Prefer repos
that are real, idiomatic, widely-used code in their language/domain - the
value of this corpus is entirely in how representative it is of code Verum
will actually be run against.
