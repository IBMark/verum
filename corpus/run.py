#!/usr/bin/env python3
"""Deterministic false-positive regression harness for Verum.

Clones every repo listed in corpus/manifest at its pinned commit into a
temporary directory, runs the release `verum` binary's `report --format
json` over it, tallies findings by kind, and either:

  * writes corpus/snapshot.json (the baseline), or
  * (--diff) compares a fresh run against corpus/snapshot.json and reports
    every count that moved, exiting non-zero if anything changed.

This never touches the workspace's git history or working tree: every clone
happens in its own `tempfile.mkdtemp()` directory that is removed again
before the script exits, win or lose. Nothing here is wired into CI - it
clones ~20 third-party repositories over the network, which is slow and
non-hermetic, so it is opt-in only. See corpus/README.md.

Usage:
    python3 corpus/run.py                  # run + write corpus/snapshot.json
    python3 corpus/run.py --diff           # run + compare against snapshot.json
    python3 corpus/run.py --only ripgrep,serde   # limit to a subset (fast iteration)
    python3 corpus/run.py --out /tmp/x.json      # write elsewhere instead of snapshot.json
    VERUM_BIN=/path/to/verum python3 corpus/run.py   # use a specific binary
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

CORPUS_DIR = Path(__file__).resolve().parent
REPO_ROOT = CORPUS_DIR.parent
MANIFEST_PATH = CORPUS_DIR / "manifest"
SNAPSHOT_PATH = CORPUS_DIR / "snapshot.json"


@dataclass
class RepoEntry:
    name: str
    group: str
    sha: str
    url: str


@dataclass
class RepoResult:
    group: str
    sha: str
    url: str
    score_overall: int | None
    total_findings: int
    by_kind: dict[str, int] = field(default_factory=dict)
    error: str | None = None


def parse_manifest(path: Path) -> list[RepoEntry]:
    entries: list[RepoEntry] = []
    seen: set[str] = set()
    for lineno, raw in enumerate(path.read_text().splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 4:
            raise ValueError(
                f"{path}:{lineno}: expected 'name group sha url', got: {raw!r}"
            )
        name, group, sha, url = parts
        if name in seen:
            raise ValueError(f"{path}:{lineno}: duplicate repo name {name!r}")
        seen.add(name)
        entries.append(RepoEntry(name=name, group=group, sha=sha, url=url))
    return entries


def find_verum_bin() -> Path:
    override = os.environ.get("VERUM_BIN")
    if override:
        p = Path(override)
        if not p.is_file():
            raise SystemExit(f"VERUM_BIN={override} does not exist")
        return p

    candidate = REPO_ROOT / "target" / "release" / "verum"
    if candidate.is_file():
        return candidate

    on_path = shutil.which("verum")
    if on_path:
        return Path(on_path)

    raise SystemExit(
        "could not find a `verum` binary - build one first:\n"
        "  cargo build --release -p verum\n"
        "or point VERUM_BIN at an existing binary."
    )


def clone_at_sha(entry: RepoEntry, dest: Path) -> None:
    """Fetch exactly one commit (no history, no other refs) into `dest`."""
    dest.mkdir(parents=True, exist_ok=True)
    run = lambda *args: subprocess.run(  # noqa: E731
        ["git", "-C", str(dest), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    run("init", "-q")
    run("remote", "add", "origin", entry.url)
    try:
        run("fetch", "--depth", "1", "--no-tags", "origin", entry.sha)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"git fetch failed for {entry.name} ({entry.url} @ {entry.sha}): "
            f"{exc.stderr.strip()}"
        ) from exc
    run("checkout", "-q", "FETCH_HEAD")


def run_verum_report(verum_bin: Path, target: Path) -> dict:
    proc = subprocess.run(
        [str(verum_bin), "report", str(target), "--format", "json"],
        capture_output=True,
        text=True,
        timeout=900,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"`verum report {target} --format json` exited {proc.returncode}: "
            f"{proc.stderr.strip()[-2000:]}"
        )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"could not parse verum JSON output: {exc}") from exc


def tally_findings(report: dict) -> tuple[Counter, int, int | None]:
    findings = report.get("findings", [])
    counts = Counter(f["kind"] for f in findings)
    score_overall = report.get("score_after", {}).get("overall")
    return counts, len(findings), score_overall


def process_repo(verum_bin: Path, entry: RepoEntry) -> RepoResult:
    tmpdir = Path(tempfile.mkdtemp(prefix=f"verum-corpus-{entry.name}-"))
    try:
        clone_at_sha(entry, tmpdir)
        report = run_verum_report(verum_bin, tmpdir)
        counts, total, score = tally_findings(report)
        return RepoResult(
            group=entry.group,
            sha=entry.sha,
            url=entry.url,
            score_overall=score,
            total_findings=total,
            by_kind=dict(sorted(counts.items())),
        )
    except Exception as exc:  # noqa: BLE001 - reported per-repo, run continues
        return RepoResult(
            group=entry.group,
            sha=entry.sha,
            url=entry.url,
            score_overall=None,
            total_findings=0,
            by_kind={},
            error=str(exc),
        )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def result_to_json(r: RepoResult) -> dict:
    d = {
        "group": r.group,
        "sha": r.sha,
        "url": r.url,
        "score_overall": r.score_overall,
        "total_findings": r.total_findings,
        "by_kind": r.by_kind,
    }
    if r.error is not None:
        d["error"] = r.error
    return d


def do_run(entries: list[RepoEntry], verum_bin: Path) -> dict:
    results: dict[str, dict] = {}
    had_error = False
    for i, entry in enumerate(entries, start=1):
        print(f"[{i}/{len(entries)}] {entry.name} ({entry.group}) @ {entry.sha[:12]}...",
              file=sys.stderr, flush=True)
        result = process_repo(verum_bin, entry)
        if result.error:
            had_error = True
            print(f"  ERROR: {result.error}", file=sys.stderr)
        else:
            print(f"  {result.total_findings} findings, score {result.score_overall}",
                  file=sys.stderr)
        results[entry.name] = result_to_json(result)

    return {
        "repos": dict(sorted(results.items())),
        "_had_error": had_error,
    }


def write_snapshot(data: dict, out_path: Path) -> None:
    payload = {"repos": data["repos"]}
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def diff_mode(fresh: dict, baseline_path: Path, filtered: bool) -> int:
    if not baseline_path.is_file():
        print(f"no baseline at {baseline_path} - run without --diff first", file=sys.stderr)
        return 2

    baseline = json.loads(baseline_path.read_text())
    baseline_repos: dict = baseline.get("repos", {})
    fresh_repos: dict = fresh["repos"]

    changed = False

    # With --only, `fresh_repos` is intentionally a subset of the manifest -
    # baseline entries outside that subset were never meant to run, so they
    # are neither "new" nor "removed"; only compare what was actually run.
    all_names = sorted(set(fresh_repos) if filtered else set(baseline_repos) | set(fresh_repos))
    for name in all_names:
        old = baseline_repos.get(name)
        new = fresh_repos.get(name)

        if old is None:
            print(f"+ {name}: new repo in manifest (not in baseline)")
            changed = True
            continue
        if new is None:
            print(f"- {name}: repo removed from manifest (was in baseline)")
            changed = True
            continue

        if new.get("error"):
            print(f"! {name}: run failed this time: {new['error']}")
            changed = True
            continue
        if old.get("error"):
            print(f"! {name}: baseline had recorded an error, now succeeds")
            changed = True
            # fall through and still compare counts below

        old_kinds: dict = old.get("by_kind", {})
        new_kinds: dict = new.get("by_kind", {})
        all_kinds = sorted(set(old_kinds) | set(new_kinds))
        repo_changed_kinds = []
        for kind in all_kinds:
            ocount = old_kinds.get(kind, 0)
            ncount = new_kinds.get(kind, 0)
            if ocount != ncount:
                delta = ncount - ocount
                sign = "+" if delta > 0 else ""
                repo_changed_kinds.append(f"    {kind}: {ocount} -> {ncount} ({sign}{delta})")

        old_score = old.get("score_overall")
        new_score = new.get("score_overall")
        score_line = None
        if old_score != new_score:
            score_line = f"    score_overall: {old_score} -> {new_score}"

        if repo_changed_kinds or score_line:
            changed = True
            print(f"~ {name}:")
            for line in repo_changed_kinds:
                print(line)
            if score_line:
                print(score_line)

    if not changed:
        print("no changes: fresh run matches corpus/snapshot.json")
        return 0

    print("\nfindings drifted from the committed baseline.")
    print("If this is an intentional detector change, regenerate the baseline:")
    print("  python3 corpus/run.py")
    print("and commit the updated corpus/snapshot.json alongside the detector change.")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--diff", action="store_true",
        help="compare a fresh run against corpus/snapshot.json instead of writing it",
    )
    parser.add_argument(
        "--only", default=None,
        help="comma-separated subset of repo names to run (default: all)",
    )
    parser.add_argument(
        "--out", type=Path, default=None,
        help="write the snapshot here instead of corpus/snapshot.json (run mode only)",
    )
    parser.add_argument(
        "--manifest", type=Path, default=MANIFEST_PATH,
        help="path to the manifest file (default: corpus/manifest)",
    )
    args = parser.parse_args()

    entries = parse_manifest(args.manifest)
    if args.only:
        wanted = set(args.only.split(","))
        entries = [e for e in entries if e.name in wanted]
        missing = wanted - {e.name for e in entries}
        if missing:
            raise SystemExit(f"--only: unknown repo name(s): {', '.join(sorted(missing))}")

    if not entries:
        raise SystemExit("no repos selected")

    verum_bin = find_verum_bin()
    print(f"using verum binary: {verum_bin}", file=sys.stderr)

    fresh = do_run(entries, verum_bin)

    if args.diff:
        return diff_mode(fresh, SNAPSHOT_PATH, filtered=args.only is not None)

    out_path = args.out or SNAPSHOT_PATH
    write_snapshot(fresh, out_path)
    print(f"wrote {out_path}", file=sys.stderr)
    return 1 if fresh["_had_error"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
