#!/bin/sh
# Verum PostToolUse hook for Claude Code.
#
# Runs the deploy gate over the whole project after every file edit and, when
# the gate fails, exits 2 so the agent - not just the human - receives the
# reasons on stderr and can fix them before moving on. A passing gate is silent.
#
# Install: copy to .claude/hooks/verum-hook.sh, chmod +x, and point the
# PostToolUse hook command at "$CLAUDE_PROJECT_DIR/.claude/hooks/verum-hook.sh".
# The inline one-liner in settings.json does the same thing with no file to
# install; use this script when you want to extend the logic.
set -eu

PROJECT="${CLAUDE_PROJECT_DIR:-$PWD}"

if ! command -v verum >/dev/null 2>&1; then
    # Not installed is not a reason to block an edit: stay quiet and pass.
    exit 0
fi

if out=$(verum gate "$PROJECT" 2>&1); then
    exit 0
fi

printf '%s\n' "$out" >&2
printf 'Verum deploy gate failed. Fix the findings above before continuing.\n' >&2
exit 2
