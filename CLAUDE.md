# Project conventions

## Git authorship policy (enforced)

This repo must never contain Claude attribution. All commits and PR bodies are
authored by the human who ran the session, not by Claude.

**Required for every commit and PR you create in this repo:**

- Author and committer must be `jeremylaratro <62393443+jeremylaratro@users.noreply.github.com>`.
  Local git is already configured this way; do not change it.
- Commit messages must NOT contain any of:
  - `https://claude.ai/code/session_...` (the session link Claude Code adds by default)
  - `Co-Authored-By: Claude ...`
  - `Generated with ...Claude...`
  - The robot emoji + `Generated with` phrasing
- PR titles, descriptions, comments, and review bodies are subject to the same rule.

`.claude/settings.json` sets `attribution.commit = ""` and `attribution.pr = ""`,
which disables Claude Code's built-in trailer/PR-body attribution. Do not
re-enable it. Do not paste those strings in by hand either.

## Enforcement

Three layers, all already wired up:

1. **Claude Code PreToolUse hook** (`.claude/settings.json`) — blocks any
   `Bash` tool call whose command contains one of the banned patterns. Any
   `git commit -m ...` or `gh pr ...` that includes a session link or Claude
   co-author line is rejected before it runs.
2. **git `commit-msg` hook** (`.githooks/commit-msg`) — rejects matching
   commit messages even if a commit is made outside Claude Code. Activated via
   `git config core.hooksPath .githooks` (already set locally; new clones must
   run this once).
3. **This file** — read at session start so Claude follows the policy
   proactively rather than waiting to be blocked.

If a hook blocks you, strip the offending line(s) from the message and retry.
Do not bypass with `--no-verify`.

## Setup for a fresh clone

```
git config user.name jeremylaratro
git config user.email 62393443+jeremylaratro@users.noreply.github.com
git config commit.gpgsign false
git config core.hooksPath .githooks
```
