---
name: merge-flow
description: Merge an approved PR and fully close it out — branch/worktree cleanup, main sync, clean-workspace check, linked-issue update. Use when the maintainer says to merge a PR. Merging without the maintainer's explicit instruction is never allowed; this skill only sequences the mechanics after that instruction.
---

Safe to delegate to a cheaper sub-agent — every step is mechanical.

1. Merge with a regular merge commit (`gh pr merge <N> --merge`), never squash
   or rebase. Wait for CI unless the maintainer said not to; on "do not wait
   for CI", use `--admin`.
2. Delete the topic branch, remote and local, then `git fetch --prune`. Delete
   other leftover branches only when the maintainer asked and `git cherry` /
   `git log main..<branch>` shows nothing unmerged.
3. If the branch lived in a `.claude/worktrees/` checkout, remove the
   worktree.
4. Sync local `main` (`git checkout main && git pull --ff-only`).
5. Update or close the linked issue as instructed (progress comment or close).

**Verify:** `gh pr view <N>` shows MERGED; `git status` is clean;
`git log origin/main..main` is empty; no stale topic branches or worktrees
remain; report merged SHA, deletions, and the clean-workspace confirmation in
one short summary.
