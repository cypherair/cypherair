---
name: merge-flow
description: Merge an approved PR and fully close it out — branch/worktree cleanup, main sync, clean-workspace check, linked-issue update. Use when the maintainer says to merge a PR, or when merging under the agent-merge policy (CLAUDE.md Git & Workflow — verification passed, high confidence held by both author and merger; security-critical and governance changes stay with the maintainer).
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
5. Post the merge note naming the merging model (e.g. "Merged by Claude
   (Fable 5)") as a PR comment or description edit — mandatory for agent
   merges under the CLAUDE.md policy.
6. Update or close the linked issue as instructed (progress comment or close).

**Verify:** `gh pr view <N>` shows MERGED; `git status` is clean;
`git log origin/main..main` is empty; no stale topic branches or worktrees
remain; report merged SHA, deletions, and the clean-workspace confirmation in
one short summary.
