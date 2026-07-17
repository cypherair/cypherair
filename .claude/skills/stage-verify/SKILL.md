---
name: stage-verify
description: Per-stage adversarial verification for multi-stage campaign work. Use when implementing work that lands as multiple stages, phases, or PR-sized commits against a written spec or plan. Not for single small PRs.
---

Open the stage's PR FIRST, then have a fresh-context subagent adversarially
verify the completed stage against the governing spec, and resolve its
findings. Post the verdict as a comment on the PR before merging — never
verify-then-PR. Record verdicts in the campaign worklog as well.
