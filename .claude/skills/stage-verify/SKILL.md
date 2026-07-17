---
name: stage-verify
description: Per-stage adversarial verification for multi-stage campaign work. Use when implementing work that lands as multiple stages, phases, or PR-sized commits against a written spec or plan. Not for single small PRs.
---

Open the stage's PR, then have a fresh-context subagent adversarially verify
it against the governing spec, and resolve its findings. Post the verdict as
a PR comment before merging, and record it in the campaign worklog.
