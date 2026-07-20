---
name: stage-verify
description: Per-stage adversarial verification for multi-stage campaign work. Use when implementing work that lands as multiple stages, phases, or PR-sized commits against a written spec or plan. Not for single small PRs.
---

Have a fresh-context subagent adversarially verify each completed stage
against the governing spec, and resolve its findings. Ask the verifier to
also judge new or changed tests: for each, name the future change it would
catch, and flag any that only restate the implementation. Open any PR or PRs
before the verification runs. Record verdicts in the campaign worklog.
