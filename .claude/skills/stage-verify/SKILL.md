---
name: stage-verify
description: Per-stage adversarial verification for multi-stage campaign work. Use when implementing work that lands as multiple stages, phases, or PR-sized commits against a written spec or plan. Not for single small PRs.
---

Have a fresh-context subagent adversarially verify each completed stage
against the governing spec, and resolve its findings. Ask the verifier to
also judge new or changed tests: for each, name the future change it would
catch, and flag any that only restate the implementation. Open any PR or PRs
before the verification runs. Record verdicts in the campaign worklog.

## Design check

**[Temporary — in force until the maintainer revisits it, a review due after
the cleanup campaign; open questions on #842.]**

Where the change has architecture to judge — skip a pin rotation, a comment
fix, or a value update — the verifier also answers, with evidence:

- **Root cause.** What mechanism produced the defect, and is it gone? Two
  copies of a rule made to *agree* is not a removal.
- **Complexity direction.** Does this add a type, parameter, branch, or call
  site without removing at least as much structure?
- **Burden of proof on the keep** (CLAUDE.md §Git & Workflow). Anything
  retained needs a stated positive reason it must exist; a reference count is
  not one.
- **Stopgap.** Is any part a knowingly-wrong interim with a fix-later attached?

Name the mechanism and its disposition — an unevidenced "well designed" does
not count. A disputed design objection goes to the maintainer, not back to the
author.
