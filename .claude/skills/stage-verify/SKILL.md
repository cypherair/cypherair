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

**[Temporary — in force until the maintainer revisits it, a review due after the
cleanup campaign. The open questions behind it are #842.]**

Correctness is not the whole verdict. A change can be behaviourally right and
architecturally wrong, and the pass above will not catch it. Where the change
has architecture to judge — skip this for a pin rotation, a comment fix, or a
value update — the verifier answers, with evidence:

- **Root cause.** What mechanism produced the defect, and is that mechanism
  gone? If it survives, say so plainly and name what still permits the class.
  The shape to watch for is two copies of a rule made to *agree* rather than
  one copy removed.
- **Complexity direction.** Does this add a type, parameter, branch, or call
  site without removing at least as much structure? A net-additive change
  justifies itself or fails.
- **Burden of proof on the keep.** Anything retained needs a stated positive
  reason it must exist. That something references it is not a reason — it is
  the next question, which is whether the caller should change (CLAUDE.md
  §Git & Workflow).
- **Stopgap.** Is any part a knowingly-wrong interim with a fix-later
  attached?

Two rules keep this from becoming a rubber stamp. An unevidenced "well
designed" is worse than no check, because it manufactures confidence: the
verifier names the mechanism and its disposition, or the answer does not
count. And the verifier may not settle a design objection by deferring to the
author — a disputed objection goes to the maintainer, since by the time it
arises the author and the merging session both already hold high confidence.

The same questions belong in the authoring brief, so the shape is argued
before the code exists rather than litigated after.
