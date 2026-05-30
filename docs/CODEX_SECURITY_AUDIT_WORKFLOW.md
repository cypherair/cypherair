# Codex Security Audit Workflow

> Temporary workflow for reviewing Codex security findings until Codex has a
> built-in Dynamic Workflow equivalent.

This guide applies only to findings tracked by
`docs/CODEX_SECURITY_REVIEW_INDEX.md`. Agent output is evidence, not a
decision. Final disposition requires user review with the main Codex session.

Sources:

- index: `docs/CODEX_SECURITY_REVIEW_INDEX.md`
- CSV export: `codex-security-findings-2026-05-29T13-11-03.346Z.csv`
- stable anchor: `finding_url`
- confirmed follow-ups: `docs/CODEX_SECURITY_REVIEW.md`

Agents must resolve CA-ID -> index `finding_url` -> CSV row. Do not infer CSV
rows from line numbers.

## Round Layout

Each round gets a local, git-excluded directory under the repository root:

```text
.codex-audit/round-NNN/
  round-index.md
  cluster-a/
    investigator.md
    investigator-trace.md
    adversary.md
    adversary-trace.md
    reviewer-notes.md
```

Do not use `pair-log.md`, `report.md`, or a shared `audit-trail.md`.

## Roles

Investigator writes `investigator.md` and `investigator-trace.md`. It should
look for mechanisms, code locations, shipped reachability, mitigations, and
evidence for or against the finding.

Adversary reads the original sources, current code, and `investigator.md`. It
must challenge reachability, user-operation sequence, prerequisites, platform
semantics, impact, and false-positive possibilities. It does not read
`investigator-trace.md` unless needed to verify a cited source.

Main Codex writes `reviewer-notes.md` after both reports return. These notes
are short, non-final, and only support discussion with the user.

## Agent Defaults

Use sub-agents only when actually auditing:

```text
agent_type: explorer
model: gpt-5.5
reasoning_effort: xhigh
service_tier: priority
fork_context: false
```

Run at most six investigators in parallel. When one investigator completes and
its files are present, start the matching adversary. Use long waits instead of
constant short polling.

If Apple platform semantics matter, use available XcodeBuildMCP or Apple
documentation lookup tools. If no documentation lookup tool is available, say
so in the trace and base the finding on local SDK/code/project documentation.

## Required Fields

Each CA-ID report should cover: code locations, mechanism-present status,
shipped reachability, mitigations, evidence-real, evidence-false-positive,
preliminary disposition or recommendation, confidence, and open questions.

Adversary recommendations use:
`real-needs-fix`, `real-low`, `false-positive`, `already-fixed`, `wont-fix`,
or `uncertain`.

## Formal Recording Rules

- Do not edit `docs/CODEX_SECURITY_REVIEW_INDEX.md` before user confirmation.
- Do not close Codex findings before user confirmation.
- After user confirmation, update the index status and close reason separately.
- `reviewer-notes.md` is temporary discussion support, not a formal record.

Before closing an agent, verify that its expected files exist and have the
requested structure. If not, ask the agent to repair the files before closing.
