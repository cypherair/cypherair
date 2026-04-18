# Documentation Governance

> Status: Canonical current-state governance document.
> Purpose: Define the documentation classes, metadata rules, archive rules, naming/path rules, language expectations, and update triggers for the CypherAir repository.
> Audience: Human developers, reviewers, product authors, and AI coding tools.
> Source of truth: This document, together with the active canonical docs it governs.
> Last reviewed: 2026-04-18.
> Update triggers: Any documentation-class change, archive move, metadata convention change, or repeated cross-document drift that suggests the governance rules are incomplete.

## 1. Documentation Classes

CypherAir uses five durable documentation classes:

1. **Entry**
   - Root orientation documents such as `README.md`, `CLAUDE.md`, and `AGENTS.md`
   - Job: explain the project and point readers to canonical sources of truth

2. **Canonical current-state**
   - Documents expected to match shipped code, configuration, and tests now
   - Examples: architecture, security, testing, conventions, code review, canonical product/technical specs

3. **Proposal or roadmap**
   - Future-facing product or engineering direction
   - These documents must say explicitly that they do not describe current shipped behavior

4. **Audit or review snapshot**
   - Point-in-time verification artifacts
   - These documents must be dated, scoped, and clearly non-canonical

5. **Archive**
   - Historical context only
   - Archived documents must never outrank current code or active canonical docs

## 2. Required Metadata

### 2.1 Canonical Current-State Documents

Canonical docs should include:

- `Status: Canonical current-state`
- `Purpose`
- `Audience`
- `Source of truth` or an equivalent statement when useful
- `Last reviewed`
- `Update triggers`

Existing canonical docs that predate this template do not need to be rewritten for style alone, but any touched canonical doc should move toward this shape.

### 2.2 Proposal / Roadmap Documents

Proposal docs should include:

- `Status: Draft`, `Active roadmap`, or equivalent
- `Purpose`
- `Audience`
- an explicit note that the document is not a statement of current shipped behavior
- `Companion`, `Related`, `Supersedes`, or `Blocked by` references where relevant

### 2.3 Audit / Review Snapshots

Audit and review snapshots should include:

- `Status` with explicit snapshot wording
- `Date` or `Scope`
- `Purpose`
- `Audience`
- `Truth sources`, `Evidence roots`, or equivalent
- `Superseded by` when a later snapshot replaces them

### 2.4 Archived Documents

Archived docs should include:

- `Status: Archived` or an equivalent archive banner
- archival reason
- snapshot date when known
- successor docs when they exist
- an explicit statement that current code and active docs outrank the archived file

## 3. Path And Naming Rules

- Root-level `README.md`, `CLAUDE.md`, and `AGENTS.md` remain entry docs.
- Top-level `docs/` is for active canonical docs, active proposal docs, and active review snapshots that still need regular human consumption.
- Only archived material belongs in `docs/archive/`.
- New filenames should describe the document itself, not a self-referential action on that document. Prefer names such as `..._REVIEW.md` or `..._AUDIT.md` over titles like “verification of X”.
- Active docs must not depend on archived docs for primary current-state claims.

## 4. Language Rule

- Active docs in this repository are written and maintained in English.
- New or edited prose in active docs must remain English.
- Untouched historical snapshots may retain older mixed-language verdict labels or notes when rewriting them would provide no current-state value.

## 5. Archive Rules

- When a doc is archived, move it under `docs/archive/` and add or preserve a clear archive banner.
- Archived docs must keep working links to active successor docs where those links exist.
- The first historical note or banner should make it obvious that the file is evidence or context, not current guidance.
- If a review snapshot stops being actively consumed, archive it instead of leaving it indefinitely beside canonical docs.

## 6. Documentation Update Triggers

Update the relevant docs in the same change when one of these surfaces changes:

- **Build or linkage model changes**
  - Update `README.md`, `CLAUDE.md`, `AGENTS.md`, `docs/PRD.md`, `docs/TDD.md`, and `docs/TESTING.md`

- **Test-plan or workflow changes**
  - Update `README.md`, `CLAUDE.md`, `AGENTS.md`, and `docs/TESTING.md`

- **Rust / FFI service ownership or downstream adoption changes**
  - Update `docs/RUST_FFI_SERVICE_INTEGRATION_BASELINE.md`
  - Update `docs/RUST_FFI_SERVICE_INTEGRATION_PLAN.md` if the remaining queue changed
  - Update `docs/RUST_FFI_IMPLEMENTATION_REFERENCE.md` if the semantic or boundary rules changed
  - Update `docs/RUST_FFI_APP_SURFACE_ADOPTION_PLAN.md` if app ownership changed

- **Storage keys, defaults, temp paths, or startup cleanup changes**
  - Update `docs/ARCHITECTURE.md` and `docs/TDD.md`

- **Authentication mode, recovery, or permission-description changes**
  - Update `docs/SECURITY.md`, `docs/PRD.md`, `docs/TDD.md`, and any affected entry docs

- **New future-facing feature docs**
  - Add explicit lifecycle metadata before treating them as part of the active doc stack

## 7. Review Checklist For Documentation Changes

Before merging a documentation-only change:

- confirm all touched active-doc prose is English
- run a local markdown-link audit across root docs, `docs/*.md`, and `docs/archive/*.md`
- check for stale current-state claims with targeted `rg` sweeps
- confirm archived docs are not newly cited as current source of truth
- confirm `git diff --check` is clean
