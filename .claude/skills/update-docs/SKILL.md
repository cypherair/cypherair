---
name: update-docs
description: Check and report which project docs need updating after code changes
disable-model-invocation: true
---

After code changes, check which project documentation sections are affected and report what needs updating. Does NOT modify docs automatically — only reports.

## Steps

1. Identify changed files via `git diff` (staged + unstaged) or `git diff origin/main...HEAD` (branch scope).

2. For each changed area, check the corresponding documentation:

   **Swift file added/removed/renamed:**
   - `docs/CONVENTIONS.md` Section 4 — file structure tree (lines ~137-213)
   - If in `Sources/Services/`: also check `docs/ARCHITECTURE.md` Section 2 Services table
   - If in `Sources/Security/`: also check `docs/ARCHITECTURE.md` Section 2 Security table
   - If in `Sources/Models/`: also check `docs/ARCHITECTURE.md` Section 2 Models description
   - If security-critical: also check `docs/SECURITY.md` Section 8 Red Lines table

   **Rust file added/removed/renamed in pgp-mobile/src/:**
   - `docs/ARCHITECTURE.md` — pgp-mobile file listing
   - If security-critical: `docs/SECURITY.md` Section 8 Red Lines table

   **Build process changed (Cargo.toml, build scripts, targets):**
   - `CLAUDE.md` Build Commands section
   - `.claude/skills/regen-ffi/SKILL.md`

   **New error variant added:**
   - `docs/PRD.md` Section 4.7 error messages table

3. For each affected doc section, output:
   - File path and section name
   - What is currently documented
   - What the actual codebase state is
   - Suggested update

## Notes

- This skill is read-only. It reports discrepancies but does not edit files.
- Run this after completing a feature or refactor, before creating a PR.
- Focus on structural changes (new files, renamed modules). Do not report internal logic changes that don't affect documentation.
