---
name: release-stable
description: Run the tag-first stable release flow. Use when the maintainer asks for a stable release, an App Store candidate build, or a cypherair-v* version tag.
---

docs/APP_RELEASE_PROCESS.md is canonical — read it before acting; this skill
only sequences it.

1. Preflight: working tree clean on current `main`; CI green; read
   `MARKETING_VERSION` and `CURRENT_PROJECT_VERSION` from the Xcode project —
   they are maintainer-owned; never invent, increment, or reset them.
2. Confirm the stable asset contract (APP_RELEASE_PROCESS Section 2) is
   satisfiable for this build.
3. **Ask the maintainer before creating or pushing any tag or release** —
   this ask-first survives by design (CLAUDE.md). Stable releases are
   tag-first: the version tag, never `workflow_dispatch` alone.
4. After publishing: verify every asset from Section 2 is attached and the
   release verification steps in docs/XCFRAMEWORK_RELEASES.md pass.

**Verify:** the tag matches
`cypherair-v<MARKETING_VERSION>-build<CURRENT_PROJECT_VERSION>`; all Section 2
assets are present; the verification commands pass.
