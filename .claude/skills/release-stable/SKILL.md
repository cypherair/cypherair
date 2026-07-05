---
name: release-stable
description: Run the tag-first stable release flow. Use when the maintainer asks for a stable release, an App Store candidate build, or a cypherair-v* version tag.
---

docs/RELEASE.md is canonical — read it before acting; this skill
only sequences it. The formal release runs on Xcode Cloud (WF1 `PgpMobile
XCFramework` → WF2 `CypherAir Release`); see docs/RELEASE.md.

1. Preflight: working tree clean on current `main`; CI green; set
   `MARKETING_VERSION` and `CURRENT_PROJECT_VERSION` in the Xcode project to the
   intended release pair and commit them (docs/RELEASE.md Section 1), confirming
   the version with the maintainer.
2. Confirm the stable asset contract (docs/RELEASE.md Section 3) is
   satisfiable for this build.
3. **Ask the maintainer before creating or pushing any tag or release** —
   this ask-first survives by design (CLAUDE.md). Stable releases are
   tag-first: push the SSH-signed `cypherair-v*-build*` tag on the intended
   `main` commit; that tag push (never `workflow_dispatch`) triggers Xcode
   Cloud WF1, which builds + drafts the release and starts WF2 (archive, sign,
   TestFlight, publish).
4. After WF1→WF2 publish: verify every Section 3 SDK/compliance asset (plus the
   three `CypherAir-*-AppStore.*` upload artifacts) is attached, the
   `stable-release-attest.yml` run completed, and the verification steps in
   docs/RELEASE.md pass.

**Verify:** the tag matches
`cypherair-v<MARKETING_VERSION>-build<CURRENT_PROJECT_VERSION>`; all Section 3
assets are present; the verification commands pass.
