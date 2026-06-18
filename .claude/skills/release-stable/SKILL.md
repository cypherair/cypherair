---
name: release-stable
description: Run the tag-first stable release flow. Use when the maintainer asks for a stable release, an App Store candidate build, or a cypherair-v* version tag.
---

docs/APP_RELEASE_PROCESS.md is canonical — read it before acting; this skill
only sequences it. The formal release runs on Xcode Cloud (WF1 `PgpMobile
XCFramework` → WF2 `CypherAir Release`); see docs/XCODE_CLOUD_RELEASE.md.

1. Preflight: working tree clean on current `main`; CI green; read
   `MARKETING_VERSION` and `CURRENT_PROJECT_VERSION` from the Xcode project —
   they are maintainer-owned; never invent, increment, or reset them.
2. Confirm the stable asset contract (APP_RELEASE_PROCESS Section 2) is
   satisfiable for this build.
3. **Ask the maintainer before creating or pushing any tag or release** —
   this ask-first survives by design (CLAUDE.md). Stable releases are
   tag-first: push the SSH-signed `cypherair-v*-build*` tag on the intended
   `main` commit; that tag push (never `workflow_dispatch`) triggers Xcode
   Cloud WF1, which builds + drafts the release and starts WF2 (archive, sign,
   TestFlight, publish).
4. After WF1→WF2 publish: verify every Section 2 SDK/compliance asset (plus the
   three `CypherAir-*-AppStore.*` upload artifacts) is attached, the
   `stable-release-attest.yml` run completed, and the verification steps in
   docs/XCFRAMEWORK_RELEASES.md pass.

**Verify:** the tag matches
`cypherair-v<MARKETING_VERSION>-build<CURRENT_PROJECT_VERSION>`; all Section 2
assets are present; the verification commands pass.
