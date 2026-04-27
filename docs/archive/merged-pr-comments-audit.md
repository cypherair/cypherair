> Archive note: the issues captured in this audit have been fixed. This
> document is retained in `docs/archive/` for historical reference.

# Merged PR Comments Audit

- Repository: `cypherair/cypherair`
- Generated: `2026-04-27T01:39:18.388803+00:00`
- Merged PRs scanned: `237`
- PRs with any comments: `34`
- PRs with conversation comments: `25`
- PRs with inline review comments: `9`
- PRs with inline review replies: `0`
- PRs with Codex/OpenAI/Copilot-matched comments: `34`
- Total conversation comments: `25`
- Total inline review comments: `14`
- Total inline review replies: `0`
- Total Codex/OpenAI/Copilot-matched comments: `39`

Note: this fast scan counts PR conversation comments and inline pull-request review comments, including inline replies. It does not count review submissions that have no inline comment.

Triage note: the detail section below omits eight substantive inline review
comments that were already resolved or determined non-actionable during manual
review: #238 protected settings reset preflight, #238 sentinel pending-mutation
authorization, #227 local reset in tutorial sandbox, #219 app access policy
handoff context invalidation, #214 Xcode 26.4 fallback path, #203 recovery
candidate domain-master-key copies, #180 macOS file-protection requirements,
and #71 empty license search results. The raw counts above and
`docs/merged-pr-comments-audit.json` still include the full original scan.

Noise-trimming note: the PR list and detail section below also omit 25
conversation comments whose only content was the Codex code-review usage-limit
notice.

## PRs With Comments

- [#238 [codex] Implement AppData Phase 4 orchestration](https://github.com/cypherair/cypherair/pull/238) — inline 4, codex 4; merged `2026-04-27T01:15:11Z`
- [#227 [codex] add passive auth trace and local reset](https://github.com/cypherair/cypherair/pull/227) — inline 1, codex 1; merged `2026-04-26T01:13:32Z`
- [#222 Promote Apple arm64e support](https://github.com/cypherair/cypherair/pull/222) — inline 2, codex 2; merged `2026-04-24T23:21:22Z`
- [#219 [codex] feat: unify app data authentication](https://github.com/cypherair/cypherair/pull/219) — inline 1, codex 1; merged `2026-04-24T02:00:41Z`
- [#214 [codex] fix: pin GitHub Actions Xcode to 26.4.1](https://github.com/cypherair/cypherair/pull/214) — inline 1, codex 1; merged `2026-04-23T05:48:39Z`
- [#203 [codex] Add protected clipboard settings](https://github.com/cypherair/cypherair/pull/203) — inline 2, codex 2; merged `2026-04-22T09:15:53Z`
- [#180 [codex] Add app data protection migration docs](https://github.com/cypherair/cypherair/pull/180) — inline 1, codex 1; merged `2026-04-20T18:31:30Z`
- [#176 [codex] Harden source provenance validation](https://github.com/cypherair/cypherair/pull/176) — inline 1, codex 1; merged `2026-04-20T08:54:54Z`
- [#71 [codex] Add in-app license notices](https://github.com/cypherair/cypherair/pull/71) — inline 1, codex 1; merged `2026-04-03T09:24:04Z`

## Codex/OpenAI/Copilot-Matched Comment Details

### [#238 [codex] Implement AppData Phase 4 orchestration](https://github.com/cypherair/cypherair/pull/238)

- `chatgpt-codex-connector[bot]` inline on `CypherAir.xcodeproj/project.pbxproj:522` at `2026-04-27T01:20:46Z`: ** Clear RepositoryAudit snapshot before copying inputs** This script no longer deletes `$(TARGET_BUILD_DIR)/.../RepositoryAudit` before copying listed files, so removed/renamed s... ([comment](https://github.com/cypherair/cypherair/pull/238#discussion_r3144497804))
- `chatgpt-codex-connector[bot]` inline on `CypherAir.xcodeproj/project.pbxproj:499` at `2026-04-27T01:20:46Z`: ** Use metadata commit SHA before enforcing git fallback** In stable-release mode, this precheck fails the build when `SOURCE_COMPLIANCE_COMMIT_SHA` is empty and `.git/HEAD` / `.g... ([comment](https://github.com/cypherair/cypherair/pull/238#discussion_r3144497806))

### [#222 Promote Apple arm64e support](https://github.com/cypherair/cypherair/pull/222)

- `chatgpt-codex-connector[bot]` inline on `scripts/arm64e_release_metadata.py:123` at `2026-04-24T22:03:29Z`: ** Skip remote freshness checks when freshness level is off** `collect_dependency_chain` performs remote lookups unconditionally, so `--freshness-level off` still runs `git ls-rem... ([comment](https://github.com/cypherair/cypherair/pull/222#discussion_r3140525143))
- `chatgpt-codex-connector[bot]` inline on `scripts/build_apple_arm64e_xcframework.sh:41` at `2026-04-24T23:02:06Z`: ** Guard manifest restore against stale backup files** The EXIT trap restores `Cargo.toml` whenever `pgp-mobile/Cargo.toml.bak.apple-arm64e-build` exists, even if this invocation... ([comment](https://github.com/cypherair/cypherair/pull/222#discussion_r3140702253))

### [#203 [codex] Add protected clipboard settings](https://github.com/cypherair/cypherair/pull/203)

- `chatgpt-codex-connector[bot]` inline on `Sources/Security/ProtectedData/ProtectedDataSessionCoordinator.swift:42` at `2026-04-22T09:21:18Z`: ** Clear unlocked domain keys when removing shared right** When the shared right is removed, this method clears only `wrappingRootKey` and leaves `ProtectedDomainKeyManager`’s unl... ([comment](https://github.com/cypherair/cypherair/pull/203#discussion_r3122904720))

### [#176 [codex] Harden source provenance validation](https://github.com/cypherair/cypherair/pull/176)

- `chatgpt-codex-connector[bot]` inline on `scripts/validate_app_store_candidate_release.py:176` at `2026-04-20T08:55:13Z`: ** Resolve stable tag SHA from the canonical GitHub repo** `validate_candidate_release` verifies release existence against `repository_full_name` but then compares `HEAD` to `remo... ([comment](https://github.com/cypherair/cypherair/pull/176#discussion_r3109419174))
