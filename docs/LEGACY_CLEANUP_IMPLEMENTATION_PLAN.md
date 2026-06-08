# Legacy Cleanup Implementation Plan

> Status: Active roadmap (execution plan). Not a statement of current shipped behavior.
> Purpose: Turn the [LEGACY_CLEANUP](LEGACY_CLEANUP.md) inventory into an ordered, phased PR
>   sequence now that a support cutoff is approved — what each PR removes, what must stay, its
>   gate, risk, required human review, and validation.
> Audience: CypherAir maintainers, reviewers, QA, and AI coding agents.
> Companion inventory: [LEGACY_CLEANUP](LEGACY_CLEANUP.md).
> Authorities (outrank this doc on conflict): [SECURITY](SECURITY.md), [TESTING](TESTING.md),
>   [CONVENTIONS](CONVENTIONS.md), [CODE_REVIEW](CODE_REVIEW.md),
>   [PERSISTED_STATE_INVENTORY](PERSISTED_STATE_INVENTORY.md),
>   [ARCHITECTURE_REFACTOR_ROADMAP](ARCHITECTURE_REFACTOR_ROADMAP.md).
> Support cutoff: **maintainer-approved support cutoff, 2026-06-08, covering all LEGACY_CLEANUP §2 items.**
> Last reviewed: 2026-06-08.

Current code and active canonical docs outrank this plan whenever they disagree. Line numbers
are anchors at authoring time and may drift; the *symbols* are authoritative — re-confirm before
editing.

## 1. Scope & cutoff

A maintainer has approved a support cutoff (date-based, above) for **every item in
[LEGACY_CLEANUP](LEGACY_CLEANUP.md) §2**:

- **In scope:** Class 1 #1–6 (retained old-install migration), Class 2 #7–8 (revocation
  backfill, `PGPKeyIdentity` legacy decode), Class 3 #9 (Rust `legacy_*` + the Swift app-model
  legacy layer — **full retirement**, per maintainer decision).
- **Excluded:** the items already removed (`LEGACY_CLEANUP.md` §3 — do not re-chase) and the
  permanent interop/security surfaces (`LEGACY_CLEANUP.md` §4 — never remove): v4/SEIPDv1/SEIPDv2/
  DEFLATE read-compat, S2K auto-detect, the `CAPDSEF2` format-floor + SE device-binding, and
  profile-correct message-format selection.

Every removal PR body must cite the cutoff label verbatim and prove old-install
**fail-closed / recovery / reset** behavior for the path it deletes.

## 2. Global rules

- **One domain per PR.** Do not bundle ProtectedData, Rust/UniFFI, settings, and reset cleanup
  into one review. (Exceptions noted below are tightly coupled same-file edits.)
- **Security boundaries STOP-and-describe.** Per [SECURITY](SECURITY.md) §10 the review gate is
  **directory-level** for `Sources/Security/` (incl. `Sources/Security/ProtectedData/`), plus
  `pgp-mobile/src/decrypt.rs` and `streaming.rs`. Every PR touching those requires explicit
  human security review before edits.
- **Removal = drop the legacy *source* read.** After removal, an old-install legacy payload must
  route to **recovery / fail-closed**, never to a silent reset-to-defaults. This is *stronger*
  than today's tolerant behavior, not weaker.
- **Preserve invariants:** zero-network, AEAD hard-fail, secret zeroization, MIE/Enhanced
  Security, and profile-correct format selection (v4→SEIPDv1, mixed→SEIPDv1, v6→SEIPDv2).
- **Never hand-edit generated UniFFI output** (`Sources/PgpMobile/pgp_mobile.swift`,
  `bindings/pgp_mobile.swift`, headers/modulemap). Regenerate via `build-xcframework.sh`.
- **Rust changes require an XCFramework refresh** before `xcodebuild test` (see VAL-XCFW).
- **Move tests to current APIs before deleting** a compatibility surface; keep retained-migration
  removals fail-closed.

Validation shorthands used throughout:

| Name | Command |
|------|---------|
| **VAL-SWIFT** | `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'` |
| **VAL-RUST** | `cargo +stable test --manifest-path pgp-mobile/Cargo.toml` |
| **VAL-XCFW** | `ARM64E_STAGE1_FORCE_DOWNLOAD=1 ARM64E_STAGE1_RELEASE_TAG=rust-arm64e-stage1-stable196-20260530T083949Z-ecc85bf-r26679152716-a1 ./build-xcframework.sh --release` (run **before** VAL-SWIFT whenever Rust/bindings changed) |

## 3. PR sequence

### Track 0 — guardrail scaffold

| PR | Adds / removes | Gate | Review | Validate |
|----|----------------|------|--------|----------|
| **PR-0** | Adds a **Swift** source-audit test (reuse `RepositoryAuditLoader.swift` + `ArchitectureSourceAuditTests.swift`, which scan a build-time snapshot of `Sources/*.swift` only) that will forbid each removed **Swift** symbol, initially behind per-symbol **exception lists**; each later PR deletes its exception to *prove* the removal landed. The Rust symbols (#9) are out of this audit's reach — a separate Rust guard is added in Track D (see §7). Removes nothing. | none | No | VAL-SWIFT (update `RepositoryAudit*.xcfilelist` if adding files) |

### Track A — isolated / low-risk

| PR | Item | Removes | Keep-traps | Gate | Review | Validate |
|----|------|---------|-----------|------|--------|----------|
| **PR-A1** | #5 Contacts snapshot v1→v2 | `ContactsDomainSnapshotCodec.swift` `LegacySnapshotV1` (:8-16), `migrateLegacyV1Snapshot` (:52-72), decode `case 1` (:37-40) | the unsupported-version fail-closed `default` (already proven by `test_unsupportedSchemaVersion_isRejected`) | none — **do first** | Yes (`Sources/Security/ProtectedData/`) | VAL-SWIFT |
| **PR-A2** | #2A dead key-metadata migrate chain | `KeyMetadataStore.migrateLegacyMetadataIfNeeded` (:120-210); `KeyCatalogStore.migrateLegacyMetadataIfNeeded` (:26-44, incl. the `as? KeyMetadataStore` cast that fails in prod); `KeyManagementService.migrateLegacyMetadataAfterAppAuthentication` (:184-223); `AppContainer:1108` | **do NOT delete the `KeyMetadataStore` file** — its CRUD is a test fixture (~25 files); keep #2B; keep the in-domain schema v1→v2 migration (`KeyMetadataDomainStore` `PayloadV1` :67-70, decode `case 1` :489-498) | none → **unblocks PR-C2** | Yes (`Sources/Security/`) | VAL-SWIFT |

### Track B — Class 2 bundle (after the key-metadata cutoff)

| PR | Item | Removes | Keep-traps | Gate | Review | Validate |
|----|------|---------|-----------|------|--------|----------|
| **PR-B1** | #8 `PGPKeyIdentity` legacy decode | the whole custom `init(from:)` (`PGPKeyIdentity.swift:140-166`; the legacy part is the two `decodeIfPresent(...) ?? <profile default>` at :147-154) → revert to synthesized `Codable` | `CodingKeys` (:10-27) unchanged — wire-compatible; the memberwise `init(...)` convenience with `?? profile` defaults (:104-138) stays (constructor convenience, not the Codable legacy path) | #2 cutoff | No (`Sources/Models/`) | VAL-SWIFT |
| **PR-B2** | #7 imported-key revocation backfill | `KeyExportService.exportRevocationCertificate` backfill branch (:59-78) → collapse to "return stored `revocationCert`, else `throw keyOperationUnavailable(.revocationArtifactUnavailable)`"; this kills `KeyCatalogStore.updateRevocation` (:73-91, only caller) → delete it | keep the `revocationArtifactUnavailable` error category (used elsewhere); do not delete `unwrapPrivateKey`/`generateKeyRevocation` (used elsewhere) | #2 cutoff (bundle w/ B1) | Yes (unwraps key material) | VAL-SWIFT |

### Track C — high-risk security migrations

All under `Sources/Security/ProtectedData/` (+ `LocalDataResetService`) → **all require human
security review.** Ordered least-to-most consequential; the Critical pair last.

| PR | Item | Removes | Keep-traps | Gate | Risk | Validate |
|----|------|---------|-----------|------|------|----------|
| **PR-C6** | #6a self-test dir + orphan tutorial suites | `AppStartupCoordinator` legacy self-test cleanup (:131,133-150, `legacySelfTestReportDirectory`); `LocalDataResetService` `legacySelfTestReportsDirectory` (:37,81-83,224,367-369,448-450); `AppTemporaryArtifactStore` orphan `com.cypherair.tutorial.<UUID>` cleanup (:10,126,221-238) | keep current `com.cypherair.tutorial.sandbox` + `CypherAirGuidedTutorial-*` / decrypted / streaming / export cleanup | independent — **land early** (shares `LocalDataResetService.swift`) | Med | VAL-SWIFT |
| **PR-C1** | #3 private-key-control legacy defaults | `PrivateKeyControlStore.legacyInitialPayload()` (:604-645; readers at :89/:162 → `Payload.initial(authMode: .standard)`), `cleanupLegacyDefaults()` (:647-653), `PrivateKeyControlError.invalidLegacyAuthMode`; the 5 legacy `UserDefaults` key constants in `AuthenticationEvaluable` `AuthPreferences` (:395-412) | **keep ALL recovery-journal logic** (rewrap / modify-expiry crash recovery); keep `gracePeriodKey` + `defaultGracePeriod` | none (earliest high-risk; well-isolated) | High | VAL-SWIFT |
| **PR-C2** | #2B live migration source **+ #6c** | `KeyMetadataStore.loadMigrationSourceSnapshot`/`cleanupMigrationSourceItems` (:60-118) + consumers in `KeyMetadataDomainStore` (:132,169,535,542,626); `LocalDataResetService` metadataAccount reset + post-conditions (:114-118,391-395,454-456) | keep `KeyMetadataStore` CRUD; keep in-domain v1→v2; **keep the reset markers** (format-floor / device-binding / legacy-cleanup) at :127-147,371-385,439-447 | **after PR-A2** | High | VAL-SWIFT (prove Reset-All exhaustiveness) |
| **PR-C3** | #4 protected-settings v1→v2 + legacy ordinary settings | `ProtectedSettingsStore` `PayloadV1` (:14-16), `requiresOrdinarySettingsMigration` (:25-27), decode `case 1` (:894-904), `migrateOpenedSettingsSnapshotIfNeeded` body (:845-887) + call sites, `legacyOrdinarySettingsSnapshot`/`removeLegacySettingsSources` (:1032-1041 + :137,267,328,851,885), the legacy read in `legacyInitialPayload()` (:1022-1030) | **`LegacyOrdinarySettingsStore` is NOT deletable** — it is a live backend (tutorial sandbox, authenticated-test-bypass) and backs `AppConfiguration.resetPersistentKeys`. Remove only the *migration bridge*; at most rename to drop "Legacy" | after C1/C2 | High | VAL-SWIFT (v1 → recovery, not reset-to-defaults) |
| **PR-C4** | #1A legacy `LARight` right-store **+ #6b** | `ProtectedDataRightStoreClient.swift:572-785` (the whole legacy-right block); `ProtectedDataRootSecretCoordinator` `legacyMigrationDeferred` (:6), dispatch (:88-118), `migrateLegacySharedRightIfNeeded` (:273-385), `legacyRightStoreClient`; `ProtectedDataSessionCoordinator` `allowLegacyMigration` threading (:23,36,59-158); `AppContainer` args (:587,590,838,960; :1164 already `nil`); `LocalDataResetService` `legacyRightStoreClient` (:23,45,66,154-159) | keep the modern v2 envelope + device-binding; keep reset markers | last-but-one | **Critical** (wrong deletion = data lockout) | VAL-SWIFT (prove old-install fail-closed/recovery) |
| **PR-C5** | #1B raw-v1 root-secret | the migration *call* (`ProtectedDataRightStoreClient.swift:349-353`), `migrateLegacyRawRootSecret` (:395-479), `.legacyV1Raw` (:10) if unused | **CRITICAL keep:** the anti-downgrade throw at **:347** (`invalidEnvelope` when a raw payload appears after the v2 format floor) — the raw-length branch (:340) becomes *detect → throw, no migration*. Keep `CAPDSEF2` + device-binding + format-floor store | **after PR-C4** (same file) | **Critical** | VAL-SWIFT + a **permanent** negative test: raw-after-floor → `invalidEnvelope` |

### Track D — #9 full retirement (independent track; runs in parallel with A–C)

| PR | Removes / changes | Keep-traps | Gate | Review | Validate |
|----|-------------------|-----------|------|--------|----------|
| **PR-D1** (Swift → modern API; **no Rust change**) | repoint `PGPMessageResultMapper.swift` (:11-152) to `summaryState` / `signatures[summaryEntryIndex]` and stop reading the FFI legacy fields (incl. the `PasswordDecryptResult` path :54-55); remove app-model `DetailedSignatureVerification.legacyStatus`/`legacySignerFingerprint`/`legacySignerIdentity` (:52-54), `legacyVerification` (:78-86), `VerificationState(legacyStatus:)` (:90-104) and the `SignatureVerification.swift:97` fallback; `SelfTestService.swift:242,264` → `summaryState == .verified`; `DetailedSignatureSectionView` drop the empty-`signatures` legacy fallback (render from `summaryState`); migrate ~23 Swift test files (~137 assertions) | keep the whole `summaryState`/`signatures` path | precedes D2 | self-test gate is security-adjacent — describe the equivalence | VAL-SWIFT (no XCFW yet — proves equivalence before touching Rust) |
| **PR-D2 + D3** (Rust delete + bindings regen — **one PR** so `main` never has a broken Swift build) | drop `legacy_status`/`legacy_signer_fingerprint` from the 4 detailed-result structs (`signature_details.rs:37-79`) and from `SignatureCollector` (fields, assignments, `into_parts` slots, the `legacy_signer_fingerprint()` accessor); update the 6 producer sites across `decrypt.rs`, `external_decryptor.rs`, `verify.rs`, `streaming.rs`, `password.rs`; retire `PasswordDecryptResult.signature_status`/`signer_fingerprint`; rewire the "no observed results" error paths (`verify.rs:13-19`, `streaming.rs:720-726`) to compute `summary_state` directly; migrate ~19 Rust test files; regenerate **both** `Sources/PgpMobile/pgp_mobile.swift` and `bindings/pgp_mobile.swift` | **keep `LegacyFoldMode` / `legacy_stopped`** — they also drive `summary_state`/`summary_entry_index` (optionally rename to `SummaryFoldMode`/`summary_selected`); keep `state_from_legacy_status` as an internal helper or inline it | after D1 | **Yes** (`decrypt.rs`/`streaming.rs` §10) | VAL-RUST → VAL-XCFW → VAL-SWIFT |
| **PR-D4** (close-out) | tighten the Swift PR-0 guardrail to forbid the #9 **Swift** symbols, and add a **new Rust** forbidden-symbol test in `pgp-mobile` (a `#[test]` that reads `src/` via `CARGO_MANIFEST_DIR` and asserts `legacy_status`/`legacy_signer_fingerprint` are absent — no existing mechanism covers Rust); final inventory moves for #9 | — | after D1–D3 | No | VAL-XCFW + VAL-RUST + VAL-SWIFT (full matrix) |

## 4. Dependency graph

```
PR-0 ─────────────────────────────────► (its exceptions deleted by every later PR)

Track A:  PR-A1 (#5)            ── independent
          PR-A2 (#2A dead)      ── independent ──► unblocks PR-C2

Track B:  PR-A2 ──► PR-B1 (#8) + PR-B2 (#7)        [bundle; "after key-metadata cutoff"]

Track C:  PR-C6 (#6a)  ── independent; land EARLY (shares LocalDataResetService.swift)
          PR-C1 (#3)   ── independent; earliest high-risk auth
          PR-A2 ──► PR-C2 (#2B + #6c)
          PR-C3 (#4)   ── after C1/C2 (auth-adjacent)
          PR-C4 (#1A + #6b) ──► PR-C5 (#1B)        [same file; Critical pair LAST]

Track D:  PR-D1 ──► PR-D2+D3 ──► PR-D4              [⟂ Tracks A–C, fully parallel]
```

Key unblock edges and rationale:

- **PR-A2 → PR-C2:** remove the dead 2A chain before touching the live 2B migration source so the
  `as?`-cast removal and the consuming-side removal don't tangle.
- **PR-C4 → PR-C5:** both edit `ProtectedDataRightStoreClient.swift` root-secret paths; do the
  right-store block first, then the delicate raw-branch surgery.
- **PR-D1 → PR-D2:** Swift must stop reading the FFI legacy fields before they are deleted (else
  the regenerated bindings won't compile).
- **PR-C6 early:** it shares `LocalDataResetService.swift` with PR-C2 (#6c) and PR-C4 (#6b);
  landing #6a first minimizes three-way churn. Every PR touching that file must re-run the
  local-reset exhaustiveness tests.
- The **Critical pair (PR-C4/PR-C5)** lands last, with no other ProtectedData PR in flight.

## 5. Keep-list — traps the PRs must NOT remove

| Area | Keep (current behavior / permanent security) |
|------|----------------------------------------------|
| #1 root-secret | `CAPDSEF2` format-floor marker, SE device-binding envelope, and the **anti-downgrade throw at `ProtectedDataRightStoreClient.swift:347`** |
| #2 key-metadata | `KeyMetadataStore` CRUD (test fixture); the in-domain schema v1→v2 migration in `KeyMetadataDomainStore` |
| #3 private-key-control | all recovery-journal logic (rewrap / modify-expiry); `gracePeriodKey` + `defaultGracePeriod` |
| #4 settings | `LegacyOrdinarySettingsStore` (live backend — rename-only, not delete) |
| #6 local-data | `LocalDataResetService` format-floor / device-binding / legacy-cleanup markers are **reset deletion-targets that STAY** (Reset-All must keep deleting them) |
| #9 signatures | `LegacyFoldMode` / `legacy_stopped` (also drive `summary_state`/`summary_entry_index`) |

## 6. Per-PR doc maintenance + inventory corrections

In the **same PR** that removes an item:

1. **`LEGACY_CLEANUP.md`:** move the item's row from §2 to §3 ("Already done — do not re-chase"),
   reworded to "removed under the 2026-06-08 cutoff"; keep the relevant §4 keep-traps documented;
   bump `Last reviewed`.
2. **`PERSISTED_STATE_INVENTORY.md`:** update the affected rows' status/migration-readiness to
   drop "legacy source kept only as a verified cleanup source" once the source read is gone
   (rows: `authMode`/`rewrap*`/`modifyExpiry*` for #3; the ordinary-settings rows for #4;
   `PGPKeyIdentity` metadata + key-metadata payload for #2; shared root secret for #1; self-test
   reports + tutorial suites for #6). Bump `Last reviewed`.

**Two inventory phrasing corrections** (already applied to `LEGACY_CLEANUP.md` when this plan
landed; restated here so PR authors don't re-introduce the ambiguity):

- **Row 6** — "format-floor / legacy-cleanup markers" are reset **deletion-targets that STAY**
  (current anti-downgrade security), not removable code. #6 removes only the self-test dir +
  orphan tutorial suites + the #1/#2-gated reset hooks.
- **#9** — `LegacyFoldMode` / `legacy_stopped` are **kept** (they drive the modern summary). Only
  the `legacy_status`/`legacy_signer_fingerprint` fields (and the `PasswordDecryptResult`
  `signature_status`/`signer_fingerprint` equivalents) are removed.

## 7. Reintroduction guardrails

Two **separate** mechanisms — the Swift audit cannot see Rust, and no Rust guard exists yet.

**Swift guardrail (reuse existing).** `Tests/ServiceTests/RepositoryAuditLoader.swift` +
`ArchitectureSourceAuditTests.swift` (in `CypherAir-UnitTests`) scan a build-time snapshot of
`Sources/*.swift` only (hard-filtered to `.swift`, rooted at `Sources/`). Assert **zero matches
under `Sources/`** for the removed **Swift** symbols:

- #9 (Swift): `legacyStatus`, `legacySignerFingerprint`, `legacySignerIdentity`, `legacyVerification`.
- #2: `migrateLegacyMetadataIfNeeded`, `loadMigrationSourceSnapshot`, `cleanupMigrationSourceItems`.
- #3: `legacyInitialPayload`, `cleanupLegacyDefaults`, `invalidLegacyAuthMode`.
- #4: `requiresOrdinarySettingsMigration`, `migrateOpenedSettingsSnapshotIfNeeded`,
  `legacyOrdinarySettingsSnapshot`, `removeLegacySettingsSources`.
- #5: `LegacySnapshotV1`, `migrateLegacyV1Snapshot`.
- #1A: `legacyRightStoreClient`, `migrateLegacySharedRightIfNeeded`, `legacyMigrationDeferred`,
  `allowLegacyMigration`. #1B: `migrateLegacyRawRootSecret`, `legacyV1Raw`.
- #7: `updateRevocation`.

**Rust guardrail (new — must be created).** No Rust-side source audit exists, and the Swift
`RepositoryAuditLoader` is Swift-only (snapshot of `Sources/*.swift`) and structurally cannot read
`pgp-mobile/src`. Add a `pgp-mobile` `#[test]` that reads the crate source via `CARGO_MANIFEST_DIR`
(the idiom already used by `pgp-mobile/tests/` fixtures) and asserts these are absent from
`pgp-mobile/src/` — it runs under the existing `cargo test --manifest-path pgp-mobile/Cargo.toml`
with no CI change (a CI `rg` step over `pgp-mobile/src` is a lighter alternative):

- #9 (Rust): `legacy_status`, `legacy_signer_fingerprint` (and the `PasswordDecryptResult`
  `signature_status` / `signer_fingerprint` fields).

**Allowlist** the intentionally-kept `LegacyFoldMode` / `legacy_stopped` in the Rust guard (or
rename them to drop "legacy" so the match is unambiguous). Keep the Item-1B anti-downgrade negative
test **permanent**. Land the Swift guardrail (per-symbol exceptions) in PR-0 and the Rust guardrail
in Track D; each PR deletes its exception to prove the removal.

## 8. Riskiest steps & de-risking

1. **PR-C5 (raw-root-secret surgery) — Critical.** Trap: deleting the whole raw-length branch and
   dropping the anti-downgrade throw at `:347`. De-risk: reduce the branch to *detect → throw
   `invalidEnvelope`*; add the permanent negative test; isolate the PR (no other ProtectedData
   change in flight); human review citing the `CAPDSEF2`/device-binding keep-list.
2. **PR-C4 (legacy right-store) — Critical.** `allowLegacyMigration` threads through three
   coordinators + `AppContainer` + reset. De-risk: prove old-install fail-closed/recovery in
   tests before removing the source; unthread bottom-up (reset → session → root-secret →
   container).
3. **PR-D2 (Rust fold refactor) — High.** `summary_state`/`summary_entry_index` are computed
   *interleaved* with the removed `legacy_*` fields, and `decrypt.rs`/`streaming.rs` are §10
   files. De-risk: keep `legacy_stopped`/`mode` untouched; assert summary selection is unchanged
   via the migrated multi-signature tests; run VAL-RUST for **both profiles**; bundle D2+D3.
4. **Reset-All exhaustiveness (PR-C2/C4/C6).** The three reset sub-parts share the same
   enumeration/post-condition functions. De-risk: re-run local-reset tests in every PR that
   touches `LocalDataResetService.swift`; land PR-C6 first; diff the keep-list markers to prove
   they still delete.
5. **PR-D1 self-test gate + UI fallback — Medium but production-visible.** De-risk: confirm
   `summaryState == .verified` is exactly equivalent to the old `legacyStatus == .valid` gate for
   the single-signer self-test round-trip; verify the empty-`signatures` UI case still renders a
   correct "not signed / invalid" row before deleting `legacyVerification`.

## 9. Validation matrix

| Change family | Minimum validation |
|---------------|--------------------|
| ProtectedData / auth / key-metadata / settings / root-secret / local-reset (Tracks A–C, #7/#8) | VAL-SWIFT (ProtectedData framework, settings, private-key-control, key-metadata, auth, local-reset, device-binding) + prove fail-closed/recovery for the removed path |
| Rust / UniFFI surface (#9 PR-D2+D3) | VAL-RUST (both profiles) → VAL-XCFW → VAL-SWIFT |
| Reset-All-touching PR (#6a/b/c) | VAL-SWIFT local-reset exhaustiveness; diff keep-list deletion targets |
| Every removal PR | cite the 2026-06-08 cutoff; delete the matching PR-0 guardrail exception |

## Critical files (referenced by this plan; not edited except by the named PRs)

- `Sources/Security/ProtectedData/ProtectedDataRightStoreClient.swift` — #1A/#1B; **keep the `:347` anti-downgrade throw**.
- `Sources/Security/ProtectedData/ProtectedDataRootSecretCoordinator.swift`, `ProtectedDataSessionCoordinator.swift`, `ProtectedDataPostUnlockCoordinator.swift` — #1A plumbing.
- `Sources/App/Settings/LocalDataResetService.swift` — #6a/#6b/#6c; keep reset markers; shared by 3 PRs.
- `Sources/Security/ProtectedData/ProtectedSettingsStore.swift` + `Sources/Models/ProtectedOrdinarySettingsPersistence.swift` — #4; `LegacyOrdinarySettingsStore` not deletable.
- `Sources/Security/ProtectedData/PrivateKeyControlStore.swift` + `Sources/Security/AuthenticationEvaluable.swift` — #3; keep recovery-journal + grace-period.
- `Sources/Security/KeyMetadataStore.swift` + `Sources/Security/ProtectedData/KeyMetadataDomainStore.swift` + `Sources/Services/KeyManagement/KeyCatalogStore.swift` + `Sources/Services/KeyManagementService.swift` — #2A/#2B.
- `Sources/Security/ProtectedData/ContactsDomainSnapshotCodec.swift` — #5.
- `Sources/Models/PGPKeyIdentity.swift` + `Sources/Services/KeyManagement/KeyExportService.swift` — #8/#7.
- `pgp-mobile/src/signature_details.rs` (+ `decrypt.rs`, `external_decryptor.rs`, `verify.rs`, `streaming.rs`, `password.rs`) — #9 Rust; **keep `LegacyFoldMode`**.
- `Sources/Services/FFI/PGPMessageResultMapper.swift` + `Sources/Models/DetailedSignatureVerification.swift` + `Sources/Models/SignatureVerification.swift` + `Sources/Services/SelfTestService.swift` — #9 Swift.
- `Tests/ServiceTests/RepositoryAuditLoader.swift` + `Tests/ServiceTests/ArchitectureSourceAuditTests.swift` — **Swift** guardrail mechanism (Track 0; `Sources/*.swift` only). A new `pgp-mobile` `#[test]` is required for the **Rust** #9 symbols (Track D) — no existing Rust audit.
