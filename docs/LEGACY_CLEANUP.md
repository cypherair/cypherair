# Legacy Cleanup

> Status: Active roadmap. Inventory current-state-verified against `main`.
> Purpose: Single source for legacy upgrade/migration/compatibility code that is removable
>   later (gated), what is already removed, and what must never be removed.
> Audience: Human developers, security reviewers, and AI coding tools.
> Truth sources: current `main` source tree; [PERSISTED_STATE_INVENTORY.md](PERSISTED_STATE_INVENTORY.md);
>   [ARCHITECTURE_REFACTOR_ROADMAP.md](ARCHITECTURE_REFACTOR_ROADMAP.md); [SECURITY.md](SECURITY.md).
> Last reviewed: 2026-06-08.
> Note: This doc replaces the former `LEGACY_COMPATIBILITY_AUDIT.md` (2026-05-13 snapshot) and
>   `LEGACY_CLEANUP_IMPLEMENTATION_REFERENCE.md` (Phases 1–7 roadmap), both removed when this
>   doc landed. It catalogs candidates and gates.
> Companion execution plan: [LEGACY_CLEANUP_IMPLEMENTATION_PLAN.md](LEGACY_CLEANUP_IMPLEMENTATION_PLAN.md)
>   — ordered PR sequence for the approved 2026-06-08 cutoff.

This doc is an inventory, not an authorization to delete. Removal of any retained migration
code is gated on a human-approved support cutoff (§1) and is performed in separate PRs (§5).

## 1. Non-negotiable rule

Retained old-install migration code is deleted **only after a human maintainer explicitly
approves a support cutoff** named in the specific issue/PR. Never delete on telemetry, network,
or the argument that "production already uses the new path" — the app is zero-network and
offline, so installs that still hold a legacy source can surface at any time.

This rule is the same one stated in [ARCHITECTURE_REFACTOR_ROADMAP.md:26](ARCHITECTURE_REFACTOR_ROADMAP.md):
*keep legacy migration support until a separate human-approved support cutoff exists.*

**Cutoff status (2026-06-08):** a maintainer has approved the support cutoff for **all §2 items**.
The ordered PR sequence that consumes it lives in
[LEGACY_CLEANUP_IMPLEMENTATION_PLAN.md](LEGACY_CLEANUP_IMPLEMENTATION_PLAN.md); items move from §2
to §3 here as each removal PR lands.

## 2. Cleanup to do later (gated)

### Class 1 — Retained old-install migration (cutoff-gated)

Each item reads a legacy source, migrates it into the current ProtectedData/Keychain home,
then cleans the source up. All are **fail-closed**: the legacy source is kept until the
destination is verified. Removable only after a support cutoff for installs that could still
hold the old source.

| # | Domain | FROM → TO | Anchors | Removal gate | Risk |
|---|--------|-----------|---------|--------------|------|
| 1 | Root-secret v1/raw + legacy right-store | raw v1 root-secret / legacy `LARight` → v2 `CAPDSEV2` SE device-binding envelope | `ProtectedDataRootSecretCoordinator.swift:6` (`legacyMigrationDeferred`), `:88-118` (dispatch), `:273` (`migrateLegacySharedRightIfNeeded`); `ProtectedDataSessionCoordinator.swift:23,59-155`; `ProtectedDataPostUnlockCoordinator.swift:137` (`allowLegacyMigration:false`) | Formal cutoff for installs holding v1/raw or legacy right-store secrets | **Critical** — wrong deletion locks users out of protected data |
| 2 | Key-metadata Keychain → ProtectedData | legacy `metadataAccount` + default-account `PGPKeyIdentity` rows → `key-metadata` domain (schema v2) | `KeyMetadataStore.swift:60,79,120`; `KeyMetadataDomainStore.swift:132,169,535,542,626`; `KeyManagementService.swift:184,198`; `KeyCatalogStore.swift:26,37` | All supported installs migrated; cleanup retries no longer needed | **High** — wrong cleanup can hide keys |
| 3 | Private-key-control legacy defaults | legacy `UserDefaults` `authMode`/rewrap/modify-expiry → `private-key-control` domain | `PrivateKeyControlStore.swift:606,617,629` (reads), `:647-651` (`cleanupLegacyDefaults`), called at `:142,194,404`; keys in `AuthenticationEvaluable.swift:395-412` | Old-install migration support ends | **High** — auth-sensitive |
| 4 | Protected-settings v1 → v2 + legacy ordinary settings | schema-v1 payload (`clipboardNotice` only) + legacy `com.cypherair.preference.*` `UserDefaults` → schema-v2 ordinary settings | `ProtectedSettingsStore.swift:14` (`PayloadV1`), `:25` (`requiresOrdinarySettingsMigration`), `:850-885,896`, `:1028-1041` (`legacyOrdinarySettingsSnapshot`/`removeLegacySettingsSources`); `ProtectedOrdinarySettingsPersistence.swift:17` (`LegacyOrdinarySettingsStore`) | Supported installs expected to hold schema v2 | **High** — can reset auth-adjacent settings / fail-open |
| 6 | Local-data cleanup | removes legacy `Documents/self-test/` + orphan `com.cypherair.tutorial.<UUID>` defaults suites, and (gated on #1/#2) the legacy right-store + metadata-account reset hooks. **Keep:** the root-secret format-floor / device-binding / legacy-cleanup markers are current security — Reset-All must keep *deleting* them; they are not removable code | `AppTemporaryArtifactStore.swift:10,126` (`legacyTutorialDefaultsSuitePrefix`, `cleanupTutorialDefaultsSuites`); `AppStartupCoordinator.swift:131,134,143` (startup cleanup, `legacySelfTestReportDirectory`); `LocalDataResetService.swift:415,472` (reset enumeration + post-reset validation) | Those paths can no longer exist on supported installs | Medium — Reset-All correctness depends on exhaustive deletion |

> **Row 3 caveat:** Only the **legacy-defaults import/cleanup** is removable. The
> rewrap **recovery-journal** logic in the same file is current behavior — keep it.

Authoritative migration-readiness for rows 2–4 lives in
[PERSISTED_STATE_INVENTORY.md:45-57,61](PERSISTED_STATE_INVENTORY.md) — all marked
`Implemented` (migration done; legacy source kept **only** as a verified cleanup source).

### Class 2 — Removable later, newly surfaced

These are real legacy-compat paths with explicit "predate … support" / "retained for
migration" comments. They were absent from the prior audit's inventory table and are folded in
here.

| # | Item | What it does | Anchors | Removal gate |
|---|------|--------------|---------|--------------|
| 7 | Imported-key revocation backfill | for imported keys whose stored `revocationCert` is empty (keys that predate revocation-construction support), generates + persists the binary revocation lazily at export time, then zeroizes the temporarily-unwrapped secret | `PGPKeyIdentity.swift:70-73` (comment *"backfilled on demand for imported keys that predate revocation-construction support"*), `:162`; `KeyExportService.swift:51-79` (`exportRevocationCertificate()` — zeroize via `defer`, generate, persist to catalog) | After all on-device keys are guaranteed to carry a revocation artifact — tie to the key-metadata cutoff (#2) |
| 8 | `PGPKeyIdentity` legacy Codable decode | tolerant decode of metadata rows written before `openPGPConfigurationIdentity` / `privateKeyCustodyKind` existed — `decodeIfPresent(...) ?? <profile default>` fallbacks | `PGPKeyIdentity.swift:8` (comment *"legacy Keychain decoding retained for migration"*), `:147-154` | After all on-device metadata is re-encoded under `key-metadata` schema v2 — same cutoff as #2 |

### Class 3 — Active compatibility surface, removable after a Swift-side rework (not cutoff-gated)

| # | Item | Status | Anchors |
|---|------|--------|---------|
| 9 | Rust `legacy_status` / `legacy_signer_fingerprint` | **Swift consumers retired (PR-D1, 2026-06-08 cutoff).** The folded-summary fields still **remain inside the Rust detailed result + generated bindings**, now referenced only by FFI-result test fixtures; deleted in PR-D2+D3. | Rust: `signature_details.rs:38-85` (4 detailed-result structs + `LegacyFoldMode`; `SignatureCollector` `:89-212`), produced in `decrypt.rs:211-221`, `external_decryptor.rs:144-154`, `verify.rs`, `streaming.rs`, `password.rs`. Swift app-model consumers (now on `summaryState`/`signatures`): `PGPMessageResultMapper.swift`, `DetailedSignatureVerification`, `DetailedSignatureSectionView`, `SelfTestService`; generated `pgp_mobile.swift` legacy fields remain until PR-D2+D3. |

**Removal gate / progress:** The Swift-side migration is **done** under the 2026-06-08 cutoff —
PR-D1 repointed every Swift consumer (`PGPMessageResultMapper`, the `DetailedSignatureVerification`
app model, `DetailedSignatureSectionView`, and the test suite) to `summaryState` / `signatures`, and
closed the former blocker at **`SelfTestService.swift`** (self-test pass/fail now gates on
`summaryState == .verified`). `Sources/` carries zero references to the app-model legacy fields.
**Remaining for full retirement:** delete the Rust `legacy_status`/`legacy_signer_fingerprint` fields
(and the `PasswordDecryptResult` equivalents) and regenerate the bindings in **PR-D2+D3**, then make
the §2→§3 inventory move in **PR-D4**. Until then the FFI fields remain present, referenced only by
FFI-result test fixtures.

Scope note: only the `legacy_status`/`legacy_signer_fingerprint` fields (and the
`PasswordDecryptResult.signature_status`/`signer_fingerprint` equivalents) are removed.
`LegacyFoldMode`/`legacy_stopped` are **kept** — they also drive the modern
`summaryState`/`summaryEntryIndex`.

**Surfaced follow-up (not #9 scope; recorded by PR-D1).** Retiring the Swift legacy layer left
state-model debt worth a separate, non-cutoff cleanup:
- `SignatureVerification` still carries both a graded `status` (`MessageSignatureStatus`) and a
  `verificationState` that can disagree. The message-row display already derives solely from
  `verificationState` (`SignatureVerification+Presentation.swift`), so `status` is near-vestigial in
  the message path. A "collapse the signature state model" pass could remove or fold `status` into
  `verificationState` (note: `status` is still read by the **separate** `CertificateSignatureVerification`
  path, which is unaffected).
- `verify.rs` / `streaming.rs` can return an **empty `signatures` array with a failure `summaryState`**
  (`Invalid`/`Expired`) on verifier-setup failure, so "empty signatures" is **not** equivalent to "not
  signed"; the no-entries UI row renders from `summaryState` (`DetailedSignatureVerification.summaryVerification`).
- Broader direction: after this cleanup wave, sweep for other stale compatibility layers that left
  similarly complex app state behind.

## 3. Already done — do not re-chase

Confirmed absent on current `main` (verified 2026-06-08); listed so this inventory is a
complete map. Source-audit guardrails in [ARCHITECTURE_REFACTOR_ROADMAP.md](ARCHITECTURE_REFACTOR_ROADMAP.md)
block reintroduction.

- Flat `Contact`, `ContactRepository`, `ContactsLegacyMigrationSource`, `ContactsCompatibilityMapper` — **0 hits**. The current model is granular (`ContactIdentity`, `ContactKeyRecord`, …).
- No-caller `ContactService` fingerprint-recipient helpers and overloads.
- Simple Rust/UniFFI `decrypt` / `decrypt_file` / `verify_cleartext` / `verify_detached` / `verify_detached_file` (+ generated Swift) — only the `*_detailed` variants remain.
- Raw first-match User-ID FFI (`generate_user_id_certification`, `generate_user_id_revocation`, `verify_user_id_binding_signature`, `find_user_id_first_match`) — only the `*_by_selector` variants remain.
- Tracked `scripts/experiments/` — removed (`6c4356e`, `a2c00b2`).
- Contacts snapshot v1→v2 migration (`LegacySnapshotV1`, `migrateLegacyV1Snapshot`, decode `case 1`, and the `ContactsDomainStore` upgrade-on-read writeback) — removed under the 2026-06-08 cutoff (PR-A1). A schema v1 payload now fails closed via the unsupported-version `default` (routes the Contacts domain to recovery, never a silent reset); the fail-closed `default` is **kept**.

## 4. Do NOT remove — permanent interop / security

These read as "legacy" by keyword but are intentional interop or active security (see
[SECURITY.md](SECURITY.md) §1). Removing them breaks interoperability or weakens security.

- **Interop read-compat:** reads v4 keys, SEIPDv1/MDC, SEIPDv2 (OCB/GCM), DEFLATE input (read-only), SHA-256 *legacy verification*; S2K auto-detect on import (Iterated+Salted vs Argon2id) — `pgp-mobile/src/keys/s2k.rs:24` (`parse_s2k_params`), `pgp-mobile/src/keys/secret_transfer.rs`. Removing breaks GnuPG / OpenPGP.js / GopenPGP / Bouncy Castle interop.
- **Active anti-downgrade:** root-secret **format-floor** marker `CAPDSEF2` (`ProtectedDataDeviceBinding.swift:192`) and the SE device-binding envelope — current security, not cleanup debt.
- **Profile / message-format selection:** v4 → SEIPDv1, mixed → SEIPDv1, v6 → SEIPDv2 (`pgp-mobile/src/encrypt.rs:229-231`); Standard-mode passcode-fallback language; current temp/export artifact cleanup; alternate app icons; QR import route/version.

## 5. Removal procedure & validation matrix

Every PR that actually deletes retained code (out of scope for the inventory itself) must:

1. Name the **human-approved support cutoff** in the issue/PR (§1).
2. Prove old-install **fail-closed / recovery / reset** behavior for the removed migration.
3. Run the matching validation below.

| Cleanup family | Minimum validation |
|----------------|--------------------|
| ProtectedData / Keychain / auth / root-secret / settings / key-metadata migration (Class 1 rows 1–6; Class 2 #7–#8) | `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'` (ProtectedData framework, settings, private-key-control, key-metadata, auth, local-reset, device-binding) |
| Rust / UniFFI surface change (only if #9 is retired) | `cargo +stable test --manifest-path pgp-mobile/Cargo.toml`, then refresh the XCFramework (per [TESTING.md](TESTING.md)) and re-run the macOS unit tests |
| Public Swift / UniFFI surface removal | Confirm no remaining caller, then the relevant matrix row above |

## 6. Forward-looking — not current code

The **unshipped** auth-lifecycle redesign ([SECURITY.md](SECURITY.md) §4) will, when it lands,
**add two new one-time macOS migrations** to this inventory:

- force-re-wrap of macOS Standard keys, dropping `.devicePasscode`;
- root-secret re-protection `[.userPresence] → [.biometryAny]`.

These are future *additions*, not present removable code.
