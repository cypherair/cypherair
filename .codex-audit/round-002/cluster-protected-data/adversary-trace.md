# Adversary Trace: cluster-protected-data

## Scope Notes

- Did not edit repository source files or update the git index.
- Wrote only `adversary.md` and this `adversary-trace.md` in the requested output directory.
- Did not read `investigator-trace.md`.

## Required Inputs Read

- `docs/CODEX_SECURITY_REVIEW_INDEX.md`
  - Lines 48 and 74 identify CA-10 and CA-36, status `to-check`, severity, title, and relevant paths.
- `codex-security-findings-2026-05-29T13-11-03.346Z.csv`
  - Line 11 is the CA-10 source finding text.
  - Line 37 is the CA-36 source finding text.
- `.codex-audit/round-002/cluster-protected-data/investigator.md`
  - Lines 1-31: CA-10 investigator conclusion and evidence.
  - Lines 33-63: CA-36 investigator conclusion and evidence.

## Commands Run

- `rg -n "CA-10|CA-36|ProtectedData|protected data|wrapped|DMK|root-secret|relock|registry|recovery" docs/CODEX_SECURITY_REVIEW_INDEX.md`
- `rg -n "CA-10|CA-36" codex-security-findings-2026-05-29T13-11-03.346Z.csv`
- `sed -n '1,240p' .codex-audit/round-002/cluster-protected-data/investigator.md`
- `rg --files Sources/Security Sources/Services Sources/Models Tests docs | rg "ProtectedData|Keychain|SecureEnclave|Authentication|Decryption|PERSISTED|SECURITY|ARCHITECTURE|TESTING|CODE_REVIEW"`
- `rg --files -g 'codex-security-findings-2026-05-29T13-11-03.346Z.csv' -g '*.csv'`
- `sed -n '1,140p' codex-security-findings-2026-05-29T13-11-03.346Z.csv`
- `rg -n "TOCTOU can delete active protected-data root secret|Malformed protected settings envelope can crash app" codex-security-findings-2026-05-29T13-11-03.346Z.csv`
- `rg -n "cleanupOrphanedSharedRightIfSafe|ProtectedDataFirstDomainSharedRightCleaner|performCreateDomainTransaction|performDeleteDomainTransaction|open\\(|openProtectedSettings|protectedSettings|loadRegistry\\(|readAuthoritativeSnapshot|current|previous|pending" Sources/Security/ProtectedData Sources/App/AppContainer.swift Sources/App/CypherAirApp.swift Tests/ServiceTests/ProtectedDataFrameworkTests.swift`
- `rg -n "ProtectedSettingsHost|ensureCommittedAndMigrateSettingsIfNeeded|openDomainIfNeeded|authorizeSharedRight|recoverPendingMutation|resetDomain|Task|async" Sources/App/Settings Sources/App/Common Sources/App -g '*.swift'`
- `rg -n "beginAppAuthentication|postAuthenticationHandler|evaluateProtectedDataAccessGate|consumeAuthenticatedContext|hasProtectedDataAuthorizationHandoffContext" Sources/Security/ProtectedData/AppSessionOrchestrator.swift Sources/App -g '*.swift'`
- `rg -n "protocol ProtectedDataRootSecretStoreProtocol|final class KeychainProtectedDataRootSecretStore|struct KeychainProtectedDataRootSecretStore|saveRootSecret|deleteRootSecret|rootSecretExists|loadRootSecret" Sources/Security Sources -g '*.swift'`
- `rg -n "ProtectedDomainEnvelopeCodec\\.open|ProtectedDomainEnvelopeCodec\\.seal|ProtectedDomainEnvelope" Sources/Security/ProtectedData Sources/Services -g '*.swift'`
- `rg -n "FirstDomainSharedRight|cleanupOrphaned|removedOrphaned|blockedByArtifacts|orphaned shared|root secret|Malformed protected settings|schemaVersion|generationIdentifier" Tests/ServiceTests/ProtectedDataFrameworkTests.swift Tests -g '*.swift'`
- `rg -n "ProtectedSettings.*Future|protectedSettings.*unsupported|highest observed|authoritative|recoveryNeeded|invalidEnvelope" Tests/ServiceTests/ProtectedDataFrameworkTests.swift`
- `rg -n "ProtectedData|protected data|root secret|shared right|registry|pending mutation|recovery|Application Support|file protection|settings" docs/ARCHITECTURE.md docs/SECURITY.md docs/TESTING.md docs/PERSISTED_STATE_INVENTORY.md docs/CODE_REVIEW.md`
- `ls -la .codex-audit/round-002/cluster-protected-data`
- `git status --short`
- `wc -l .codex-audit/round-002/cluster-protected-data/investigator.md docs/CODEX_SECURITY_REVIEW_INDEX.md codex-security-findings-2026-05-29T13-11-03.346Z.csv`

## CA-10 Source References

- `Sources/Security/ProtectedData/ProtectedDataFirstDomainSharedRightCleaner.swift`
  - Lines 28-37: cleanup accepts caller-supplied registry and trusts its pending/membership/lifecycle state.
  - Lines 39-50: checks root-secret existence and non-registry artifacts, then deletes the persisted shared right without reloading registry.
- `Sources/Security/ProtectedData/ProtectedDataRegistryStore.swift`
  - Lines 8-18: mutation gate is an actor used by registry mutations.
  - Lines 142-198: create-domain transaction journals, awaits shared resource provisioning, stages artifacts, validates, and commits membership.
  - Lines 156-167: first-domain pending journal is saved, then shared resource provisioning is awaited before `sharedResourceProvisioned`.
  - Lines 169-175: artifact staging happens only after shared resource provisioning.
  - Lines 185-196: membership and `sharedResourceLifecycleState = .ready` are committed only near transaction end.
  - Lines 359-407: pending mutation recovery also runs under the same mutation gate.
- `Sources/Security/ProtectedData/ProtectedDataStorageRoot.swift`
  - Lines 43-71: registry and domain file layout under `ProtectedData`.
  - Lines 113-126: artifact check excludes the registry file and only detects other root entries.
  - Lines 204-263 and 355-385: persistent storage validation and path containment.
  - Lines 265-321: protected writes and file protection verification.
- `Sources/Security/ProtectedData/ProtectedDataRootSecretCoordinator.swift`
  - Lines 36-65: `persistSharedRight` saves the root secret and then awaits registry envelope-floor recording.
  - Lines 67-91: `removePersistedSharedRight` deletes the root-secret row.
  - Lines 134-136: root-secret existence check.
- `Sources/Security/ProtectedData/ProtectedDataRightStoreClient.swift`
  - Lines 74-115: Keychain root-secret save.
  - Lines 177-193: Keychain root-secret delete.
  - Lines 195-225: root-secret existence check treats auth/interaction-blocked statuses as existence.
- `Sources/Security/ProtectedData/PrivateKeyControlStore.swift`
  - Lines 63-103: first-domain bootstrap loads registry, checks empty state, runs the cleaner, then proceeds.
  - Lines 118-136: private-key-control first-domain create transaction persists shared right and stages/validates payload.
- `Sources/Security/ProtectedData/ProtectedSettingsStore.swift`
  - Lines 186-327: protected-settings create/migration path; lines 272-290 run the cleaner for first-domain creation, and lines 304-322 create the first domain.
  - Lines 418-470: protected-settings reset can call create/migration again.
- `Sources/App/AppContainer.swift`
  - Lines 181-196: production cleaner wiring to session coordinator.
  - Lines 216-239: protected-settings post-unlock opener wiring.
  - Lines 442-490: post-unlock opener order includes private-key-control, key-metadata, protected-settings, sentinel.
  - Lines 508-520: post-auth handler awaits private-key-control first-domain bootstrap before post-unlock opening.
- `Sources/Security/ProtectedData/ProtectedDataPostUnlockCoordinator.swift`
  - Lines 120-123: post-unlock open skips when no committed ready protected domain exists.
  - Lines 159-181: registered domain openers are processed sequentially against refreshed registry state.
- `Sources/App/Settings/ProtectedSettingsHost.swift`
  - Lines 5-7: UI-facing protected settings host is `@MainActor`.
  - Lines 198-282: refresh path can auto-open protected settings.
  - Lines 290-320: user actions can trigger unlock, mutation, retry, or reset.
  - Lines 332-368: content-clear/post-auth refresh tasks call refresh.
- `Sources/App/Settings/ProtectedSettingsAccessCoordinator.swift`
  - Lines 4-5: access coordinator is `@MainActor`.
  - Lines 365-610: protected-settings ensure/open flow.
  - Lines 424-460: no-domain path checks migration authorization, then calls ensure/create.
  - Lines 536-553 and 571-575: authorized/already-authorized paths can call ensure/create.
- `Sources/Security/ProtectedData/AppSessionOrchestrator.swift`
  - Lines 295-325: app authentication stores context and awaits post-auth handler.
  - Lines 472-495: context consumption/borrowing used by protected settings and metadata migration.
  - Lines 498-506: access-gate evaluation.
- `Sources/Security/ProtectedData/ProtectedDataAccessGateClassifier.swift`
  - Lines 15-37: first protected access may use startup bootstrap outcome; later access reloads current registry.
  - Lines 44-67: empty registry maps to no protected domain, pending mutation maps to recovery.
- `Tests/ServiceTests/LocalDataResetServiceTests.swift`
  - Lines 407-434: standalone cleaner deletes root secret for empty registry/no artifacts.
  - Lines 436-465: standalone cleaner blocks when artifacts remain.

## CA-36 Source References

- `Sources/Security/ProtectedData/ProtectedDataDomain.swift`
  - Lines 207-241: `ProtectedDomainEnvelope` contract validates format, positive schema/generation, nonce/tag lengths, and nonempty ciphertext.
  - Lines 276-294: `open` validates contract, builds AAD, then opens AES-GCM.
  - Lines 310-313: AAD appends `UInt16(schemaVersion)` and `UInt32(generationIdentifier)`.
  - Lines 303-309 and 310-313: `domainID` length is also narrowed to `UInt16`.
- `Sources/Security/ProtectedData/ProtectedSettingsStore.swift`
  - Lines 541-557: writer validates a freshly written pending envelope by decoding and opening it.
  - Lines 597-631: authoritative snapshot loops over current/previous/pending, decodes and opens each envelope inside `do/catch`.
  - Lines 634-646: unreadable highest generation causes recovery via thrown `invalidEnvelope`.
  - Lines 755-799: committed upgrade maps invalid envelope/length errors to recovery-required.
  - Lines 885-913: unsupported in-range schema versions throw `invalidEnvelope`.
- Shared codec consumers:
  - `Sources/Security/ProtectedData/ContactsDomainStore.swift`: open/seal references at lines 252, 264-265, 318, 323.
  - `Sources/Security/ProtectedData/ProtectedDataFrameworkSentinelStore.swift`: open/seal references at lines 204, 216-217, 264-265.
  - `Sources/Security/ProtectedData/PrivateKeyControlStore.swift`: open/seal references at lines 484, 496-497, 544-545.
  - `Sources/Security/ProtectedData/KeyMetadataDomainStore.swift`: open/seal references at lines 374, 386-387, 440, 446.
- `Tests/ServiceTests/ProtectedDataFrameworkTests.swift`
  - Lines 427-479: protected-settings test helper writes envelopes through the normal codec.
  - Lines 4338-4375 and 4379-4426: corrupt protected-settings committed payloads require recovery.
  - Lines 5175-5217: unsupported key-metadata future schema requires recovery.

## Documentation References

- `docs/SECURITY.md`
  - Lines 217-222: protected-domain payloads open only after app privacy auth and skip pending/no-domain states.
  - Lines 323-356: ProtectedData invariants, registry authority, fail-closed recovery, root-secret/DMK clearing, and storage-root expectations.
- `docs/PERSISTED_STATE_INVENTORY.md`
  - Lines 45-69: protected-data persisted state locations, including protected-settings, private-key-control, key-metadata, root secret, registry, and domain payloads.
  - Lines 81-96: migration rules require corrupted committed protected state to become recovery and avoid silent reset.
- `docs/ARCHITECTURE.md`
  - Lines 238-262: ProtectedData component ownership.
  - Lines 271-276: current-state notes on startup bootstrap, access re-checks, and protected-settings auto-open handoff.
  - Lines 515-516: pre-auth startup may classify registry/bootstrap only, while pending/framework recovery blocks open.
