# Investigator Trace

## Resolution

- Read `docs/CODEX_SECURITY_REVIEW_INDEX.md` with `rg -n "CA-10|CA-36|finding_url" ...`.
- Matched by `finding_url` in `codex-security-findings-2026-05-29T13-11-03.346Z.csv`:
  - CA-10 -> `https://chatgpt.com/codex/cloud/security/findings/9fd5a847678881918e0eea9cbdfc2e77` (CSV match line 11).
  - CA-36 -> `https://chatgpt.com/codex/cloud/security/findings/ebf86edb2698819185b2a21d6a21ed94` (CSV match line 37).
- Apple docs lookup not available. `tool_search` exposed XcodeBuildMCP simulator/build tools but no Apple/Xcode DocumentationSearch tool.

## Commands / Files Inspected

- `rg -n "CA-10|CA-36|finding_url" docs/CODEX_SECURITY_REVIEW_INDEX.md codex-security-findings-2026-05-29T13-11-03.346Z.csv`
- `rg -n "9fd5a847678881918e0eea9cbdfc2e77|ebf86edb2698819185b2a21d6a21ed94" codex-security-findings-2026-05-29T13-11-03.346Z.csv`
- `rg -n "ProtectedDataFirstDomainSharedRightCleaner|PrivateKeyControlStore|ProtectedDomainRecoveryCoordinator|ProtectedDataRegistryStore|ProtectedDataSessionCoordinator|ProtectedDataDomain" Sources/Security/ProtectedData Sources -g '*.swift'`
- `rg -n "cleanupOrphanedSharedRightIfSafe|performCreateDomainTransaction|persistSharedRight|provisionSharedResourceIfNeeded|firstDomainSharedRightCleaner|ProtectedDomainEnvelope|schemaVersion|generationIdentifier|UInt16|UInt32|envelopeAAD|validateContract|open\\(" Sources/Security/ProtectedData Sources/App -g '*.swift'`
- `rg -n "FirstDomainSharedRightCleaner|cleanupOrphanedSharedRightIfSafe|orphanedSharedRight|schemaVersion|generationIdentifier|UInt16\\(|UInt32\\(|invalidEnvelope|protected settings" Tests Sources -g '*.swift'`
- `rg -n "Int.max|UInt16.max|UInt32.max|out of range|too large|malformed|overflow|trap|large schema|large generation" Tests Sources docs -g '*.swift' -g '*.md'`
- Targeted reads:
  - `Sources/Security/ProtectedData/ProtectedDataFirstDomainSharedRightCleaner.swift`
  - `Sources/Security/ProtectedData/ProtectedDataRegistryStore.swift`
  - `Sources/Security/ProtectedData/ProtectedDataRegistry.swift`
  - `Sources/Security/ProtectedData/ProtectedDataSessionCoordinator.swift`
  - `Sources/Security/ProtectedData/ProtectedDataRootSecretCoordinator.swift`
  - `Sources/Security/ProtectedData/ProtectedDataRightStoreClient.swift`
  - `Sources/Security/ProtectedData/PrivateKeyControlStore.swift`
  - `Sources/Security/ProtectedData/ProtectedSettingsStore.swift`
  - `Sources/Security/ProtectedData/ProtectedDataDomain.swift`
  - `Sources/Security/ProtectedData/ProtectedDataStorageRoot.swift`
  - `Sources/Security/ProtectedData/ProtectedDomainRecoveryCoordinator.swift`
  - `Sources/App/AppContainer.swift`
  - `Sources/App/CypherAirApp.swift`
  - `Tests/ServiceTests/LocalDataResetServiceTests.swift`
  - `Tests/ServiceTests/ProtectedDataFrameworkTests.swift`
  - `docs/SECURITY.md`
  - `docs/ARCHITECTURE.md`
  - `docs/TESTING.md`

## Key Evidence

### CA-10

- `ProtectedDataFirstDomainSharedRightCleaner.swift:28-52`: cleanup checks only the supplied `registry`; if it is empty/absent, it checks Keychain root-secret existence, checks non-registry artifacts, then calls `removePersistedSharedRight`.
- `ProtectedDataStorageRoot.swift:113-126`: artifact check excludes `ProtectedDataRegistry.plist`, so a just-journaled first-domain transaction can still appear artifact-free until staging.
- `ProtectedDataRegistryStore.swift:142-199`: first-domain create runs under `mutationGate`, saves pending `.journaled`, calls `provisionSharedResourceIfNeeded`, then stages artifacts and commits membership. Cleaner is not part of this gate.
- `ProtectedDataRootSecretCoordinator.swift:36-65` and `ProtectedDataRightStoreClient.swift:74-115`: provisioning saves the Keychain root secret before the create transaction stages artifacts.
- `ProtectedDataRootSecretCoordinator.swift:67-91` and `ProtectedDataRightStoreClient.swift:177-193`: deletion removes the Keychain item directly.
- `PrivateKeyControlStore.swift:63-142` and `ProtectedSettingsStore.swift:186-327`: both first-domain bootstrap paths load a registry snapshot, optionally run the cleaner, then call `performCreateDomainTransaction`.
- `AppContainer.swift:181-196`, `AppContainer.swift:508-516`, and `CypherAirApp.swift:87-95`: production wiring constructs and passes the cleaner into post-auth and protected-settings paths.
- `LocalDataResetServiceTests.swift:421-469`: tests cover standalone orphan removal and blocking when artifacts exist. I found no test that races cleanup against first-domain creation or validates a current-registry recheck before deletion.

### CA-36

- `ProtectedDataDomain.swift:207-241`: `ProtectedDomainEnvelope` stores `schemaVersion` and `generationIdentifier` as `Int`; validation checks positivity only.
- `ProtectedDataDomain.swift:276-296`: `open()` calls `validateContract()`, then computes AAD.
- `ProtectedDataDomain.swift:316-337`: AAD appends `UInt16(schemaVersion)` and `UInt32(generationIdentifier)`; out-of-range exact conversions trap rather than throw.
- `ProtectedSettingsStore.swift:578-650`: protected settings reads current/previous/pending envelopes inside a `do/catch`, but a trap in `ProtectedDomainEnvelopeCodec.open()` cannot be caught and converted into recovery.
- `ProtectedSettingsStore.swift:755-799`: thrown `ProtectedDataError.invalidEnvelope` would be classified as recovery, confirming intended fail-closed behavior for recoverable errors.
- `ProtectedSettingsStore.swift:885-914`: in-range unsupported schema values throw `invalidEnvelope`; this does not cover out-of-range values that trap earlier in AAD construction.
- `ProtectedDataFrameworkTests.swift` has tests for corrupt protected settings and unsupported in-range schemas, but `rg` found no tests for `UInt16.max`, `UInt32.max`, out-of-range schema/generation, or crash/trap behavior.
