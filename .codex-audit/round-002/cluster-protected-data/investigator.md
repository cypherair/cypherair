# Round 2 Investigator: cluster-protected-data

## CA-10: TOCTOU can delete active protected-data root secret

- Relevant code locations:
  - `Sources/Security/ProtectedData/ProtectedDataFirstDomainSharedRightCleaner.swift:28`
  - `Sources/Security/ProtectedData/ProtectedDataRegistryStore.swift:142`
  - `Sources/Security/ProtectedData/PrivateKeyControlStore.swift:63`
  - `Sources/Security/ProtectedData/ProtectedSettingsStore.swift:186`
  - `Sources/Security/ProtectedData/ProtectedDataSessionCoordinator.swift:45`
  - `Sources/Security/ProtectedData/ProtectedDataRootSecretCoordinator.swift:36`
  - `Sources/App/AppContainer.swift:181`
  - `Sources/App/AppContainer.swift:508`
  - `Sources/App/CypherAirApp.swift:87`
- Mechanism-present status: Present. The cleaner accepts a caller-supplied `ProtectedDataRegistry`, checks that snapshot for empty steady state, then checks Keychain root-secret existence and non-registry artifacts before deleting the persisted shared root secret. It does not reload the registry immediately before deletion and does not execute under `ProtectedDataRegistryStore`'s `mutationGate`. First-domain creation journals the pending create, persists the root secret, and only then stages domain artifacts, leaving a window where a stale empty-registry cleaner call can see the root secret but no artifacts.
- Shipped reachability: Reachable in production code paths, but as a local process concurrency/availability-data-loss condition rather than a remote input. Production wires the cleaner into private-key-control first-domain bootstrap after app authentication and into protected-settings first-domain creation/migration/reset paths. A practical trigger requires overlapping first-domain work using a stale empty-registry snapshot while another first-domain transaction has persisted the root secret but has not staged artifacts.
- Mitigations:
  - Registry mutation operations themselves are serialized by `ProtectedDataRegistryStore`'s actor gate.
  - `performCreateDomainTransaction` writes a pending create journal before provisioning the shared root secret; a fresh registry read would block cleanup.
  - Cleanup refuses to delete when non-registry ProtectedData artifacts already exist.
  - Recovery classification treats pending mutations and corrupt/missing domain state as recovery instead of silently opening data.
- Evidence-real:
  - `cleanupOrphanedSharedRightIfSafe` guards only the passed-in snapshot, then deletes via `removePersistedSharedRight` without a current registry recheck.
  - `hasProtectedDataArtifactsExcludingRegistry` ignores the registry file, so it can return false before `stageArtifacts` creates a domain directory or envelope.
  - `performCreateDomainTransaction` persists the shared resource at the first-domain point before staging artifacts.
  - Existing tests cover standalone cleanup/no-cleanup cases but not a concurrent stale-snapshot race against first-domain creation.
- Evidence-false-positive:
  - If the cleaner reloaded the current registry after the transaction journal was saved, the pending mutation would make it return `.notNeeded`; the vulnerable path depends on stale snapshot timing.
  - The race is narrow and local to app-owned ProtectedData bootstrap flows. Normal sandboxed third-party apps cannot directly invoke it or write the protected-data root.
- Preliminary disposition: Likely real / fix-worthy. Likely fix direction is to serialize orphan cleanup with registry mutations, or reload and validate current registry state under the same mutation gate immediately before deleting the root secret.
- Confidence: Medium-high.
- Open questions:
  - Which shipped UI/post-auth paths can overlap first-domain private-key-control bootstrap and protected-settings first-domain creation on a fresh install?
  - Should first-domain callers also revalidate whether they are still first-domain inside `performCreateDomainTransaction` before using a locally generated root key?

## CA-36: Malformed protected settings envelope can crash app

- Relevant code locations:
  - `Sources/Security/ProtectedData/ProtectedDataDomain.swift:207`
  - `Sources/Security/ProtectedData/ProtectedDataDomain.swift:276`
  - `Sources/Security/ProtectedData/ProtectedDataDomain.swift:316`
  - `Sources/Security/ProtectedData/ProtectedSettingsStore.swift:578`
  - `Sources/Security/ProtectedData/ProtectedSettingsStore.swift:755`
  - `Sources/Security/ProtectedData/ProtectedSettingsStore.swift:885`
  - `Sources/Security/ProtectedData/ProtectedDomainRecoveryCoordinator.swift:25`
- Mechanism-present status: Present. `ProtectedDomainEnvelope.validateContract()` requires only positive `schemaVersion` and `generationIdentifier`. `ProtectedDomainEnvelopeCodec.open()` then builds AAD with `UInt16(schemaVersion)` and `UInt32(generationIdentifier)`. Swift exact integer narrowing traps on out-of-range values, so a decoded envelope with very large positive values can terminate the process before the surrounding `do/catch` can convert the malformed data into recovery.
- Shipped reachability: Reachable when opening app-owned protected-settings `current`, `previous`, or `pending` plist files from persistent ProtectedData storage. This is primarily local availability/corrupt-state reachability: normal third-party apps should not be able to write the app sandbox, but malformed persisted app data, restore artifacts, local tampering, or an app bug could hit the path.
- Mitigations:
  - Protected settings files live under the app ProtectedData root with file-protection/containment checks.
  - `ProtectedSettingsStore` catches thrown decode/open/payload errors and normally marks the domain `.recoveryNeeded`.
  - Corrupt committed protected settings are covered by recovery tests for ordinary malformed payloads and unsupported in-range schema versions.
- Evidence-real:
  - The bounds check accepts any positive `Int`; it does not enforce `schemaVersion <= UInt16.max` or `generationIdentifier <= UInt32.max`.
  - The narrowing conversions occur before AES-GCM open and are not throwing APIs, so they bypass `catch { continue }` in `ProtectedSettingsStore.readAuthoritativeSnapshot`.
  - The protected-settings committed-upgrade error mapper would treat thrown `invalidEnvelope` as recovery, but it cannot catch a trap.
- Evidence-false-positive:
  - The malformed envelope must already be in app-owned persistent storage; there is no network or normal cross-app write path.
  - In-range malformed envelopes are generally handled as thrown errors and converted to recovery.
- Preliminary disposition: Real / low-severity fix-worthy. Likely fix direction is to validate all integer fields used in AAD against their encoded widths before conversion, and return `ProtectedDataError.invalidEnvelope` instead of trapping.
- Confidence: High.
- Open questions:
  - Should the same AAD-width validation also cover `domainID.rawValue` byte length and all non-settings `ProtectedDomainEnvelope` consumers?
  - Is there any supported backup/restore or migration path that can introduce malformed ProtectedData plist files without local filesystem access?
