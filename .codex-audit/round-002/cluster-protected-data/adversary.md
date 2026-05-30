# Round 2 Adversary: cluster-protected-data

## CA-10: TOCTOU can delete active protected-data root secret

### Challenge Summary

The mechanism is plausible, but the shipped impact is narrower than the finding title implies. This is not attacker-controlled input and not cross-app or remote reachability. It requires a fresh empty ProtectedData registry, two app-owned first-domain creation/cleanup paths overlapping at a very specific point, and a caller carrying an empty registry snapshot loaded before the other create transaction journals. The most realistic consequence is local ProtectedData availability loss/reset, not plaintext or private-key disclosure.

### Strongest Evidence Against Real Impact

- Shipped storage is app-owned: the root secret is in Keychain and domain files are under `Application Support/ProtectedData`; normal third-party apps should not be able to invoke the cleaner or tamper with those files directly.
- The cleaner refuses to delete unless the caller-provided registry is empty, has no pending mutation, and reports the shared resource absent, and it also blocks if any non-registry artifact exists.
- `performCreateDomainTransaction` journals a pending create before provisioning the first shared root secret. Any cleaner that reloads the current registry after that journal sees a pending mutation and returns `.notNeeded`.
- The normal post-auth flow awaits private-key-control first-domain bootstrap before running the post-unlock opener sequence, and the post-unlock coordinator only proceeds when the current registry already has committed ready membership.
- Protected settings UI/access code is `@MainActor`, so this needs Swift actor/task reentrancy and overlapping UI/auth tasks, not ordinary parallel external requests.

### Strongest Evidence Supporting Real Impact

- `cleanupOrphanedSharedRightIfSafe` trusts the passed-in registry snapshot through deletion. It checks root-secret existence and filesystem artifacts, then deletes the Keychain root secret without reloading the registry.
- `performCreateDomainTransaction` awaits `provisionSharedResourceIfNeeded` after saving the first-domain journal and before creating domain artifacts. While suspended, the actor-based mutation gate can interleave other actor messages.
- `persistSharedRight` writes the Keychain root-secret row before recording the registry envelope floor, so a competing stale cleaner can observe the root secret.
- `hasProtectedDataArtifactsExcludingRegistry` can remain false until `stageArtifacts` creates the first domain directory/envelopes.
- If deletion wins, the create transaction can still finish using the in-memory root key and commit registry membership, leaving committed protected data whose root secret is missing.

### Practical Shipped Scenario

Most plausible: first launch or post-reset app authentication starts private-key-control first-domain bootstrap. At nearly the same time, a protected-settings access task that already loaded the empty registry reaches its first-domain orphan cleaner after private-key-control has persisted the root secret but before it has staged artifacts. The stale cleaner deletes the root secret, then private-key-control finishes and commits membership. Subsequent ProtectedData authorization cannot load the root secret and the app enters framework/domain recovery until reset.

This is a narrow local race. I did not find evidence of an attacker-supplied file/import/network path that can trigger it directly. The strongest shipped overlap candidates are settings/clipboard protected-settings tasks and SwiftUI refresh tasks around app authentication; the code supports reentrancy, but the exact UI timing remains the weak link.

### Final Recommendation

`real-low`

Fix-worthy as state-machine hardening, but severity should be framed as local availability/data-loss. The clean fix is small: serialize orphan cleanup with registry mutations, or reload and validate the current registry under the same mutation gate immediately before deleting the root secret.

### Confidence

Medium.

### Questions For Main Discussion

- Can the main app or macOS Settings scene make a protected-settings access task overlap first-domain private-key-control bootstrap on a fresh install/reset in practice, or only in tests/synthetic scheduling?
- Should any cleanup path be allowed to make deletion decisions from a registry snapshot that was not loaded under the same serialized mutation operation?
- Should first-domain provisioning mark a registry state that distinguishes "root secret provisioned but shared resource not ready" before any await that can interleave?

## CA-36: Malformed protected settings envelope can crash app

### Challenge Summary

The trap mechanism is real, but the shipped security impact is low. The malformed envelope must already exist in app-owned ProtectedData storage. Normal app writes use small schema and generation values, and normal external inputs do not flow into these plist envelopes. This is best treated as a corrupt-state/local-tamper robustness bug that can cause an app crash or crash loop after authentication, not a confidentiality or integrity bypass.

### Strongest Evidence Against Real Impact

- The affected files live under app-owned `Application Support/ProtectedData/<domain>/` storage with path containment and file-protection checks. There is no network path or normal cross-app write path.
- Product code writes protected-settings envelopes through `ProtectedDomainEnvelopeCodec.seal` with `Payload.currentSchemaVersion` and locally incremented generation identifiers, so shipped app logic should not produce out-of-range values by itself.
- In-range malformed/corrupt protected-settings data is already treated as recovery: `readAuthoritativeSnapshot` catches decode/open/decode failures per slot, and the committed-upgrade mapper turns `invalidEnvelope`/length errors into `.recoveryNeeded`.
- The direct impact is process availability. It does not expose plaintext, root secrets, private keys, or silently accept tampered payloads.

### Strongest Evidence Supporting Real Impact

- `ProtectedDomainEnvelope.validateContract()` only requires positive `schemaVersion` and `generationIdentifier`.
- `ProtectedDomainEnvelopeCodec.open()` builds AAD by narrowing those decoded `Int` values with `UInt16(schemaVersion)` and `UInt32(generationIdentifier)`. Swift exact integer narrowing traps on out-of-range values.
- The narrowing happens before AES-GCM authentication, so a corrupt plist with valid envelope shape and huge positive integers can crash without needing a valid tag or domain master key.
- The call sites expect thrown errors: `ProtectedSettingsStore.readAuthoritativeSnapshot` wraps decode/open in `do/catch`, but a trap bypasses the catch and prevents recovery classification.
- The codec is shared by several ProtectedData domains, so the same primitive likely deserves one shared fix rather than a protected-settings-only patch.

### Practical Shipped Scenario

A local user, backup/restore artifact, filesystem corruption, or sandbox-tampering process places a binary plist for `ProtectedData/protected-settings/current.plist`, `previous.plist`, or `pending.plist` with `formatVersion == 1`, positive but oversized `schemaVersion` or `generationIdentifier`, correct nonce/tag lengths, and nonempty ciphertext. After app authentication, protected-settings open/upgrade reads that file and traps during AAD construction before recovery handling can run.

### Final Recommendation

`real-low`

Keep it as a low-severity fix. The fix should validate every field used in fixed-width AAD before conversion, including `schemaVersion <= UInt16.max`, `generationIdentifier <= UInt32.max`, and probably `domainID` UTF-8 length <= `UInt16.max`, returning `ProtectedDataError.invalidEnvelope` instead of trapping.

### Confidence

High.

### Questions For Main Discussion

- Should the fix be applied centrally in `ProtectedDomainEnvelope.validateContract()` so all ProtectedData domains inherit the recovery behavior?
- Does the product treat local filesystem tamper/corrupt-state crashes as security findings or as robustness debt when no confidentiality/integrity bypass exists?
- Are there supported backup, restore, migration, or macOS container-access workflows that make malformed ProtectedData plists more than purely local tampering?
