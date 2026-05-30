# Adversary Report: cluster-secret-memory-zeroization

Worktree: `/Users/tianren/.codex/worktrees/5de8/cypherair-main`

Investigator trace: not read.

## CA-25 - macOS Argon2 guard treats total RAM as available

### Challenge Summary

The mechanism is present on macOS, but the impact should be constrained to local, user-mediated availability. The guard's documented motivation is iOS Jetsam prevention, while the macOS implementation explicitly treats the absence of Jetsam as a reason to use total physical memory. That may be too permissive, but it does not expose keys or plaintext and requires a malicious or pathological passphrase-protected secret-key import plus the passphrase.

### Strongest Evidence Against Real Impact

- `docs/SECURITY.md` frames the memory guard as "iOS Memory Safety Guard" and says it prevents iOS Jetsam, not a macOS confidentiality boundary.
- `SystemMemoryInfo` comments state "macOS has no Jetsam - use total physical memory"; this looks like an intentional platform tradeoff, not an accidental bypass of the iOS path.
- The shipped path is a file import flow controlled by the local user. An attacker must get the user to import a passphrase-protected secret key and supply the correct passphrase.
- The effect is memory pressure, hang, or process termination. No plaintext/private-key disclosure follows from the guard accepting a high Argon2id memory cost.
- Profile A imports are out of scope because non-Argon2id S2K returns before any memory check.

### Strongest Evidence Supporting Real Impact

- `Argon2idMemoryGuard.validate` permits required memory up to 75% of `availableMemoryBytes`.
- On macOS, `availableMemoryBytes` is `ProcessInfo.processInfo.physicalMemory`, which is installed RAM rather than current free/process-usable headroom.
- `KeyProvisioningService.importKey` validates the parsed S2K info before calling the Rust import; if the macOS check passes, Rust still reaches Sequoia's `decrypt_secret(&password)` for each encrypted secret key.
- A high but under-75%-of-RAM Argon2id cost can still be disruptive on a busy Mac, especially with swap pressure.

### Practical Shipped Scenario

A user imports a passphrase-protected malicious secret key from the local file picker, enters the provided passphrase, and the key advertises an Argon2id memory cost below 75% of installed RAM but above realistic current headroom. The app may hang, be killed, or pressure the system while deriving the key.

### Final Recommendation

`real-low`

Treat as macOS availability hardening, not medium confidentiality/integrity risk. A conservative macOS cap or better headroom estimate would be reasonable, but the scenario is local and user-mediated.

### Confidence

High for availability-only classification; medium-high for practical exploitability because macOS may swap or fail allocation before a clean app crash.

### Questions For Main Discussion

- Does the project want the Argon2id guard to enforce a cross-platform app responsiveness cap, or only iOS Jetsam safety?
- Should macOS use a fixed maximum allowed import cost, current VM statistics, or the same 512 MiB Profile B policy cap rather than installed RAM?
- Should Rust enforce a defense-in-depth S2K memory cap before Sequoia derivation?

## CA-27 - Secret key zeroization skipped on KMS helper failures

### Challenge Summary

The local adapter ordering gap is real as a code pattern: secret-bearing `Data` exists before a local Swift `defer` is installed. The harder question is reachability. On normal success and on failures after the adapter returns, callers do zeroize. Rust also zeroizes pre-FFI secret buffers. The unzeroized path requires a helper operation to fail after Rust has returned a freshly generated/imported secret cert but before `KeyProvisioningService` receives it. For generated keys this looks mostly theoretical; for imported keys it is plausible but needs a concrete decryptable fixture.

### Strongest Evidence Against Real Impact

- `KeyProvisioningService.generateKey` installs `defer { generated.certData.resetBytes(...) }` immediately after `keyAdapter.generateKey` returns; `importKey` does the same for `imported.secretKeyData`.
- Duplicate-key rejection, cancellation, auth-mode/storage failures, Secure Enclave wrapping failures, and commit failures happen after those outer defers are installed.
- Rust generation/import wraps secret output buffers in `Zeroizing` until the Vec is intentionally transferred over FFI.
- `performGenerateKey` parses public data produced by the same Rust `generateKey` call; a natural post-secret parsing failure is hard to identify.
- `performImportSecretKey` helper inputs are the decrypted cert just parsed and serialized by the Rust engine, so `parseKeyInfo`, `detectProfile`, `armorPublicKey`, and `dearmor` should usually be self-consistent.
- The residual exposure is heap lifetime after a Swift throw. That is a confidentiality hardening issue only in the presence of crash dumps, memory forensics, or a separate memory disclosure primitive.

### Strongest Evidence Supporting Real Impact

- `PGPKeyOperationAdapter.performGenerateKey` stores `let generated = try engine.generateKey(...)`, then calls `engine.parseKeyInfo` before returning `generated.certData`; no local zeroizing defer exists in that helper.
- `performImportSecretKey` stores `let secretKeyData = try engine.importSecretKey(...)`, then calls multiple throwing helpers before returning the secret-bearing material.
- `generateKeyRevocation(secretCert:)` can plausibly fail for unusual imported secret certificates even after decryption/serialization succeeds, because it builds a primary keypair and asks Sequoia to issue a revocation signature.
- The generated binding and Rust comments explicitly push responsibility for zeroizing returned secret cert data to Swift.

### Practical Shipped Scenario

The only plausible shipped scenario is user-mediated import of a crafted, passphrase-protected secret key that decrypts successfully but causes a later adapter helper, most likely revocation generation, to throw before the adapter returns. I did not find a concrete fixture or normal UI path that demonstrates this. Generation looks weaker still: it would require internally generated public material to fail metadata parsing before the caller can zeroize the secret cert.

### Final Recommendation

`uncertain`

The invariant violation is worth discussing and probably cheap to harden, but adversarial classification should not assume broad shipped reachability without a fixture. If a crafted decryptable key can make revocation generation or another helper fail, downgrade uncertainty to `real-low` or `real-needs-fix` depending on project policy for explicit zeroization invariants.

### Confidence

Medium. The missing local `defer` is clear; the practical trigger is not.

### Questions For Main Discussion

- Can we produce a decryptable secret-key fixture where `importSecretKey` succeeds but `generateKeyRevocation`, `armorPublicKey`, or `parseKeyInfo` fails?
- Should adapter methods install local zeroization defers immediately after receiving secret-bearing `Data`, even if practical failures are rare?
- Should secret-bearing Swift result types become scoped wrappers with deinit zeroization to prevent this pattern from recurring?

## CA-32 - Signing key not zeroized on no-default encrypt-to-self error

### Challenge Summary

This is the strongest item in the cluster. The zeroization ordering bug is explicit: `EncryptionService` unwraps the signing key, then may throw `.noKeySelected` before registering the defer that clears it. The adversarial pushback is mainly on normal shipped UI reachability. The default UI seeds both signer and encrypt-to-self key from `defaultKey`, so the common path does not hit it. Still, a service caller, injected route configuration, or inconsistent metadata state with selectable signing keys but no default can make the private key buffer live through a throwing path.

### Strongest Evidence Against Real Impact

- The standard encrypt screen initializes `signerFingerprint` and `encryptToSelfFingerprint` from `keyManagement.defaultKey`; if there is no default, the initial signer is nil.
- With no selected signer, `signWithFingerprint` is nil and no private key is unwrapped.
- Normal key creation/import marks the first key default, and deleting the default promotes another key when keys remain.
- The shipped UI does not obviously provide a supported way to clear the default key while leaving keys present.
- The error path requires `encryptToSelf == true`, no explicit self key, no default key, and a non-nil signer fingerprint.

### Strongest Evidence Supporting Real Impact

- In both streaming file and text encryption, `signingKey = try await keyManagement.unwrapPrivateKey(...)` occurs before encrypt-to-self resolution.
- If no explicit self key and no default key exist, the code throws `.noKeySelected` before the zeroizing `defer`.
- `unwrapPrivateKey` returns unwrapped secret certificate material and documents that callers must zeroize it.
- `KeyCatalogStore.setDefaultKey` can set every key's `isDefault` false if called with a nonexistent fingerprint, and loaded metadata could also be inconsistent.
- If keys are present without a default and there are at least two own keys, the signing picker can allow the user to select a signer while encrypt-to-self still falls back to the missing default.

### Practical Shipped Scenario

Narrow but plausible: local key metadata ends up with multiple keys and no default through corruption, migration edge case, or an invalid internal default-key call. The encrypt screen appears with signing enabled. The user selects a signing key, leaves encrypt-to-self enabled without an explicit self key, authenticates for signing, and the service throws `.noKeySelected` before clearing the unwrapped signing key.

### Final Recommendation

`real-needs-fix`

The common UI path is narrower than the service API, but this crosses a private-key zeroization invariant after device authentication. Resolve self-key/default-key selection before unwrapping the signer, or install a zeroizing defer immediately after `signingKey` is declared/acquired.

### Confidence

High for the ordering bug; medium-high for shipped reachability because it depends on inconsistent metadata or non-default UI/service configuration.

### Questions For Main Discussion

- Should `EncryptionService` resolve all public recipient/self keys before any private-key unwrap?
- Should the UI block signing when `signerFingerprint` is nil even if `signMessage` is true, to make the state explicit?
- Should tests cover signed + encrypt-to-self + no-default for both text and streaming-file paths?

## CA-35 - Oversized FFI inputs can crash Swift callers

### Challenge Summary

The trapping conversion is real in generated UniFFI Swift, but the impact is local denial of service. It requires constructing or importing extremely large `Data` or collections before FFI lowering. Many shipped large-file workflows use path-based streaming APIs instead. The most credible paths are key import and text/certificate/signature inputs that read local files into memory without a size cap.

### Strongest Evidence Against Real Impact

- Triggering `Int32(value.count)` requires counts above `Int32.max`, so practical exploitation needs multi-gigabyte in-memory `Data` or an enormous sequence.
- `Data(contentsOf:)`, string decoding, or general memory pressure may fail before the UniFFI conversion traps.
- Streaming encrypt/decrypt and file-recipient matching pass file paths instead of whole file contents.
- The attacker-controlled input is a local file or pasted/local text selected by the user; there is no network ingress.
- This does not expose keys or plaintext by itself. It terminates the process before Rust can return a structured error.

### Strongest Evidence Supporting Real Impact

- `ForeignBytes(bufferPointer:)` and `FfiConverterData.write` use trapping `Int32(...)` initializers.
- Generated methods such as `encrypt`, `importSecretKey`, and `parseS2kParams` lower user-controlled `Data` before Rust-side `PgpError` handling.
- The generated app copy at `Sources/PgpMobile/pgp_mobile.swift` is byte-identical to `bindings/pgp_mobile.swift`, so this is the shipped binding.
- `ImportKeyScreenModel` reads selected key files with `Data(contentsOf:)` and does not enforce a pre-FFI size cap.
- Text decrypt/verify import paths also keep raw imported text bytes and pass them to services that eventually lower `Data` over FFI.

### Practical Shipped Scenario

A user selects an extremely large `.asc`, key, cleartext, signature, or text ciphertext file through a local importer. If the app successfully materializes the input as `Data` and then calls a generated FFI method, Swift traps during lowering instead of returning a user-facing error. This is a local availability failure.

### Final Recommendation

`real-low`

Classify as availability hardening at Swift input policy or generated binding boundaries. It is not a realistic confidentiality issue absent a separate memory disclosure/crash-dump concern.

### Confidence

High for the trapping conversions; medium for end-to-end exploitability because allocation or file read may fail first.

### Questions For Main Discussion

- What per-operation size limits should exist for key import, text ciphertext import, cleartext verification, detached signatures, and contact certificate imports?
- Should generated binding customization use checked conversions and throw a structured UniFFI error, or should product services preflight sizes before every FFI call?
- Should local file importers reject oversize files before `Data(contentsOf:)` to avoid both this trap and ordinary memory exhaustion?
