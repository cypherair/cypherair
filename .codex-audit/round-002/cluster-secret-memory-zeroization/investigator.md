# Investigator Report: cluster-secret-memory-zeroization

Worktree: `/Users/tianren/.codex/worktrees/5de8/cypherair-main`

HEAD inspected: `d075268f61154227b5ff8545bb53808cccfda66c`

CSV resolution: each CA-ID was resolved from `docs/CODEX_SECURITY_REVIEW_INDEX.md` to its `finding_url`, then matched by `finding_url` in `codex-security-findings-2026-05-29T13-11-03.346Z.csv`.

## CA-25 - macOS Argon2 guard treats total RAM as available

- Relevant code locations:
  - `Sources/Security/Argon2idMemoryGuard.swift:31-75`
  - `Sources/Security/Argon2idMemoryGuard.swift:81-89`
  - `Sources/Services/KeyManagement/KeyProvisioningService.swift:109-118`
  - `pgp-mobile/src/keys/s2k.rs:24-44`
  - `pgp-mobile/src/keys/secret_transfer.rs:170-193`
  - `docs/ARCHITECTURE.md:235`
  - `docs/SECURITY.md:384-394`
- Mechanism-present status: Partially present. The import path parses S2K parameters, runs `Argon2idMemoryGuard.validate`, and rejects costs above 75% of the reported memory. On non-macOS it calls `os_proc_available_memory()`. On macOS, `SystemMemoryInfo` returns `ProcessInfo.processInfo.physicalMemory`, which is total installed memory rather than current available headroom.
- Shipped reachability: Shipped on macOS key import. A passphrase-protected secret key reaches `parseS2kParams`, the guard, and then Rust `importSecretKey`; a malicious Argon2id S2K cost below 75% of total RAM can pass the macOS guard even when current free/process-usable memory is much lower. iOS/device behavior is different because the non-macOS branch uses `os_proc_available_memory()`.
- Mitigations:
  - Guard exists before Argon2 derivation and is no-op for Profile A.
  - The guard rejects values above RFC 9580's encoded maximum via `maxMemoryKib`.
  - Integer overflow in the 75% comparison is checked.
  - The attack requires user-assisted import of a passphrase-protected secret key and the correct passphrase.
- Evidence-real:
  - Docs say the guard should validate `os_proc_available_memory()` against Argon2id requirements before key import.
  - Current macOS code explicitly returns `ProcessInfo.processInfo.physicalMemory`.
  - Rust import calls Sequoia `decrypt_secret(&password)` after the guard, so the expensive Argon2id work still occurs if the macOS guard passes.
- Evidence-false-positive:
  - This is not a confidentiality or integrity bypass; it is an availability/system-pressure path.
  - Routine decrypt/sign operations do not use this Argon2id import guard.
  - The iOS branch appears aligned with the documented available-memory design.
- Preliminary disposition: Real for macOS availability hardening. Impact should be tracked as denial of service / memory pressure, not secret disclosure.
- Confidence: High.
- Open questions:
  - What macOS memory-headroom API or conservative fixed cap should replace total physical memory?
  - Should the same cap also be enforced in Rust as defense in depth before Sequoia Argon2id derivation?

## CA-27 - Secret key zeroization skipped on KMS helper failures

- Relevant code locations:
  - `Sources/Services/FFI/PGPKeyOperationAdapter.swift:117-141`
  - `Sources/Services/FFI/PGPKeyOperationAdapter.swift:144-168`
  - `Sources/Services/KeyManagement/KeyProvisioningService.swift:56-64`
  - `Sources/Services/KeyManagement/KeyProvisioningService.swift:116-122`
  - `pgp-mobile/src/keys/generation.rs:74-83`
  - `pgp-mobile/src/keys/secret_transfer.rs:213-229`
- Mechanism-present status: Incomplete. `KeyProvisioningService` zeroizes generated/imported secret `Data` after the adapter returns, but `PGPKeyOperationAdapter.performGenerateKey` and `performImportSecretKey` do not install a local `defer` immediately after receiving secret-bearing Swift `Data` from the generated binding.
- Shipped reachability: The generate/import service paths are shipped. On generation, the post-secret helper failure would require an unexpected failure parsing app-generated public material. On import, user-controlled passphrase-protected key files reach `engine.importSecretKey`; if subsequent helper calls such as `parseKeyInfo`, `detectProfile`, `armorPublicKey`, `dearmor`, or `generateKeyRevocation` throw, the helper exits before `KeyProvisioningService` receives and zeroizes the secret key data.
- Mitigations:
  - Rust wraps secret serialization buffers in `Zeroizing` until transferring them over FFI.
  - Successful Swift provisioning paths install defers that reset generated/imported secret key data.
  - The imported source data snapshot in the UI is reset after import attempts.
  - No evidence of plaintext/private-key logging on these paths.
- Evidence-real:
  - `performGenerateKey` stores `let generated = try engine.generateKey(...)`, then calls `parseKeyInfo` before returning `generated.certData`; no local zeroization covers `generated.certData` if `parseKeyInfo` throws.
  - `performImportSecretKey` stores `let secretKeyData = try engine.importSecretKey(...)`, then runs multiple throwing helpers before returning a `PGPImportedSecretKeyMaterial`; no local zeroization covers `secretKeyData` if any helper throws.
  - The outer defers in `KeyProvisioningService` are created only after the adapter call has already succeeded.
- Evidence-false-positive:
  - The happy path is covered by outer zeroization in `KeyProvisioningService`.
  - Rust-side copies are zeroized on Rust error/drop paths before FFI transfer.
  - No concrete natural fixture was identified in this pass that makes app-generated key metadata parsing fail after generation.
- Preliminary disposition: Real mechanism gap for Swift-side secret lifetime on helper error paths. Import is the more security-relevant path because it accepts user-controlled secret-key files.
- Confidence: Medium-high.
- Open questions:
  - Can a crafted but decryptable secret-key file make `generateKeyRevocation` or public-key armoring fail after `importSecretKey` succeeds?
  - Should secret-bearing adapter structs use a small owned wrapper with `deinit` zeroization to reduce future ordering mistakes?

## CA-32 - Signing key not zeroized on no-default encrypt-to-self error

- Relevant code locations:
  - `Sources/Services/EncryptionService.swift:111-140`
  - `Sources/Services/EncryptionService.swift:204-233`
  - `Sources/App/Encrypt/EncryptScreenModel.swift:771-785`
  - `Sources/App/Encrypt/EncryptOptionsSection.swift:19-46`
  - `Tests/ServiceTests/EncryptionServiceTests.swift:333-361`
- Mechanism-present status: Present but ordered incorrectly. `EncryptionService` does zeroize signing keys after successful engine calls and on later throwing paths, but the `defer` is declared after the encrypt-to-self default-key lookup. The `noKeySelected` throw can therefore occur after `unwrapPrivateKey` returns and before any signing-key zeroization is registered.
- Shipped reachability: The service API is reachable for text and streaming-file encryption when `signWithFingerprint` is non-nil, `encryptToSelf` is true, no explicit encrypt-to-self key is resolved, and `keyManagement.defaultKey` is nil. The normal UI tends to seed both signer and self-key from the default key, so the common UI path avoids this. It remains reachable through service callers, tests, injected route configuration, or inconsistent metadata state with selectable signing keys but no default key.
- Mitigations:
  - Private-key unwrap requires device authentication.
  - If a default/self key exists, the later `defer` and primary inline reset clear the signing key.
  - If `signWithFingerprint` is nil, no private key is unwrapped.
  - The existing test for no default key uses `signWithFingerprint: nil`, so it does not expose the zeroization gap.
- Evidence-real:
  - Text encryption unwraps `signingKey` at `EncryptionService.swift:204-211`, then throws `.noKeySelected` at `:223` if encrypt-to-self cannot resolve a default key. The zeroizing `defer` begins only at `:227`.
  - Streaming encryption has the same order: unwrap at `:111-119`, throw at `:130`, defer only at `:134`.
  - A Swift thrown error leaves the process alive, so the private key buffer can remain in heap memory until ordinary release/reuse rather than explicit reset.
- Evidence-false-positive:
  - The bug is not reachable when signing is disabled or when an explicit/default self key is available.
  - Rust zeroization is not involved because the Rust engine is never called on this error path.
- Preliminary disposition: Real confidentiality hardening issue. The practical UI reachability is narrower than the raw service API, but the ordering violates the app's private-key lifetime invariant.
- Confidence: High.
- Open questions:
  - Should encrypt-to-self resolution be performed before private-key unwrap, or should a zeroizing defer be installed immediately after declaring/acquiring `signingKey`?
  - Should tests cover the signed + encrypt-to-self + no-default path for both text and file encryption?

## CA-35 - Oversized FFI inputs can crash Swift callers

- Relevant code locations:
  - `bindings/pgp_mobile.swift:38-40`
  - `bindings/pgp_mobile.swift:549-553`
  - `bindings/pgp_mobile.swift:1237-1245`
  - `bindings/pgp_mobile.swift:1430-1436`
  - `bindings/pgp_mobile.swift:1568-1573`
  - `bindings/pgp_mobile.swift:5326-5336`
  - `bindings/pgp_mobile.swift:5447-5455`
  - `bindings/pgp_mobileFFI.h:32-36`
  - `Sources/PgpMobile/pgp_mobile.swift:38-40`
  - `Sources/PgpMobile/pgp_mobile.swift:549-553`
  - `Sources/App/Keys/ImportKeyScreenModel.swift:44-61`
- Mechanism-present status: Present. The generated Swift binding converts `Data.count`, string byte counts, sequence counts, and `ForeignBytes` lengths with trapping `Int32(...)` initializers. These conversions happen during lowering/marshalling before Rust can return a `PgpError`.
- Shipped reachability: Shipped through the generated `Sources/PgpMobile/pgp_mobile.swift` used by the Xcode project, which is byte-identical to `bindings/pgp_mobile.swift`. User-controlled key import reads selected files into `Data` without a size cap and then calls `parseS2kParams` and `importSecretKey`; other text/public-key/ciphertext paths also pass `Data` into the same binding family. Streaming file encrypt/decrypt APIs mitigate full-file marshalling by passing paths, but key import and several text/certificate paths are still in-memory FFI calls.
- Mitigations:
  - Many routine OpenPGP files are far below `Int32.max`; practical triggering requires extremely large inputs or enough memory to construct a huge `Data`.
  - Some file workflows use streaming path APIs rather than marshalling full file contents.
  - `ArmoredTextMessageClassifier` limits only a preview/classification path; it is not a general FFI input cap.
  - No evidence this exposes plaintext or keys directly; the primary impact is process termination.
- Evidence-real:
  - `ForeignBytes(bufferPointer:)` does `Int32(bufferPointer.count)`.
  - `FfiConverterData.write` does `let len = Int32(value.count)`.
  - `FfiConverterOptionData` and `FfiConverterSequenceData` call the same `FfiConverterData.write`.
  - The C header fixes `ForeignBytes.len` as `int32_t`.
  - Generated methods such as `encrypt`, `importSecretKey`, and `parseS2kParams` lower attacker-controlled `Data` before entering Rust error handling.
- Evidence-false-positive:
  - This is best classified as availability-only for attacker-controlled oversized public/ciphertext/key-file data. It does not create a normal confidentiality or integrity bypass.
  - For signed operations, a fatal trap could occur while a signing key is live in Swift memory, but process termination rather than a recoverable error is the primary behavior; this pass found no direct secret exfiltration path.
  - Some practical inputs may fail earlier while reading/allocating `Data`, before the `Int32` trap.
- Preliminary disposition: Real availability hardening issue in generated FFI boundary and/or preflight size policy. Confidentiality impact is indirect and materially weaker than CA-27/CA-32.
- Confidence: High for the trapping conversion; medium for broad shipped exploitability because constructing such large `Data` may itself fail first.
- Open questions:
  - What per-operation maximum input sizes should be enforced before FFI marshalling?
  - Should fixes live in generated binding customization, Swift adapter preflight, Rust/UniFFI type choices, or all three?
