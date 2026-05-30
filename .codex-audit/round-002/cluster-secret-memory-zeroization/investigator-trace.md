# Investigator Trace: cluster-secret-memory-zeroization

Worktree: `/Users/tianren/.codex/worktrees/5de8/cypherair-main`

HEAD: `d075268f61154227b5ff8545bb53808cccfda66c`

## Resolution steps

- `rg -n "CA-25|CA-27|CA-32|CA-35|finding_url|codex-security-findings" docs/CODEX_SECURITY_REVIEW_INDEX.md`
  - Mapped CA-25 to `https://chatgpt.com/codex/cloud/security/findings/c56fc514b22481918273dc22faae7421`
  - Mapped CA-27 to `https://chatgpt.com/codex/cloud/security/findings/2a18f490890c8191afc9b8775a8ff2b3`
  - Mapped CA-32 to `https://chatgpt.com/codex/cloud/security/findings/8ef989997a7081919d767f560071a253`
  - Mapped CA-35 to `https://chatgpt.com/codex/cloud/security/findings/105db662caf481918b80f2a457afae2e`
- `ruby -rcsv -e 'urls=%w[...]; rows=CSV.read("codex-security-findings-2026-05-29T13-11-03.346Z.csv", headers:true); ...'`
  - Matched each row by exact `finding_url`, not by line number.
  - Confirmed CSV titles, descriptions, severities, commit hashes, and relevant paths for all four CA-IDs.
- `tool_search` queries for Apple/Xcode documentation lookup:
  - `DocumentationSearch Apple Developer documentation Xcode`
  - `Apple Developer DocumentationSearch documentation search`
  - Only XcodeBuildMCP build/scheme tooling was exposed; no Apple `DocumentationSearch` tool was callable. Apple docs lookup not available.

## Repository/docs context inspected

- `sed -n '1,90p' docs/CODEX_SECURITY_REVIEW_INDEX.md`
- `sed -n '1,220p' docs/SECURITY.md`
- `sed -n '1,180p' docs/ARCHITECTURE.md`
- `nl -ba docs/ARCHITECTURE.md | sed -n '210,245p'`
  - `docs/ARCHITECTURE.md:235`: `Argon2idMemoryGuard` documented as validating `os_proc_available_memory()` against Argon2id requirements.
- `nl -ba docs/SECURITY.md | sed -n '220,260p'`
  - `docs/SECURITY.md:231`: raw private key bytes zeroized only after successful storage.
  - `docs/SECURITY.md:242-244`: private key bytes are zeroized after PGP operation.
- `nl -ba docs/SECURITY.md | sed -n '372,398p'`
  - `docs/SECURITY.md:384-394`: Argon2id import guard should parse S2K, query `os_proc_available_memory()`, and refuse if required memory exceeds 75%.
- `nl -ba docs/SECURITY.md | sed -n '430,460p'`
  - `docs/SECURITY.md:441-456`: passphrase `String` zeroization is a known platform limitation; Rust-side passphrase copies are zeroized.

## CA-25 evidence

- `nl -ba Sources/Security/Argon2idMemoryGuard.swift | sed -n '1,180p'`
  - `Argon2idMemoryGuard.swift:31-75`: validates only `s2kType == "argon2id"`, checks `memoryKib`, caps at `1 << 31`, compares `requiredBytes * 4` to `availableBytes * 3`, throws `.argon2idMemoryExceeded`.
  - `Argon2idMemoryGuard.swift:81-89`: `SystemMemoryInfo.availableMemoryBytes()` returns `ProcessInfo.processInfo.physicalMemory` on macOS and `_os_proc_available_memory()` elsewhere.
- `nl -ba Sources/Services/KeyManagement/KeyProvisioningService.swift | sed -n '1,230p'`
  - `KeyProvisioningService.swift:109-118`: import parses protection info, validates the memory guard, then calls `keyAdapter.importSecretKey`.
- `nl -ba pgp-mobile/src/keys/s2k.rs | sed -n '1,260p'`
  - `s2k.rs:24-44`: parses encrypted secret-key S2K and computes Argon2 memory as `1u64 << m`.
- `nl -ba pgp-mobile/src/keys/secret_transfer.rs | sed -n '1,320p'`
  - `secret_transfer.rs:170-193`: imports passphrase-protected key and calls Sequoia `decrypt_secret(&password)` for primary key.
  - `secret_transfer.rs:197-203`: same for secret subkeys.
- `nl -ba Tests/FFIIntegrationTests/FFIIntegrationTests.swift | sed -n '2170,2388p'`
  - Mock-memory tests cover 512MB/1GB/2GB thresholds and Profile A no-op, but not macOS total-vs-available semantics.
- `nl -ba Tests/DeviceSecurityTests/DeviceSystemMemoryTests.swift | sed -n '1,120p'`
  - Device test checks real `SystemMemoryInfo` returns nonzero and <= physical memory.

## CA-27 evidence

- `nl -ba Sources/Services/FFI/PGPKeyOperationAdapter.swift | sed -n '1,240p'`
  - `PGPKeyOperationAdapter.swift:125-141`: `performGenerateKey` receives `generated.certData`, then calls `parseKeyInfo` before returning. No local defer zeroizes `generated.certData` if the helper throws.
  - `PGPKeyOperationAdapter.swift:150-168`: `performImportSecretKey` receives `secretKeyData`, then calls `parseKeyInfo`, `detectProfile`, `armorPublicKey`, `dearmor`, and `generateKeyRevocation` before returning. No local defer zeroizes `secretKeyData` on helper failure.
- `nl -ba Sources/Services/KeyManagement/KeyProvisioningService.swift | sed -n '1,230p'`
  - `KeyProvisioningService.swift:56-64`: outer generation zeroization defer is installed only after `keyAdapter.generateKey` returns successfully.
  - `KeyProvisioningService.swift:116-122`: outer import zeroization defer is installed only after `keyAdapter.importSecretKey` returns successfully.
- `nl -ba pgp-mobile/src/keys/generation.rs | sed -n '1,280p'`
  - `generation.rs:74-83`: Rust generated secret cert serialization buffer is `Zeroizing`.
  - `generation.rs:102-109`: `std::mem::take` transfers the secret Vec out to FFI.
- `nl -ba pgp-mobile/src/keys/secret_transfer.rs | sed -n '1,320p'`
  - `secret_transfer.rs:213-229`: imported secret output buffer is `Zeroizing` until transferred out.
- `nl -ba pgp-mobile/src/keys/key_info.rs | sed -n '1,260p'`
  - `key_info.rs:4-108`: `parse_key_info` parses the cert and derives metadata.
- `nl -ba pgp-mobile/src/keys/profile.rs | sed -n '1,220p'`
  - `profile.rs:12-18`: `detect_profile` reparses and maps version to profile.

## CA-32 evidence

- `nl -ba Sources/Services/EncryptionService.swift | sed -n '1,290p'`
  - Streaming path:
    - `EncryptionService.swift:111-119`: unwraps signing key if requested.
    - `EncryptionService.swift:121-131`: resolves encrypt-to-self key and can throw `.noKeySelected`.
    - `EncryptionService.swift:134-140`: zeroizing defer is installed after the throw site.
  - Text path:
    - `EncryptionService.swift:204-211`: unwraps signing key if requested.
    - `EncryptionService.swift:214-224`: resolves encrypt-to-self key and can throw `.noKeySelected`.
    - `EncryptionService.swift:227-233`: zeroizing defer is installed after the throw site.
    - `EncryptionService.swift:235-249`: normal engine call and primary reset happen only after the throw site.
- `nl -ba Sources/App/Encrypt/EncryptScreenModel.swift | sed -n '1,230p'`, `230,520p`, `520,830p`
  - `EncryptScreenModel.swift:771-785`: normal UI seeds signer/self-key from default key.
  - `EncryptScreenModel.swift:432-438` and `481-486`: service receives selected signer and encrypt-to-self values.
- `nl -ba Sources/App/Encrypt/EncryptOptionsSection.swift | sed -n '1,120p'`
  - `EncryptOptionsSection.swift:19-46`: UI can expose separate pickers when multiple own keys exist.
- `nl -ba Tests/ServiceTests/EncryptionServiceTests.swift | sed -n '320,365p'`
  - Existing no-default test uses `signWithFingerprint: nil`, so it does not cover the unwrapped-signing-key error path.

## CA-35 evidence

- `nl -ba bindings/pgp_mobile.swift | sed -n '1,120p'`
  - `bindings/pgp_mobile.swift:38-40`: `ForeignBytes(bufferPointer:)` does `Int32(bufferPointer.count)`.
- `nl -ba bindings/pgp_mobile.swift | sed -n '500,570p'`
  - `bindings/pgp_mobile.swift:531-534`: string write uses `Int32(value.utf8.count)`.
  - `bindings/pgp_mobile.swift:549-553`: `FfiConverterData.write` uses `Int32(value.count)`.
- `nl -ba bindings/pgp_mobileFFI.h | sed -n '1,140p'`
  - `bindings/pgp_mobileFFI.h:32-36`: `ForeignBytes.len` is `int32_t`.
- `nl -ba bindings/pgp_mobile.swift | sed -n '1180,1325p'`
  - `bindings/pgp_mobile.swift:1237-1245`: `encrypt` lowers plaintext, recipients, signing key, and self key before Rust call returns errors.
- `nl -ba bindings/pgp_mobile.swift | sed -n '1420,1580p'`
  - `bindings/pgp_mobile.swift:1430-1436`: `importSecretKey` lowers attacker-controlled key file data.
  - `bindings/pgp_mobile.swift:1568-1573`: `parseS2kParams` lowers attacker-controlled key file data.
- `nl -ba bindings/pgp_mobile.swift | sed -n '5315,5485p'`
  - `bindings/pgp_mobile.swift:5326-5336`: optional `Data` writes call `FfiConverterData.write`.
  - `bindings/pgp_mobile.swift:5447-5455`: `[Data]` writes call `FfiConverterData.write` for each item and use `Int32(value.count)`.
- `nl -ba Sources/PgpMobile/pgp_mobile.swift | sed -n '1,120p'`
  - Shipped generated source has the same `ForeignBytes` conversion.
- `cmp -s bindings/pgp_mobile.swift Sources/PgpMobile/pgp_mobile.swift`
  - Exit code `0`: source binding is byte-identical to the binding copy.
- `rg -n "Sources/PgpMobile/pgp_mobile\\.swift|pgp_mobile\\.swift|pgp_mobileFFI\\.h|PgpMobile" CypherAir.xcodeproj/project.pbxproj project.yml Package.swift`
  - Project references `PgpMobile/pgp_mobile.swift` and `PgpMobile.xcframework`.
- `nl -ba Sources/App/Keys/ImportKeyScreenModel.swift | sed -n '1,230p'`
  - `ImportKeyScreenModel.swift:44-61`: selected key file is read with `Data(contentsOf:)` without a size cap.
  - `ImportKeyScreenModel.swift:137-141`: import path passes data to `importKeyAction`.
- `nl -ba Sources/Services/FFI/PGPMessageOperationAdapter.swift | sed -n '1,260p'` and `260,560p`
  - Message adapter passes `Data` to generated engine calls for text/ciphertext/signature paths; streaming file paths use string file paths instead.

## Workspace integrity

- `git status --short` before writing reports showed no tracked changes.
- No tests were run because this was an investigation-only task and repository files were not edited.
