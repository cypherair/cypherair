# Adversary Trace: cluster-secret-memory-zeroization

Worktree: `/Users/tianren/.codex/worktrees/5de8/cypherair-main`

Investigator trace: not read.

## Commands And Sources Inspected

- `pwd`
  - Confirmed worktree path.
- `git status --short`
  - Confirmed clean worktree before writing adversary artifacts.
- `ls -la .codex-audit/round-002/cluster-secret-memory-zeroization`
  - Confirmed existing files were `investigator.md` and `investigator-trace.md`.
- `rg --files | rg '(^docs/CODEX_SECURITY_REVIEW_INDEX.md$|codex-security-findings-2026-05-29T13-11-03\.346Z\.csv$)'`
  - Confirmed required review index and CSV are present.
- `rg -n "CA-(25|27|32|35)|cluster-secret-memory-zeroization|secret|zero" docs/CODEX_SECURITY_REVIEW_INDEX.md`
  - Relevant lines: `docs/CODEX_SECURITY_REVIEW_INDEX.md:63`, `:65`, `:70`, `:73`.
- `rg -n "CA-(25|27|32|35)" codex-security-findings-2026-05-29T13-11-03.346Z.csv`
  - No direct CA-ID matches; findings are identified by URL.
- `head -n 5 codex-security-findings-2026-05-29T13-11-03.346Z.csv`
  - Confirmed CSV header.
- `rg -n "c56fc514b22481918273dc22faae7421|2a18f490890c8191afc9b8775a8ff2b3|8ef989997a7081919d767f560071a253|105db662caf481918b80f2a457afae2e" codex-security-findings-2026-05-29T13-11-03.346Z.csv`
  - CA-25 CSV row: `codex-security-findings-2026-05-29T13-11-03.346Z.csv:26`.
  - CA-27 CSV row: `codex-security-findings-2026-05-29T13-11-03.346Z.csv:28`.
  - CA-32 CSV row: `codex-security-findings-2026-05-29T13-11-03.346Z.csv:33`.
  - CA-35 CSV row: `codex-security-findings-2026-05-29T13-11-03.346Z.csv:36`.
- `nl -ba .codex-audit/round-002/cluster-secret-memory-zeroization/investigator.md | sed -n '1,260p'`
  - Investigator CA-25 summary: `investigator.md:9-38`.
  - Investigator CA-27 summary: `investigator.md:40-68`.
  - Investigator CA-32 summary: `investigator.md:70-96`.
  - Investigator CA-35 summary: `investigator.md:98-133`.

## CA-25 Source Trace

- `nl -ba Sources/Security/Argon2idMemoryGuard.swift | sed -n '1,150p'`
  - Guard purpose comments: `Sources/Security/Argon2idMemoryGuard.swift:3-12`.
  - Argon2id-only gate and memory validation: `Sources/Security/Argon2idMemoryGuard.swift:31-75`.
  - macOS `ProcessInfo.processInfo.physicalMemory` branch: `Sources/Security/Argon2idMemoryGuard.swift:78-89`.
- `nl -ba Sources/Services/KeyManagement/KeyProvisioningService.swift | sed -n '1,190p'`
  - Import S2K parse and guard before Rust import: `Sources/Services/KeyManagement/KeyProvisioningService.swift:109-119`.
  - Caller zeroization after adapter import returns: `Sources/Services/KeyManagement/KeyProvisioningService.swift:120-122`.
- `nl -ba pgp-mobile/src/keys/s2k.rs | sed -n '1,140p'`
  - S2K memory extraction: `pgp-mobile/src/keys/s2k.rs:24-44`.
- `nl -ba pgp-mobile/src/keys/secret_transfer.rs | sed -n '130,250p'`
  - Import decrypts secret keys with passphrase after guard path: `pgp-mobile/src/keys/secret_transfer.rs:170-204`.
  - Rust output `Zeroizing` wrapper and FFI transfer: `pgp-mobile/src/keys/secret_transfer.rs:213-229`.
- `nl -ba docs/SECURITY.md | sed -n '360,410p'`
  - Argon2id use limited to private-key export/import: `docs/SECURITY.md:372-376`.
  - iOS memory guard steps and Jetsam rationale: `docs/SECURITY.md:384-394`.
- `nl -ba docs/ARCHITECTURE.md | sed -n '225,245p'`
  - Architecture description says guard validates `os_proc_available_memory`: `docs/ARCHITECTURE.md:235`.

## CA-27 Source Trace

- `nl -ba Sources/Services/FFI/PGPKeyOperationAdapter.swift | sed -n '1,230p'`
  - Secret-bearing material structs: `Sources/Services/FFI/PGPKeyOperationAdapter.swift:3-15`.
  - Adapter catch mapping: `Sources/Services/FFI/PGPKeyOperationAdapter.swift:31-75`.
  - Generation helper receives `generated` then parses metadata before return: `Sources/Services/FFI/PGPKeyOperationAdapter.swift:117-141`.
  - Import helper receives `secretKeyData` then runs parse/profile/armor/dearmor/revocation helpers before return: `Sources/Services/FFI/PGPKeyOperationAdapter.swift:144-168`.
- `nl -ba Sources/Services/KeyManagement/KeyProvisioningService.swift | sed -n '1,190p'`
  - Outer generated-key zeroization after adapter success: `Sources/Services/KeyManagement/KeyProvisioningService.swift:56-64`.
  - Outer imported-secret zeroization after adapter success: `Sources/Services/KeyManagement/KeyProvisioningService.swift:116-122`.
  - Duplicate/cancellation/storage/wrapping occur after the outer defer: `Sources/Services/KeyManagement/KeyProvisioningService.swift:123-162`.
- `nl -ba pgp-mobile/src/keys/generation.rs | sed -n '1,120p'`
  - Rust generated cert data wrapped in `Zeroizing`: `pgp-mobile/src/keys/generation.rs:74-83`.
  - FFI transfer via `std::mem::take`: `pgp-mobile/src/keys/generation.rs:102-109`.
- `nl -ba pgp-mobile/src/keys/secret_transfer.rs | sed -n '130,250p'`
  - Rust imported secret output `Zeroizing`: `pgp-mobile/src/keys/secret_transfer.rs:213-229`.
- `nl -ba pgp-mobile/src/keys/key_info.rs | sed -n '1,180p'`
  - `parse_key_info` parses certificate and derives metadata: `pgp-mobile/src/keys/key_info.rs:3-108`.
- `nl -ba pgp-mobile/src/keys/profile.rs | sed -n '1,120p'`
  - `detect_profile` reparses cert and reads version: `pgp-mobile/src/keys/profile.rs:11-18`.
- `nl -ba pgp-mobile/src/armor.rs | sed -n '1,140p'`
  - `decode_armor`: `pgp-mobile/src/armor.rs:39-61`.
  - `armor_public_key`: `pgp-mobile/src/armor.rs:86-108`.
- `nl -ba pgp-mobile/src/keys/revocation.rs | sed -n '1,120p'`
  - Revocation generation parses secret cert, builds primary keypair, and signs: `pgp-mobile/src/keys/revocation.rs:3-44`.
- `nl -ba pgp-mobile/src/lib.rs | sed -n '90,130p;395,445p'`
  - `parse_key_info`/`detect_profile` exposed methods: `pgp-mobile/src/lib.rs:102-124`.
  - Rust `generate_key_revocation` wraps secret input in `Zeroizing`: `pgp-mobile/src/lib.rs:400-403`.
  - `dearmor` and `armor_public_key` exposed methods: `pgp-mobile/src/lib.rs:433-441`.

## CA-32 Source Trace

- `nl -ba Sources/Services/EncryptionService.swift | sed -n '1,280p'`
  - Streaming path unwraps signer before self-key/default resolution: `Sources/Services/EncryptionService.swift:111-130`.
  - Streaming zeroizing defer starts after possible `.noKeySelected`: `Sources/Services/EncryptionService.swift:134-140`.
  - Text path unwraps signer before self-key/default resolution: `Sources/Services/EncryptionService.swift:204-223`.
  - Text zeroizing defer starts after possible `.noKeySelected`: `Sources/Services/EncryptionService.swift:227-233`.
  - Primary zeroing after successful text engine call: `Sources/Services/EncryptionService.swift:243-249`.
- `nl -ba Sources/Services/KeyManagement/PrivateKeyAccessService.swift | sed -n '1,160p'`
  - `unwrapPrivateKey` returns unwrapped secret material and requires callers to zeroize: `Sources/Services/KeyManagement/PrivateKeyAccessService.swift:22-24`.
  - Successful unwrap return: `Sources/Services/KeyManagement/PrivateKeyAccessService.swift:64-90`.
- `nl -ba Sources/App/Encrypt/EncryptScreenModel.swift | sed -n '1,180p'`
  - Text/file actions pass signer and encrypt-to-self selections to `EncryptionService`: `Sources/App/Encrypt/EncryptScreenModel.swift:122-157`.
- `nl -ba Sources/App/Encrypt/EncryptScreenModel.swift | sed -n '220,520p'`
  - Resolved encrypt-to-self setting: `Sources/App/Encrypt/EncryptScreenModel.swift:238-250`.
  - Text encryption passes `signerFingerprint` only when signing enabled: `Sources/App/Encrypt/EncryptScreenModel.swift:419-454`.
  - File encryption passes `signerFingerprint` only when signing enabled: `Sources/App/Encrypt/EncryptScreenModel.swift:467-503`.
- `nl -ba Sources/App/Encrypt/EncryptScreenModel.swift | sed -n '640,810p'`
  - Initial signer and self-key seeded from default key: `Sources/App/Encrypt/EncryptScreenModel.swift:771-775`.
  - Encrypt-to-self initial policy: `Sources/App/Encrypt/EncryptScreenModel.swift:781-784`.
- `nl -ba Sources/App/Encrypt/EncryptOptionsSection.swift | sed -n '1,90p'`
  - Self-key picker only shown when encrypt-to-self and more than one own key: `Sources/App/Encrypt/EncryptOptionsSection.swift:19-29`.
  - Signing picker only shown when signing and more than one own key: `Sources/App/Encrypt/EncryptOptionsSection.swift:37-47`.
- `nl -ba Sources/Services/KeyManagementService.swift | sed -n '520,610p'`
  - `defaultKey` is first `isDefault`: `Sources/Services/KeyManagementService.swift:535-538`.
  - `unwrapPrivateKey` facade: `Sources/Services/KeyManagementService.swift:592-597`.
- `nl -ba Sources/Services/KeyManagement/KeyCatalogStore.swift | sed -n '1,140p'`
  - First new identity appended by store; default property comes from provisioning: `Sources/Services/KeyManagement/KeyCatalogStore.swift:54-57`.
  - Removing default promotes another key when keys remain: `Sources/Services/KeyManagement/KeyCatalogStore.swift:103-112`.
  - `setDefaultKey` clears defaults if fingerprint does not match any key: `Sources/Services/KeyManagement/KeyCatalogStore.swift:115-128`.
- `nl -ba Tests/ServiceTests/EncryptionServiceTests.swift | sed -n '320,370p'`
  - Existing no-default test uses `signWithFingerprint: nil`, so it does not cover the secret-zeroization path: `Tests/ServiceTests/EncryptionServiceTests.swift:333-350`.

## CA-35 Source Trace

- `cmp -s bindings/pgp_mobile.swift Sources/PgpMobile/pgp_mobile.swift; printf '%s\n' $?`
  - Output `0`; generated binding and shipped source copy are byte-identical.
- `nl -ba bindings/pgp_mobile.swift | sed -n '1,70p'`
  - `ForeignBytes(bufferPointer:)` uses trapping `Int32(bufferPointer.count)`: `bindings/pgp_mobile.swift:38-40`.
- `nl -ba bindings/pgp_mobile.swift | sed -n '150,220p'`
  - `FfiConverterRustBuffer.lower` serializes values into `[UInt8]` then calls `RustBuffer(bytes:)`: `bindings/pgp_mobile.swift:209-212`.
- `nl -ba bindings/pgp_mobile.swift | sed -n '520,565p'`
  - `FfiConverterString.write` uses `Int32(value.utf8.count)`: `bindings/pgp_mobile.swift:531-534`.
  - `FfiConverterData.write` uses `Int32(value.count)`: `bindings/pgp_mobile.swift:549-552`.
- `nl -ba bindings/pgp_mobileFFI.h | sed -n '1,60p'`
  - C `ForeignBytes.len` is `int32_t`: `bindings/pgp_mobileFFI.h:32-36`.
- `nl -ba bindings/pgp_mobile.swift | sed -n '1230,1265p'`
  - `encrypt`/`encryptBinary` lower plaintext, recipients, signing key, and self key before Rust call: `bindings/pgp_mobile.swift:1237-1259`.
- `nl -ba bindings/pgp_mobile.swift | sed -n '1424,1440p'`
  - `importSecretKey` lowers user/import data before Rust call: `bindings/pgp_mobile.swift:1430-1436`.
- `nl -ba bindings/pgp_mobile.swift | sed -n '1564,1576p'`
  - `parseS2kParams` lowers user/import data before Rust call: `bindings/pgp_mobile.swift:1568-1573`.
- `nl -ba bindings/pgp_mobile.swift | sed -n '5315,5345p'`
  - Optional `Data` writes call `FfiConverterData.write`: `bindings/pgp_mobile.swift:5326-5336`.
- `nl -ba bindings/pgp_mobile.swift | sed -n '5438,5462p'`
  - Sequence `[Data]` writes sequence length with `Int32(value.count)` and then each item via `FfiConverterData.write`: `bindings/pgp_mobile.swift:5447-5455`.
- `nl -ba Sources/PgpMobile/pgp_mobile.swift | sed -n '38,42p;549,553p'`
  - Shipped copy has the same `Int32` conversions: `Sources/PgpMobile/pgp_mobile.swift:38-40`, `:549-552`.
- `nl -ba Sources/App/Keys/ImportKeyScreenModel.swift | sed -n '1,210p'`
  - Key import reads selected file into `Data` without a size cap: `Sources/App/Keys/ImportKeyScreenModel.swift:44-61`.
  - Import attempt snapshots data and zeroizes local copy after attempt: `Sources/App/Keys/ImportKeyScreenModel.swift:123-141`.
  - Stored imported key data is cleared with `resetBytes`: `Sources/App/Keys/ImportKeyScreenModel.swift:188-190`.
- `nl -ba Sources/App/Decrypt/DecryptScreenModel.swift | sed -n '80,170p;330,385p'`
  - Text ciphertext file import reads whole file into `Data`: `Sources/App/Decrypt/DecryptScreenModel.swift:108-130`.
  - Text recipient parsing passes imported/raw `Data` into service path: `Sources/App/Decrypt/DecryptScreenModel.swift:342-350`.
  - Separate file-ciphertext inspection has a classifier size cap before whole-file read: `Sources/App/Decrypt/DecryptScreenModel.swift:142-151`.
- `nl -ba Sources/App/Sign/VerifyScreenModel.swift | sed -n '80,120p;270,295p'`
  - Detached signature reads whole signature file into `Data`: `Sources/App/Sign/VerifyScreenModel.swift:88-94`.
  - Cleartext file import reads whole file into `Data`: `Sources/App/Sign/VerifyScreenModel.swift:97-120`.
  - Cleartext verification passes imported/raw `Data` into service path: `Sources/App/Sign/VerifyScreenModel.swift:282-288`.
- `nl -ba Sources/Services/FFI/PGPMessageOperationAdapter.swift | sed -n '1,110p;230,285p'`
  - Text message paths pass `Data` to FFI adapters: `Sources/Services/FFI/PGPMessageOperationAdapter.swift:17-27`, `:59-77`, `:230-241`, `:269-280`.
  - File encrypt uses path API: `Sources/Services/FFI/PGPMessageOperationAdapter.swift:80-101`.
- `nl -ba Sources/Services/DecryptionService.swift | sed -n '1,180p'`
  - Text parse path dearmors/matches in memory: `Sources/Services/DecryptionService.swift:38-63`.
  - File parse path uses path-based recipient matching: `Sources/Services/DecryptionService.swift:66-99`.
