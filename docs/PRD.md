# Product Requirements Document (PRD)

> **Version:** v4.4<br>
> **Platform:** iOS 26.4+ / iPadOS 26.4+ / macOS 26.4+ / visionOS 26.4+<br>
> **License:** `GPL-3.0-or-later OR MPL-2.0` for first-party code<br>
> **Companion documents:** [TDD](TDD.md) · [ARCHITECTURE](ARCHITECTURE.md) · [SECURITY](SECURITY.md) · [POC](archive/POC.md) (archived)

## 1. Product Overview

### 1.1 Goal

A fully offline OpenPGP encryption tool that enables everyday users to communicate securely with friends, preventing message content from being monitored by third parties.

### 1.2 Core Value Proposition

- **Truly Offline:** Zero network access; data leakage eliminated at the architectural level.
- **Minimal Permissions:** The only usage-description key is `NSFaceIDUsageDescription`, used for biometric authentication. No camera, photo library, contacts, or network permissions. All I/O via system-provided pickers and Share Sheet.
- **Standards-Compliant:** Compatible with GnuPG (Profile A) and the latest RFC 9580 standard (Profile B).
- **Usable by Anyone:** No cryptographic knowledge required.

### 1.3 Supported Platforms

iOS 26.4+ / iPadOS 26.4+ / macOS 26.4+ / visionOS 26.4+ (same codebase). Minimum device: 8 GB RAM.

### 1.4 Explicit Exclusions

No messaging. No key-server sync. No custom encryption formats.

### 1.5 Open-Source License

`GPL-3.0-or-later OR MPL-2.0` for first-party code. All source code remains open-source.

### 1.6 Localization

English + Simplified Chinese. iOS String Catalog (.xcstrings) for community translations.

### 1.7 Accessibility

- VoiceOver on all elements. Fingerprints: segment-by-segment readout.
- Dynamic Type. 44×44pt touch targets. Text equivalents for all status indicators.

---

## 2. Offline & Permission Constraints

### 2.1 Fully Offline (Hard Requirement)

No HTTP(S). No networked SDKs. No update checks. Code audit confirms zero network paths.

### 2.2 Minimal Permissions (Hard Requirement)

The only `CypherAir-Info.plist` usage description is `NSFaceIDUsageDescription`, which CypherAir uses for LocalAuthentication-backed biometric flows. This is not a runtime permission prompt. No camera (QR via system Camera + URL scheme). No photo library (PHPickerViewController). No other permission descriptions in `CypherAir-Info.plist`. Permitted I/O: App sandbox, Share Sheet, file picker, photo picker, URL scheme, system "Open With."

---

## 3. Encryption Profiles

The App offers two encryption profiles. The user selects a profile when generating a key. The profile determines the key format, algorithms, and interoperability scope.

### 3.1 Profile A: Universal Compatible (Default)

Designed for maximum interoperability with all major PGP implementations, including GnuPG. v4 key format (RFC 4880), Ed25519+X25519, SEIPDv1, ~128-bit security.

For complete algorithm specifications, see [SECURITY.md](SECURITY.md) Section 1 (Profile A).

**Compatible with:** GnuPG 2.1+, Sequoia, OpenPGP.js, GopenPGP, Thunderbird, Bouncy Castle — virtually all PGP tools.

### 3.2 Profile B: Advanced Security

Designed for maximum security using RFC 9580 (the latest OpenPGP standard). Not compatible with GnuPG. v6 key format, Ed448+X448, SEIPDv2 AEAD, ~224-bit security.

For complete algorithm specifications, see [SECURITY.md](SECURITY.md) Section 1 (Profile B).

**Compatible with:** Sequoia 2.0+, OpenPGP.js 6.0+, GopenPGP 3.0+, Bouncy Castle 1.82+, PGPainless 2.0+. **Not compatible with GnuPG.**

### 3.3 Profile Selection UX

- **Key generation:** User chooses profile before generating a key. Default: Profile A.
  - "Universal Compatible" — "Works with all PGP tools including GnuPG."
  - "Advanced Security" — "Uses the latest encryption standard (RFC 9580) with stronger algorithms. Not compatible with GnuPG."
- **Encryption:** Message format is determined automatically by the recipient's key version. If recipient has a v4 key → SEIPDv1. If v6 key → SEIPDv2 (AEAD). The user does not choose this manually.
- **Decryption:** The App accepts and decrypts both v4 and v6 messages regardless of the user's own key profile.
- **Multiple keys:** A user may have keys of different profiles (e.g., a Profile A key for GnuPG contacts and a Profile B key for security-conscious contacts).

### 3.4 Security Hard Rules

- AEAD auth failure → hard-fail; no plaintext fragments shown.
- All failures produce user-understandable error messages.
- Random numbers: SecRandomCopyBytes (Swift) / getrandom crate (Rust).
- No plaintext or private keys in logs. Sensitive data zeroed from memory.

---

## 4. User Workflows

### 4.1 First Run, Guided Tutorial, And Key Generation

```
Open App → Onboarding (3 pages) → tutorial decision page
→ Start Guided Tutorial OR Skip Tutorial and Enter App
→ If tutorial starts: isolated sandbox modules → explicit Finish → real app
→ Real app → Keys → Generate Key
→ Select profile: Universal Compatible (default) / Advanced Security
→ Name (required) + email (optional, recommended) + expiry (default 2y)
→ Done → Prompt: back up private key & share public key
```

- The guided tutorial is a sandboxed learning path, not a key-generation prerequisite. Tutorial keys, contacts, messages, settings, and outputs never read or write the real workspace.
- First-run users can skip the tutorial without marking it complete. The tutorial can be replayed from Settings, and completion is recorded only when the user explicitly finishes from the tutorial completion surface.
- Revocation cert auto-generated. Onboarding and the guided tutorial are re-viewable from Settings.
- Profile cannot be changed after generation. To switch profile, generate a new key.

### 4.2 Public Key Exchange

**Method A: QR via System Camera (Recommended)**
- Format: `cypherair://import/v1/<base64url OpenPGP binary, no padding>`
- Alice shows QR → Bob scans with system Camera → "Open in CypherAir" → confirm → added.
- Fallback: QR from photo (PHPicker + CIDetector).

**Method B:** Share .asc file via Share Sheet.

**Method C:** Copy ASCII armor to clipboard; recipient pastes.

**Unified Import:** Contacts → Add Friend's Key → QR Photo | File | Paste. Fingerprint verification reminder.

**Contacts Management:** Contacts are person-centered. A contact can retain multiple public keys with preferred, additional active, or historical usage state; recipient selection resolves a contact to its current preferred encryptable key. Contacts support search, tags, recipient lists, merge behavior, and a clear distinction between local manual fingerprint verification and OpenPGP certification history. Contacts package exchange is not a shipped feature, and any future complete Contacts backup or device migration must be a separate mandatory encrypted design.

### 4.3 Encryption

**Text:**
```
Home → Encrypt → plaintext → recipients → encrypt-to-self (ON) → signature (ON)
→ signing identity if multi-key → Encrypt → Copy / Share
```

**File:** Pick file → same flow. Binary .gpg default. Streaming I/O. Progress. Cancellable. Background task. File size validated against available disk space at runtime.

- **Encrypt-to-self:** Default ON, configurable in Settings.
- **Signing:** Default ON per message, no global off.
- **Message format:** Automatically determined by recipient key version. v4 recipient → SEIPDv1. v6 recipient → SEIPDv2 (AEAD OCB). Mixed recipients (v4 + v6) → SEIPDv1 (lowest common denominator).

### 4.4 Decryption

**Phase 1 (no auth):** Parse header, match keys. No match → error without auth prompt.

**Phase 2 (auth):** Match → device authentication → decrypt → display.

**Content Lifecycle:** Text: memory only, zeroed on dismiss or grace period expiry. Files: tmp dir, deleted on exit + app launch.

The App decrypts both SEIPDv1 and SEIPDv2 messages regardless of the user's own key profile.

### 4.5 Signing & Verification

Text: cleartext sig. File: detached .sig. Auto-verify during decryption. Graded results.

The shipped verify and decrypt routes preserve a summary-first result presentation while also showing detailed per-signature entries when available.

Contact detail includes a contact-scoped certificate-signature workflow for direct-key verification, User ID binding verification, and User ID certification generation.

Saved certification signatures are Contacts data only after an explicit save action. They remain separate from local manual verification and can be exported/shared only as explicit certification artifacts.

Password / SKESK message handling exists at the service layer, but it is not part of the current shipped app surface.

### 4.6 Backup & Restore

- **Profile A backup:** Auth → passphrase → Iterated+Salted S2K → .asc → Share Sheet.
- **Profile B backup:** Auth → passphrase → Argon2id S2K (512 MB / p=4 / t=3, ~3s target on contemporary hardware) → .asc → Share Sheet.
- **Restore:** Import .asc → enter passphrase → stored with SE protection.
- **Revocation cert:** Can be exported separately from key detail page via Share Sheet.
- **Selective revocation:** Key detail also exposes a dedicated export flow for subkey and User ID revocation certificates.

### 4.7 Error Messages

| Error | User Message |
|-------|-------------|
| AEAD failure | ❌ May have been tampered with. |
| No matching key | ❌ Not addressed to your identities. |
| Unsupported algo | ❌ Method not supported. |
| Key expired | ⚠️ Ask sender to update. |
| Bad signature | ❌ Content may have been modified. |
| Unknown signer | ⚠️ Signer not in Contacts. |
| Corrupt data | ❌ Damaged. Ask sender to resend. |
| Wrong passphrase | ❌ Re-enter backup passphrase. |
| Invalid QR | ❌ Not a valid CypherAir key. |
| Unsupported QR ver | ⚠️ Update the App. |
| Profile incompatible | ⚠️ This message uses a format your recipient's tool may not support. The message was encrypted using a compatible format instead. |

### 4.8 Clipboard Safety

First-copy notice. Dismissible. Also in Settings.

### 4.9 App Protection

**Privacy Screen**

Blur overlay when App enters background. Prevents multitasking switcher leakage.

**Re-Authentication on Resume**

- **Within grace period:** Resume normally. Decrypted content retained.
- **Grace period exceeded:** Device auth required. Content cleared.
- **Grace period options:** Immediately (0s) / 1 min (60s) / 3 min (180s, default) / 5 min (300s).

*App-level auth is independent of per-operation Keychain auth.*

**Protected App Data**

After app privacy authentication succeeds, the app can open protected app-data domains through the same authenticated session. Protected app data is separate from private-key material: it protects app-owned local state after unlock, while private keys remain under the Secure Enclave / Keychain private-key domain.

Protected app-data scope and per-surface classification are maintained in [PERSISTED_STATE_INVENTORY](PERSISTED_STATE_INVENTORY.md). At product level, current coverage includes ordinary protected settings, private-key control state, key metadata, and Contacts protected-domain state through PR8. Self-test reports remain short-lived export-only data rather than a protected diagnostics domain, and temporary/export/tutorial cleanup hardening is complete. Contacts PR7 package exchange is withdrawn; any future complete Contacts backup must be a separate mandatory encrypted design.

**Authentication Mode**

The App offers two authentication modes, selectable in Settings:

- **Standard Mode (default):** Face ID / Touch ID with device passcode fallback. Suitable for most users. Equivalent to Apple `deviceOwnerAuthentication`.
- **High Security Mode:** Face ID / Touch ID only, with no passcode fallback. Inspired by Apple's Stolen Device Protection, which removes passcode fallback for sensitive operations to prevent a thief who has obtained both the device and the passcode from accessing critical data. In this mode, if biometric authentication is unavailable (sensor damaged, face obscured), the user cannot perform any private-key operations (decrypt, sign, export) until biometric authentication is restored.

**Activation safeguards:** When the user enables High Security Mode, the App:

1. Displays a warning: "In this mode, if Face ID / Touch ID becomes unavailable, you will be unable to access your private keys. Ensure you have a current backup."
2. Verifies that at least one private key has been backed up (exported). If no backup exists, the warning is stronger and the user must acknowledge the risk explicitly.
3. Requires current biometric authentication to confirm the mode change.

*Technical detail: Standard Mode uses `SecAccessControlCreateFlags` `[.biometryAny, .or, .devicePasscode]` + `.privateKeyUsage`. High Security Mode uses `[.biometryAny]` + `.privateKeyUsage` only. Switching modes requires re-wrapping all SE-protected keys with the new access control flags. See [TDD](TDD.md) Section 3 and [SECURITY](SECURITY.md) Section 4 for full implementation details.*

---

## 5. Detailed Feature Requirements

### 5.1 Key Management

- **Generation:** Ed25519+X25519 (Profile A) or Ed448+X448 (Profile B). Revocation cert auto-generated.
- **Multi-Key:** Multiple keys with different profiles supported. One key = "Default."
- **Public Key Update:** Same UID + same fingerprint = absorb any new public update material (revocations, refreshed bindings, added User IDs/subkeys); exact duplicate re-import remains a no-op. Same UID + different fingerprint = key regenerated (warning: verify with contact before accepting update).
- **Key Detail Page:** Full fingerprint, Short Key ID (de-emphasized), profile indicator (A/B), backup status badge, expiry modification (MVP), key-level revocation export, and selective revocation launchers for subkey/User ID revocation export.

### 5.1.1 Contacts

- Person-centered Contacts keep relationship state on `ContactIdentity` records and key-specific state on `ContactKeyRecord` records.
- Contacts support multiple keys per person, merge, preferred-key selection, historical-key signer recognition, search, tags, and recipient lists.
- Manual verification remains a local fingerprint-check state. OpenPGP certification state and saved certification signature artifacts remain separate and are surfaced distinctly.
- Contacts data lives in protected app data after unlock. There is no Contacts package exchange; complete Contacts backup or device migration is deferred to a future mandatory encrypted design.

### 5.2 Encryption / Decryption

- Text + file. Multi-recipient. Encrypt-to-self. Two-phase decryption. Cancellable. Runtime disk space validation.
- Message format auto-selected by recipient key version. Mixed v4+v6 recipients → SEIPDv1.
- Device auth: Standard or High Security mode.

### 5.3 Signing / Verification

Text: cleartext sig. File: detached .sig. Auto-verify. Graded results.

- Verify and decrypt screens keep the legacy summary-first result while also rendering detailed per-signature entries when available.
- Contact detail includes a contact-scoped certificate-signature tool for direct-key verification, User ID binding verification, and User ID certification generation.
- Password / SKESK message workflows are not currently exposed in the shipped app UI.

### 5.4 Private Key Protection

Keychain + Secure Enclave P-256 key wrapping (CryptoKit ECDH + AES-GCM) + biometric/passcode auth. Keys device-bound. Two access control configurations for Standard/High Security modes. See [TDD](TDD.md) Section 3 and [SECURITY](SECURITY.md) Section 3.

### 5.5 App Protection

Privacy screen. Re-auth with grace period. Two auth modes. Protected app-data unlock after app authentication. Current protected app-data coverage includes protected settings, private-key control state, key metadata, Contacts protected-domain state through PR8, self-test export-only behavior, and temporary/export/tutorial cleanup; row-level classification lives in [PERSISTED_STATE_INVENTORY](PERSISTED_STATE_INVENTORY.md). Contacts PR7 package exchange is withdrawn; any future complete Contacts backup must be a separate mandatory encrypted design.

---

## 6. Usability Checks & Self-Test

### 6.1 Compatibility Check

Before encryption, evaluate recipient key compatibility:
- ✅ Can encrypt — recipient key compatible with sender's profile.
- ⚠️ Possible risk — e.g., format downgrade (v6 sender encrypting to v4 recipient; SEIPDv1 used instead of AEAD), or key nearing expiry.
- ❌ Cannot encrypt — no valid encryption subkey or key expired.

### 6.2 Self-Test

Key gen, encrypt/decrypt, sign/verify, tamper (1-bit flip), QR encode/decode. Runs for both Profile A and Profile B. Shareable report.

---

## 7. System Integration

- File types: .asc, .gpg/.pgp, .sig. URL scheme: cypherair://. Share Extension: v2.0.
- Clipboard: no proactive reading; paste areas; copy with safety notice.

---

## 8. Security Acceptance Criteria

### 8.1 Encryption

- [ ] AEAD hard-fail. Sig failure communicated. SecRandomCopyBytes. No logs. SE-wrapped Keychain. Memory zeroing. Tmp cleanup.

### 8.2 Profile Compliance

- [ ] Profile A keys generate v4 format with Ed25519+X25519. Messages use SEIPDv1.
- [ ] Profile B keys generate v6 format with Ed448+X448. Messages use SEIPDv2 (OCB).
- [ ] Encrypting to v4 recipient always produces SEIPDv1 regardless of sender's profile.
- [ ] Encrypting to v6 recipient produces SEIPDv2.
- [ ] Mixed v4+v6 recipients → SEIPDv1.
- [ ] App decrypts both SEIPDv1 and SEIPDv2 regardless of user's profile.
- [ ] Profile A export uses Iterated+Salted S2K. Profile B export uses Argon2id.

### 8.3 App Protection

- [ ] Privacy screen active on background.
- [ ] Re-auth after grace period functions correctly.
- [ ] Both Standard and High Security authentication modes function correctly.
- [ ] High Security Mode blocks all private-key operations when biometrics unavailable.
- [ ] Protected app data opens only after app privacy authentication or an active protected-data session.
- [ ] Protected app-data unlock does not add a redundant prompt when the app can reuse the authenticated launch/resume context.
- [ ] URL scheme import (`cypherair://`) requires user confirmation before adding key.
- [ ] Encrypt-to-self correct.

### 8.4 Interoperability

- [ ] Profile A: App ↔ GnuPG encrypt/decrypt/sign/verify all succeed.
- [ ] Profile B: App ↔ Sequoia/OpenPGP.js encrypt/decrypt/sign/verify all succeed.
- [ ] Profile B output rejected by GnuPG with clear error (not silent corruption).
- [ ] Tamper → failure in all cases.

### 8.5 Offline & Permission

- [ ] Airplane Mode works. No prompts. Only `NSFaceIDUsageDescription` in `CypherAir-Info.plist` (no other usage descriptions). No network/camera/photo APIs.

### 8.6 Accessibility

- [ ] VoiceOver. Fingerprint readout. Text equivalents. Dynamic Type.

### 8.7 Memory Safety

- [ ] Xcode Enhanced Security capability enabled with Hardware Memory Tagging.
- [ ] App tested under MIE (Memory Integrity Enforcement) on all models of iPhone 17 and iPhone Air (A19/A19 Pro) with no crashes or tag mismatches.
- [ ] OpenSSL (vendored C code) operates correctly under hardware memory tagging in both debug and release builds.

*Note: MIE is built right into Apple hardware and software in all models of iPhone 17 and iPhone Air. It provides hardware-level protection against buffer overflows and use-after-free vulnerabilities in C/C++ code (including vendored OpenSSL). On older devices, the App still runs normally but without hardware memory tagging protection.*

---

## 9. Technical Architecture (Summary)

Full details in [TDD](TDD.md). Key decisions:

- **OpenPGP:** Sequoia PGP 2.2.0 (Rust) + crypto-openssl vendored.
- **Profiles:** Profile A = `CipherSuite::Cv25519` + `Profile::RFC4880`. Profile B = `CipherSuite::Cv448` + `Profile::RFC9580`.
- **FFI:** Mozilla UniFFI. The `pgp-mobile` wrapper crate generates Swift bindings and packaged outputs; the current Xcode project links the locally generated `PgpMobile.xcframework` plus `bindings/module.modulemap`.
- **Key storage:** Keychain + SE P-256 wrapping (CryptoKit ECDH + AES-GCM). Two access control configurations for Standard/High Security modes.
- **UI:** SwiftUI. UIKit where needed (UIActivityViewController, UIDocumentPickerViewController, PHPickerViewController, beginBackgroundTask).
- **Storage:** Keychain + sandbox. No database.
- **Memory safety:** MIE / Enhanced Security enabled. Hardware Memory Tagging (MIE/EMTE) protects vendored OpenSSL C code on A19+ devices.

---

## 10. MVP Scope & Roadmap

### 10.1 MVP (v1.0)

- [x] Dual profile key generation (Profile A: Ed25519+X25519 v4 / Profile B: Ed448+X448 v6). Multi-key with default designation. Expiry modification. Revocation cert auto-generated.
- [x] Profile-aware encryption (auto format selection by recipient key version).
- [x] Key exchange: QR + Share Sheet + paste + photo QR. Public key update.
- [x] Text + file encrypt/decrypt (streaming I/O, cancel, runtime disk space validation). Encrypt-to-self. Two-phase decrypt.
- [x] Signing/verification. Contact management. Backup & restore (Iterated+Salted / Argon2id).
- [x] Device auth (Standard + High Security). SE wrapping.
- [x] Compatibility check. Self-test (both profiles). File/URL registration. Clipboard notice.
- [x] Privacy screen + re-auth + content lifecycle. Onboarding + guided tutorial. Backup indicator.
- [x] English + Chinese. Zero permissions. Background tasks. Accessibility. MIE.

### 10.2 v1.1 — Completed

- [x] Streaming file processing: file-path-based streaming I/O with constant memory usage (64 KB buffers), replacing in-memory processing for file operations.
- [x] File size increase: removed fixed 100 MB limit, replaced with runtime disk space validation.
- [x] Progress reporting and cancellation for all file operations (encrypt, decrypt, sign, verify).

### 10.3 v1.2 — Completed

- [x] macOS 26.4+ support (same codebase). Separate entitlements for macOS sandbox and file access. Conditional compilation for platform-specific APIs (clipboard, background tasks, biometric icons). The Rust build/packaging workflow includes the `aarch64-apple-darwin` release archive and packaged output slice.

### 10.4 v1.3 — Completed

- [x] Native visionOS 26.4+ support (same codebase). The project ships native `visionOS` and `visionOS Simulator` Rust release archives, links them directly in Xcode, and validates the native app path with `xcodebuild build -scheme CypherAir -destination 'generic/platform=visionOS' CODE_SIGNING_ALLOWED=NO`.

### 10.5 v2.0

Share Extension. Post-quantum cryptography (pending IETF PQC standard). Interop test-pack.

---

## Appendix A: Usage Scenarios

**Scenario 1: GnuPG User** — Alice generates a Profile A key. Exchanges with Bob (GnuPG user). Full interoperability.

**Scenario 2: Security-Conscious Pair** — Alice and Bob both generate Profile B keys. Messages use AEAD (OCB). Argon2id protects backups.

**Scenario 3: Mixed Profiles** — Alice (Profile B, v6) encrypts to Charlie (Profile A, v4). App auto-selects SEIPDv1. Charlie decrypts in GnuPG.

**Scenario 4: Multiple Keys** — Alice has both a Profile A key (for GnuPG contacts) and a Profile B key (for Sequoia contacts). She selects which identity to use per message.

**Scenario 5: Face-to-Face Exchange** — Alice and Bob meet. Alice shows QR on screen. Bob scans with system Camera → "Open in CypherAir" → confirm → added. Bob encrypts a message (encrypt-to-self ON) → sends via WeChat → Alice decrypts (two-phase + Face ID) → ✅ Valid signature. Alice sends reply. Bob re-reads his own sent ciphertext.

**Scenario 6: Remote Exchange** — Alice sends her public key (.asc) to Bob via iMessage. Bob imports and verifies fingerprint by phone call.

**Scenario 7: Encrypted File** — Alice encrypts a PDF → sends .gpg via AirDrop → Bob opens with "Open With" → CypherAir → two-phase decrypt + Face ID → preview/save.

**Scenario 8: Key Compromise** — Alice discovers her key may be compromised. She exports and distributes her revocation certificate. Contacts mark the key as revoked. Alice generates a new key.

**Scenario 9: QR from Screenshot** — Bob receives a screenshot of Alice's QR code. Contacts → Add Friend's Key → QR Photo → PHPicker (no permission) → CIDetector decode → confirm → added.

**Scenario 10: Contact Key Update** — Alice regenerates her key (same UID, new fingerprint). She sends her new public key. Bob's App detects same UID but different fingerprint → warning → Bob verifies with Alice → confirms update.

**Scenario 11: High-Risk User** — A journalist enables High Security Mode in Settings and generates a Profile B key. The App warns about backup necessity and requires Face ID confirmation. From this point, all decryption and signing requires biometric authentication only — even if someone obtains the device passcode, they cannot access encrypted messages. The journalist's private keys are protected by both Secure Enclave hardware binding and biometric-only access control. Messages use AEAD (OCB) encryption. Argon2id protects key backups.
