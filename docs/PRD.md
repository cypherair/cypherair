# Product Requirements Document (PRD)

> **Version:** v3.9  
> **Platform:** iOS 26+ / iPadOS 26+  
> **License:** GPLv3  
> **Companion documents:** [TDD](TDD.md) · [POC](POC.md) · [ARCHITECTURE](ARCHITECTURE.md) · [SECURITY](SECURITY.md)

## 1. Product Overview

### 1.1 Goal

A fully offline OpenPGP encryption tool that enables everyday users to communicate securely with friends, preventing message content from being monitored by third parties.

### 1.2 Core Value Proposition

- **Truly Offline:** Zero network access; data leakage eliminated at the architectural level.
- **Zero Permissions:** No system permissions requested. All I/O via system-provided pickers and Share Sheet.
- **Standards-Compliant:** Compatible with GnuPG (Profile A) and the latest RFC 9580 standard (Profile B).
- **Usable by Anyone:** No cryptographic knowledge required.

### 1.3 Supported Platforms

iOS 26+ / iPadOS 26+ (same codebase). Minimum device: 8 GB RAM.

### 1.4 Explicit Exclusions

No macOS (this release). No messaging. No key-server sync. No custom encryption formats.

### 1.5 Open-Source License

GPLv3. All source code remains open-source.

### 1.6 Localization

English + Simplified Chinese. iOS String Catalog (.xcstrings) for community translations.

### 1.7 Accessibility

- VoiceOver on all elements. Fingerprints: segment-by-segment readout.
- Dynamic Type. 44×44pt touch targets. Text equivalents for all status indicators.

---

## 2. Offline & Permission Constraints

### 2.1 Fully Offline (Hard Requirement)

No HTTP(S). No networked SDKs. No update checks. Code audit confirms zero network paths.

### 2.2 Zero Permissions (Hard Requirement)

No permission descriptions in Info.plist. No camera (QR via system Camera + URL scheme). No photo library (PHPickerViewController). Permitted I/O: App sandbox, Share Sheet, file picker, photo picker, URL scheme, system "Open With."

---

## 3. Encryption Profiles

The App offers two encryption profiles. The user selects a profile when generating a key. The profile determines the key format, algorithms, and interoperability scope.

### 3.1 Profile A: Universal Compatible (Default)

Designed for maximum interoperability with all major PGP implementations, including GnuPG.

| Component | Algorithm | Notes |
|-----------|-----------|-------|
| Key format | v4 (RFC 4880) | Universal compatibility |
| Signing | Ed25519 (legacy EdDSA) | GnuPG 2.1+ support |
| Encryption | X25519 (legacy ECDH) | GnuPG 2.1+ support |
| Symmetric | AES-256 | |
| Message format | SEIPDv1 (MDC) | Non-AEAD; GnuPG compatible |
| Hash | SHA-512 | Accepts SHA-256 for legacy signature verification |
| S2K (key export) | Iterated+Salted (mode 3) | GnuPG compatible |
| Compression | DEFLATE (read-only) | Enabled for reading compatibility; outgoing messages are never compressed |
| Security level | ~128 bit | |

**Compatible with:** GnuPG 2.1+, Sequoia, OpenPGP.js, GopenPGP, Thunderbird, Bouncy Castle — virtually all PGP tools.

### 3.2 Profile B: Advanced Security

Designed for maximum security using RFC 9580 (the latest OpenPGP standard). Not compatible with GnuPG.

| Component | Algorithm | Notes |
|-----------|-----------|-------|
| Key format | v6 (RFC 9580) | Latest standard |
| Signing | Ed448 | ~224-bit security; deterministic signatures |
| Encryption | X448 | ~224-bit security; inherent AES-256 key wrap |
| Symmetric | AES-256 | |
| AEAD | OCB (primary), GCM (secondary) | OCB is RFC 9580 mandatory mode |
| Hash | SHA-512 | |
| S2K (key export) | Argon2id (512 MB / p=4 / ~3s) | Memory-hard; RFC 9580 recommended |
| Compression | DEFLATE (read-only) | Enabled for reading compatibility; outgoing messages are never compressed |
| Security level | ~224 bit | |

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

### 4.1 Key Generation

```
Open App → Onboarding (3 pages) → "Generate My Key"
→ Select profile: Universal Compatible (default) / Advanced Security
→ Name (required) + email (optional, recommended) + expiry (default 2y)
→ Done → Prompt: back up private key & share public key
```

- Revocation cert auto-generated. Onboarding re-viewable from Settings.
- Profile cannot be changed after generation. To switch profile, generate a new key.

### 4.2 Public Key Exchange

**Method A: QR via System Camera (Recommended)**
- Format: `cypherair://import/v1/<base64url OpenPGP binary, no padding>`
- Alice shows QR → Bob scans with system Camera → "Open in Cypher Air" → confirm → added.
- Fallback: QR from photo (PHPicker + Vision).

**Method B:** Share .asc file via Share Sheet.

**Method C:** Copy ASCII armor to clipboard; recipient pastes.

**Unified Import:** Contacts → Add Friend's Key → QR Photo | File | Paste. Fingerprint verification reminder.

### 4.3 Encryption

**Text:**
```
Home → Encrypt → plaintext → recipients → encrypt-to-self (ON) → signature (ON)
→ signing identity if multi-key → Encrypt → Copy / Share
```

**File:** Pick file (≤ 100 MB) → same flow. Binary .gpg default. Progress. Cancellable. Background task.

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

### 4.6 Backup & Restore

- **Profile A backup:** Auth → passphrase → Iterated+Salted S2K → .asc → Share Sheet.
- **Profile B backup:** Auth → passphrase → Argon2id S2K (512 MB / p=4 / ~3s) → .asc → Share Sheet.
- **Restore:** Import .asc → enter passphrase → stored with SE protection.
- **Revocation cert:** Can be exported separately from key detail page via Share Sheet.

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
| Invalid QR | ❌ Not a valid Cypher Air key. |
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

**Authentication Mode**

The App offers two authentication modes, selectable in Settings:

- **Standard Mode (default):** Face ID / Touch ID with device passcode fallback. Suitable for most users. Equivalent to iOS `deviceOwnerAuthentication`.
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
- **Public Key Update:** Same UID + same fingerprint = key content unchanged (re-import, no action needed). Same UID + different fingerprint = key regenerated (warning: verify with contact before accepting update).
- **Key Detail Page:** Full fingerprint, Short Key ID (de-emphasized), profile indicator (A/B), backup status badge, expiry modification (MVP).

### 5.2 Encryption / Decryption

- Text + file. Multi-recipient. Encrypt-to-self. Two-phase decryption. Cancellable. 100 MB limit.
- Message format auto-selected by recipient key version. Mixed v4+v6 recipients → SEIPDv1.
- Device auth: Standard or High Security mode.

### 5.3 Signing / Verification

Text: cleartext sig. File: detached .sig. Auto-verify. Graded results.

### 5.4 Private Key Protection

Keychain + Secure Enclave P-256 key wrapping (CryptoKit ECDH + AES-GCM) + biometric/passcode auth. Keys device-bound. Two access control configurations for Standard/High Security modes. See [TDD](TDD.md) Section 3 and [SECURITY](SECURITY.md) Section 3.

### 5.5 App Protection

Privacy screen. Re-auth with grace period. Two auth modes. Content lifecycle. Tmp cleanup. Background tasks.

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

- File types: .asc, .gpg/.pgp, .sig. URL scheme: cypherair://. Share Extension: v1.1.
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
- [ ] URL scheme import (`cypherair://`) requires user confirmation before adding key.
- [ ] Encrypt-to-self correct.

### 8.4 Interoperability

- [ ] Profile A: App ↔ GnuPG encrypt/decrypt/sign/verify all succeed.
- [ ] Profile B: App ↔ Sequoia/OpenPGP.js encrypt/decrypt/sign/verify all succeed.
- [ ] Profile B output rejected by GnuPG with clear error (not silent corruption).
- [ ] Tamper → failure in all cases.

### 8.5 Offline & Permission

- [ ] Airplane Mode works. No prompts. No usage descriptions. No network/camera/photo APIs.

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
- **FFI:** Mozilla UniFFI. Wrapper crate → Swift bindings → XCFramework.
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
- [x] Text + file encrypt/decrypt (≤ 100 MB, cancel). Encrypt-to-self. Two-phase decrypt.
- [x] Signing/verification. Contact management. Backup & restore (Iterated+Salted / Argon2id).
- [x] Device auth (Standard + High Security). SE wrapping.
- [x] Compatibility check. Self-test (both profiles). File/URL registration. Clipboard notice.
- [x] Privacy screen + re-auth + content lifecycle. Onboarding. Backup indicator.
- [x] English + Chinese. Zero permissions. Background tasks. Accessibility. MIE.

### 10.2 v1.1

Share Extension + streaming. File size increase.

### 10.3 v2.0

macOS. Post-quantum cryptography (pending IETF PQC standard). Interop test-pack. Multi-device sync.

---

## Appendix A: Usage Scenarios

**Scenario 1: GnuPG User** — Alice generates a Profile A key. Exchanges with Bob (GnuPG user). Full interoperability.

**Scenario 2: Security-Conscious Pair** — Alice and Bob both generate Profile B keys. Messages use AEAD (OCB). Argon2id protects backups.

**Scenario 3: Mixed Profiles** — Alice (Profile B, v6) encrypts to Charlie (Profile A, v4). App auto-selects SEIPDv1. Charlie decrypts in GnuPG.

**Scenario 4: Multiple Keys** — Alice has both a Profile A key (for GnuPG contacts) and a Profile B key (for Sequoia contacts). She selects which identity to use per message.

**Scenario 5: Face-to-Face Exchange** — Alice and Bob meet. Alice shows QR on screen. Bob scans with system Camera → "Open in Cypher Air" → confirm → added. Bob encrypts a message (encrypt-to-self ON) → sends via WeChat → Alice decrypts (two-phase + Face ID) → ✅ Valid signature. Alice sends reply. Bob re-reads his own sent ciphertext.

**Scenario 6: Remote Exchange** — Alice sends her public key (.asc) to Bob via iMessage. Bob imports and verifies fingerprint by phone call.

**Scenario 7: Encrypted File** — Alice encrypts a PDF (≤ 100 MB) → sends .gpg via AirDrop → Bob opens with "Open With" → Cypher Air → two-phase decrypt + Face ID → preview/save.

**Scenario 8: Key Compromise** — Alice discovers her key may be compromised. She exports and distributes her revocation certificate. Contacts mark the key as revoked. Alice generates a new key.

**Scenario 9: QR from Screenshot** — Bob receives a screenshot of Alice's QR code. Contacts → Add Friend's Key → QR Photo → PHPicker (no permission) → Vision decode → confirm → added.

**Scenario 10: Contact Key Update** — Alice regenerates her key (same UID, new fingerprint). She sends her new public key. Bob's App detects same UID but different fingerprint → warning → Bob verifies with Alice → confirms update.

**Scenario 11: High-Risk User** — A journalist enables High Security Mode in Settings and generates a Profile B key. The App warns about backup necessity and requires Face ID confirmation. From this point, all decryption and signing requires biometric authentication only — even if someone obtains the device passcode, they cannot access encrypted messages. The journalist's private keys are protected by both Secure Enclave hardware binding and biometric-only access control. Messages use AEAD (OCB) encryption. Argon2id protects key backups.

---

## Appendix B: Revision Log

| Version | Changes |
|---------|---------|
| v2.0–v3.5 | See previous history. |
| v3.6 | **Dual profile system introduced.** Profile A (Universal Compatible): v4 keys, Ed25519+X25519, SEIPDv1, Iterated+Salted S2K — full GnuPG compatibility. Profile B (Advanced Security): v6 keys, Ed448+X448, SEIPDv2 AEAD OCB, Argon2id — RFC 9580 ecosystem only. Auto format selection by recipient key version. Mixed recipient handling (v4+v6 → SEIPDv1). Profile selection in key generation UX. Acceptance criteria split by profile. Self-test covers both profiles. Scenarios updated for mixed-profile communication. Documents split into PRD + TDD + POC markdown files in repository. |
| v3.7 | **Content restoration and consolidation.** Restored content that was inadvertently removed or over-compressed during v3.6 revision: compression algorithm setting (Disabled) in both profile tables, file output format (.gpg default), full Authentication Mode description (High Security Mode rationale, activation safeguards, technical detail) with cross-references retained as supplementary, detailed App Protection acceptance criteria (High Security biometric-only enforcement), MIE explanatory note on compatibility, Technical Architecture summary (SE wrapping detail, UI framework, storage architecture). Scenarios 5–10 restored with full descriptions (previously marked "unchanged from v3.5" without content). Scenario numbering updated (v3.5 Scenario 7 merged with new Scenario 11). |
| v3.8 | **Cross-version audit and completeness pass.** Restored content inadvertently lost during v3.6/v3.7 revisions, verified against v3.5 docx and companion documents (SECURITY.md, ARCHITECTURE.md, CLAUDE.md). Changes: Section 4.1 restored "recommended" hint for email field. Section 4.6 added revocation cert export path. Section 8.3 restored "URL scheme requires confirmation" acceptance criterion. Section 9 restored full FFI pipeline description ("Wrapper crate → Swift bindings → XCFramework") and full MIE description ("Hardware Memory Tagging protects vendored OpenSSL C code on A19+ devices"). Section 10.1 MVP checklist restored multi-key, expiry modification, and revocation cert features. |
| v3.9 | **Second cross-version audit against v3.5 docx.** Scenario 11 restored Secure Enclave hardware binding + biometric-only access control description (present in v3.5 Scenario 7, lost during v3.6 rewrite). Section 5.1 restored "badge" in "backup status badge" (UI element specificity). Section 6.1 restored general "⚠️ Possible risk" label alongside format downgrade example (v3.8 had replaced the general label with a single specific case). |
