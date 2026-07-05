# Product Requirements Document (PRD)

> **Status:** Canonical current-state.<br>
> **Purpose:** Product requirements, workflows, feature scope, and acceptance criteria for CypherAir.<br>
> **Audience:** Human developers, product reviewers, and AI coding tools.<br>
> **Version:** v4.4<br>
> **Platform:** iOS 26.5+ / iPadOS 26.5+ / macOS 26.5+ / visionOS 26.5+<br>
> **License:** `GPL-3.0-or-later OR MPL-2.0` for first-party code<br>
> **Companion documents:** [TDD](TDD.md) · [ARCHITECTURE](ARCHITECTURE.md) · [SECURITY](SECURITY.md)<br>
> **Update triggers:** Product scope, user workflows, profile behavior, acceptance criteria, or roadmap change.<br>
> **Last reviewed:** 2026-07-03.

## 1. Product Overview

### 1.1 Goal

A fully offline OpenPGP encryption tool that enables everyday users to communicate securely with friends, preventing message content from being monitored by third parties.

### 1.2 Core Value Proposition

- **Truly Offline:** Zero network access; data leakage eliminated at the architectural level.
- **Minimal Permissions:** The only usage-description key is `NSFaceIDUsageDescription`, used for biometric authentication. No camera, photo library, contacts, or network permissions. All I/O via system-provided pickers and Share Sheet.
- **Standards-Compliant:** Compatible with GnuPG (Profile A) and the latest RFC 9580 standard (Profile B).
- **Usable by Anyone:** No cryptographic knowledge required.

### 1.3 Supported Platforms

iOS 26.5+ / iPadOS 26.5+ / macOS 26.5+ / visionOS 26.5+ (same codebase). Minimum device: 8 GB RAM.

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

## 3. Encryption Profiles and Key Families

The App presents key generation as a choice between **key families** that combine message compatibility and private-key custody (issue #501, Phase 7): **Portable Compatible** (Profile A software key), **Portable Modern** (Profile B software key), **Portable Post-Quantum** (RFC 9980 software key), **Device-Bound Compatible** (Secure Enclave custody, P-256 v4), **Device-Bound Modern** (Secure Enclave custody, P-256 v6), and **Device-Bound Post-Quantum** (RFC 9980 split custody — post-quantum components in the Secure Enclave, classical components under the fixed-access envelope). Profile A/B remains the technical vocabulary for the two software configurations; the family vocabulary is the product-facing layer above it. All six families are product-selectable in the shipped key-generation surface (device-bound rows appear only on Secure Enclave hardware).

The post-quantum families (campaign #567, [POST_QUANTUM](POST_QUANTUM.md), [TDD](TDD.md) §1.3) cover generation, contact import/display, message classification, and the encrypt-surface quantum-safety indicator. Like the other RFC 9580-track families they are not compatible with GnuPG, and their public certificates exchange via file, share sheet, or clipboard — never QR (~30 KB armored).

### 3.1 Profile A: Universal Compatible (Default)

Designed for maximum interoperability with all major PGP implementations, including GnuPG. v4 key format (RFC 4880), Ed25519+X25519, SEIPDv1, ~128-bit security.

For complete algorithm specifications, see [SECURITY.md](SECURITY.md) Section 1 (Profile A).

**Compatible with:** GnuPG 2.1+, Sequoia, OpenPGP.js, GopenPGP, Thunderbird, Bouncy Castle — virtually all PGP tools.

### 3.2 Profile B: Advanced Security

Designed for maximum security using RFC 9580 (the latest OpenPGP standard). Not compatible with GnuPG. v6 key format, Ed448+X448, SEIPDv2 AEAD, ~224-bit security.

For complete algorithm specifications, see [SECURITY.md](SECURITY.md) Section 1 (Profile B).

**Compatible with:** Sequoia 2.0+, OpenPGP.js 6.0+, GopenPGP 3.0+, Bouncy Castle 1.82+, PGPainless 2.0+. **Not compatible with GnuPG.**

### 3.3 Key Type Selection UX

- **Key generation:** User picks a key family from a flat "Key Type" list before generating. Default: Portable Compatible (Profile A).
  - "Portable Compatible" — "Works with all PGP tools including GnuPG. The private key can be exported and backed up."
  - "Portable Modern" — "Uses the latest encryption standard (RFC 9580) with stronger algorithms. Not compatible with GnuPG. The private key can be exported and backed up."
  - "Portable Post-Quantum" — "Uses post-quantum encryption (RFC 9980) designed to resist future quantum computers. Not compatible with GnuPG. The private key can be exported and backed up."
  - "Device-Bound Compatible" — "Works with GnuPG and other OpenPGP tools. The private key lives in this device's Secure Enclave and cannot be exported or backed up."
  - "Device-Bound Modern" — "Uses the latest OpenPGP standard (RFC 9580). Not compatible with GnuPG. The private key lives in this device's Secure Enclave and cannot be exported or backed up."
  - "Device-Bound Post-Quantum" — "Uses post-quantum encryption (RFC 9980) designed to resist future quantum computers. Not compatible with GnuPG. The key is split for this device: the post-quantum half lives in the Secure Enclave, the classical half is sealed to this device. It cannot be exported or backed up."
  - Each row has an info button that opens a detail sheet covering algorithms, key version, message format, approximate security level, exportability, GnuPG compatibility, and custody.
  - Device-bound families require passing a commitment sheet (custody, fixed biometric enforcement, non-exportability, loss consequence, public artifacts are not backups) before generation starts; the rows appear only where the capability resolver and a wired generation service allow them.
- **Encryption:** Message format is determined automatically by the recipient's key version. If recipient has a v4 key → SEIPDv1. If v6 key → SEIPDv2 (AEAD). Mixed v4+v6 recipients → SEIPDv1 (lowest common denominator). The user does not choose this manually. See [TDD](TDD.md) Section 1.4.
- **Decryption:** The App accepts and decrypts both v4 and v6 messages regardless of the user's own key profile.
- **Multiple keys:** A user may have keys of different profiles (e.g., a Profile A key for GnuPG contacts and a Profile B key for security-conscious contacts).

### 3.4 Apple Secure Enclave Custody (Device-Bound key families)

Apple Secure Enclave Custody is the implemented hardware-backed private-key
custody mode behind the Device-Bound key families — a custody model, not a
replacement for Profile A or Profile B and not a third `PGPKeyProfile`. It
generates and holds P-256 private keys inside Apple Secure Enclave so signing
and ECDH private-key operations happen in hardware and the long-term private
scalar never enters CypherAir's Swift or Rust plaintext memory.

Device-Bound Post-Quantum extends the same custody model to RFC 9980 composite
keys as **split custody**: the ML-DSA-65 and ML-KEM-768 components are
generated and held in the Secure Enclave (never exportable), while the Ed25519
and X25519 classical components are sealed under a fixed-access
(`privateKeyUsage` + `biometryAny`) Secure Enclave envelope. Every composite
signature or decryption requires an in-enclave operation; the classical
component alone can neither sign nor decrypt anything. Split-custody design and
invariants: [POST_QUANTUM](POST_QUANTUM.md) §3 and
[SECURE_ENCLAVE_CUSTODY](SECURE_ENCLAVE_CUSTODY.md).

Key creation treats algorithm/configuration and private-key custody as separate
dimensions: `PGPKeyCapabilityResolver` exposes only combinations the platform,
OpenPGP rules, Sequoia support, CypherAir implementation, and product policy
support. Since Phase 7 the production policy exposes device-bound generation
and the implemented private operations. Phase 8 hardware/GnuPG-interop evidence
is captured and the Phase 9 release gate is satisfied (2026-06-14); the families
ship with the next tag-first stable release. See
[SECURE_ENCLAVE_CUSTODY](SECURE_ENCLAVE_CUSTODY.md).

This mode has a different product tradeoff from ordinary software-key custody:
the private key is device-bound, not exportable, and cannot be migrated or
restored from a backup. Device loss, Secure Enclave/key-handle loss, or loss of
the required biometric access may make the key permanently unusable. The shipped
UI presents this as an explicit opt-in (commitment sheet before generation), a
distinct custody display ("Key Type" with a device-bound explainer, custody
badges), and no backup badge or backup flow for device-bound keys. Full custody
reference: [SECURE_ENCLAVE_CUSTODY](SECURE_ENCLAVE_CUSTODY.md).

### 3.5 Security Hard Rules

- All failures produce user-understandable error messages (Section 4.7).
- The remaining app-wide hard rules — AEAD hard-fail with no plaintext fragments, secure randomness, no secret logging, memory zeroing — are canonically stated in CLAUDE.md "Hard Constraints — NEVER Violate" and [SECURITY.md](SECURITY.md) Section 10.

---

## 4. User Workflows

### 4.1 First Run, Guided Tutorial, And Key Generation

```
Open App → Onboarding (3 pages) → tutorial decision page
→ Start Guided Tutorial OR Skip Tutorial and Enter App
→ If tutorial starts: isolated sandbox modules → explicit Finish → real app
→ Real app → Keys → Generate Key
→ Select key type: Portable Compatible (default) / Portable Modern / Portable Post-Quantum / Device-Bound Compatible / Device-Bound Modern / Device-Bound Post-Quantum (device-bound rows shown only where the resolver and a wired generation service allow them; commitment sheet before device-bound generation)
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

### 4.3 Encryption

**Text:**
```
Home → Encrypt → plaintext → recipients → encrypt-to-self (ON) → signature (ON)
→ signing identity if multi-key → Encrypt → Copy / Share
```

**File:** Pick file → same flow. Binary .gpg default. Streaming I/O. Progress. Cancellable. Background task. File size validated against available disk space at runtime.

- **Encrypt-to-self:** Default ON, configurable in Settings.
- **Signing:** Default ON per message, no global off.
- **Message format:** Auto-selected by recipient key version (Section 3.3 / [TDD](TDD.md) Section 1.4).

### 4.4 Decryption

**Phase 1 (no auth):** Parse header, match keys. No match → error without auth prompt.

**Phase 2 (auth):** Match → device authentication → decrypt → display.

**Content Lifecycle:** Text: memory only, zeroed on dismiss or grace period expiry. Files: tmp dir, deleted on exit + app launch.

The App decrypts both SEIPDv1 and SEIPDv2 messages regardless of the user's own key profile.

### 4.5 Signing & Verification

Text: cleartext sig. File: detached .sig. Auto-verify during decryption. Graded results.

The shipped verify and decrypt routes consume detailed per-signature results, with the overall verdict taken from the summary state and summary entry index derived from those entries.

Contact detail includes a contact-scoped certificate-signature workflow for direct-key verification, User ID binding verification, and User ID certification generation.

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

**Privacy Cover and App Lock**

Two separate layers protect on-screen content (cover ≠ lock):

- **Cosmetic privacy cover:** a content-obscuring material overlay shown whenever the app is not
  foreground-active. It keeps sensitive content out of the multitasking-switcher snapshot and away
  from shoulder-surfing, and has no coupling to authentication.
- **App lock:** an explicit lock state. Leaving the foreground *covers* content immediately; the app
  *locks* — clears decrypted content and requires re-authentication — only after the grace period
  elapses following a genuine away event (iOS / iPadOS / visionOS: the app entering the background;
  macOS: app resign ∪ screen lock ∪ explicit "Lock Now"), or on the away event itself at
  grace = Immediately. A biometric prompt's own transient deactivation is never an away event.
  While locked, the app shows an opaque lock surface (app name + locked-state caption) on every platform
  that auto-invokes system authentication on appear and hosts the retry and
  biometrics-locked-out messaging.

**Re-Authentication on Resume**

- **Within grace period:** Resume normally. Decrypted content retained (the cover hides it while away).
- **Grace period exceeded:** Device auth required via the lock surface. Content cleared; protected
  app data relocked.
- **Grace period options:** Immediately (0s) / 1 min (60s) / 3 min (180s, default) / 5 min (300s).

*App-level auth is independent of per-operation Keychain auth. When an unlocked user action presents
system authentication (private-key operations, key generation/import wrapping, key-expiry change,
protection-mode and App Access Protection changes, Local Data Reset), the prompt and the immediately
following Keychain / Secure Enclave work that consumes the authenticated context run inside a short
operation-prompt session. Longer action work stays outside that window, so the sheet's own lifecycle
noise never locks the app mid-prompt while genuine macOS away events under grace=0 still relock
promptly outside the authentication window.*

**Protected App Data**

After app privacy authentication succeeds, the app can open protected app-data domains through the same authenticated session. Protected app data is separate from private-key material: it protects app-owned local state after unlock, while private keys remain under the Secure Enclave / Keychain private-key domain.

Protected app-data scope and per-surface classification are maintained in [PERSISTED_STATE_INVENTORY](PERSISTED_STATE_INVENTORY.md). At product level, current coverage includes ordinary protected settings, private-key control state, key metadata, and the protected Contacts domain. Contacts now supports person-centered entries, multiple keys per contact, manual verification and OpenPGP certification state, search, and tags over protected app data. Self-test reports remain short-lived export-only data rather than a protected diagnostics domain, and temporary/export/tutorial cleanup hardening is complete.

**Authentication Mode**

The App offers two portable-key authentication modes, selectable in Settings under "Portable Key Protection":

- **Standard Mode (default):** Face ID / Touch ID with device passcode fallback. Suitable for most users. Equivalent to Apple `deviceOwnerAuthentication`.
- **High Security Mode:** Face ID / Touch ID only, with no passcode fallback for private-key operations. In this mode, decrypt, sign, and export require biometric authorization before private-key material can be used. If biometric authentication is unavailable (sensor damaged, face obscured, or temporarily locked out), private-key operations remain unavailable until biometric authentication is restored.

**Activation safeguards:** When the user enables High Security Mode, the App:

1. Displays a warning: "In this mode, if Face ID / Touch ID becomes unavailable, you will be unable to access your private keys. Ensure you have a current backup."
2. Verifies that at least one software-custody private key has been backed up (exported); device-bound keys carry no backup obligation. If software keys exist with no backup, the warning is stronger and the user must acknowledge the risk explicitly.
3. Requires current biometric authentication to confirm the mode change.

Device-bound keys always require biometric authentication. For security, this enforcement is fixed and cannot be changed; Portable Key Protection does not affect device-bound keys.

*Technical detail: for portable software-custody keys, Standard Mode uses `SecAccessControlCreateFlags` `[.biometryAny, .or, .devicePasscode]` + `.privateKeyUsage`; High Security Mode uses `[.biometryAny]` + `.privateKeyUsage` only. Switching modes requires re-wrapping portable software-custody keys with the new access control flags. See [TDD](TDD.md) Section 3 and [SECURITY](SECURITY.md) Section 4 for full implementation details.*

---

## 5. Detailed Feature Requirements

### 5.1 Key Management

- **Generation:** Ed25519+X25519 (Profile A) or Ed448+X448 (Profile B). Revocation cert auto-generated.
- **Multi-Key:** Multiple keys with different profiles supported. One key = "Default."
- **Public Key Update:** Same UID + same fingerprint = absorb any new public update material (revocations, refreshed bindings, added User IDs/subkeys); exact duplicate re-import remains a no-op. Same UID + different fingerprint = key regenerated (warning: verify with contact before accepting update).
- **Key Detail Page:** Full fingerprint, Short Key ID (de-emphasized), Key Type row (family name; device-bound keys drill into a custody explainer), backup status badge for software keys (device-bound keys show the non-exportable statement instead, with no backup flow), expiry modification (MVP), key-level revocation export, and selective revocation launchers for subkey/User ID revocation export.

### 5.2 Contacts

- Contacts are person-centered entries, not bare public-key files. A contact may have one preferred key, additional active keys, and historical keys retained for signer recognition and audit context.
- Contact detail separates local manual fingerprint verification from OpenPGP certification. Manual verification is a local user assertion; saved certification artifacts are cryptographic evidence and may be exported explicitly as certification signatures.
- Contacts support search and free-form tags. Encrypt can use a tag as a one-click batch selection entry that adds the tag's currently encryptable contacts to the explicit recipient selection; users may then add, remove, or clear selected recipients before sending.
- Contacts does not store recipient lists; tag-based batch selection feeds the explicit recipient selection at encrypt time.
- Contacts package exchange is not active. Any future complete Contacts backup or device migration must be designed as mandatory encrypted export/import, not as plaintext or optional-encryption social-graph export.

### 5.3 Encryption / Decryption

- Text + file. Multi-recipient. Encrypt-to-self. Two-phase decryption. Cancellable. Runtime disk space validation.
- Message format auto-selected by recipient key version (Section 3.3).
- Device auth: Standard or High Security mode.

### 5.4 Signing / Verification

Text: cleartext sig. File: detached .sig. Auto-verify. Graded results.

- Verify and decrypt screens render detailed per-signature entries, with the overall verdict taken from the summary state and summary entry index derived from those entries.
- Contact detail includes a contact-scoped certificate-signature tool for direct-key verification, User ID binding verification, and User ID certification generation.
- Password / SKESK message workflows are not currently exposed in the shipped app UI.

### 5.5 Portable Key Protection

Portable software private keys use Keychain + Secure Enclave P-256 key wrapping (CryptoKit ECDH + AES-GCM) + biometric/passcode auth. Two access control configurations support Standard/High Security modes. The Settings control applies only to portable keys; device-bound keys always use biometric access and are not affected. See [TDD](TDD.md) Section 3 and [SECURITY](SECURITY.md) Section 3.

### 5.6 App Protection

Cosmetic privacy cover + explicit app lock (Section 4.9). Re-auth with grace period. Two auth modes. Protected app-data unlock after app authentication. Current protected app-data coverage includes protected settings, private-key control state, key metadata, protected Contacts data, self-test export-only behavior, and temporary/export/tutorial cleanup; row-level classification lives in [PERSISTED_STATE_INVENTORY](PERSISTED_STATE_INVENTORY.md). Contacts package exchange is not active (Section 5.2).

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

Each criterion below must hold in every release.

### 8.1 Encryption

- AEAD hard-fail. Sig failure communicated. SecRandomCopyBytes. No logs. SE-wrapped Keychain. Memory zeroing. Tmp cleanup.

### 8.2 Profile Compliance

- Profile A keys generate v4 format with Ed25519+X25519. Messages use SEIPDv1.
- Profile B keys generate v6 format with Ed448+X448. Messages use SEIPDv2 (OCB).
- Encrypting to v4 recipient always produces SEIPDv1 regardless of sender's profile.
- Encrypting to v6 recipient produces SEIPDv2.
- Mixed v4+v6 recipients → SEIPDv1.
- App decrypts both SEIPDv1 and SEIPDv2 regardless of user's profile.
- Profile A export uses Iterated+Salted S2K. Profile B export uses Argon2id.

### 8.3 App Protection

- Privacy cover active whenever the app is not foreground-active; lock surface shown when locked.
- Re-auth after grace period functions correctly.
- Both Standard and High Security authentication modes function correctly.
- High Security Mode blocks all private-key operations when biometrics unavailable.
- Protected app data opens only after app privacy authentication or an active protected-data session.
- Protected app-data unlock does not add a redundant prompt when the app can reuse the authenticated launch/resume context.
- URL scheme import (`cypherair://`) requires user confirmation before adding key.
- Encrypt-to-self correct.

### 8.4 Interoperability

- Profile A: App ↔ GnuPG encrypt/decrypt/sign/verify all succeed.
- Profile B: App ↔ Sequoia/OpenPGP.js encrypt/decrypt/sign/verify all succeed.
- Profile B output rejected by GnuPG with clear error (not silent corruption).
- Tamper → failure in all cases.

### 8.5 Offline & Permission

- Airplane Mode works. No prompts. Only `NSFaceIDUsageDescription` in `CypherAir-Info.plist` (no other usage descriptions). No network/camera/photo APIs.

### 8.6 Accessibility

- VoiceOver. Fingerprint readout. Text equivalents. Dynamic Type.

### 8.7 Memory Safety

- Xcode Enhanced Security capability enabled with Hardware Memory Tagging.
- App tested under MIE (Memory Integrity Enforcement) on supported A19/A19 Pro-or-newer hardware with no crashes or tag mismatches.
- OpenSSL (vendored C code) operates correctly under hardware memory tagging in both debug and release builds.

*Note: MIE provides hardware-level protection against buffer overflows and use-after-free in C/C++ code (including vendored OpenSSL) on supported hardware; unsupported older devices run normally without it. Device examples and details: [SECURITY.md](SECURITY.md) Section 8.*

---

## 9. Technical Architecture (Summary)

Full details in [TDD](TDD.md). Key decisions:

- **OpenPGP:** Sequoia PGP 2.4.0 (Rust) + crypto-openssl vendored.
- **Profiles:** Profile A = `CipherSuite::Cv25519` + `Profile::RFC4880`. Profile B = `CipherSuite::Cv448` + `Profile::RFC9580`.
- **FFI:** Mozilla UniFFI. The `pgp-mobile` wrapper crate generates Swift bindings and packaged outputs; the current Xcode project links the locally generated `PgpMobile.xcframework` plus `bindings/module.modulemap`.
- **Key storage:** Keychain + SE P-256 wrapping (CryptoKit ECDH + AES-GCM). Two access control configurations for Standard/High Security modes.
- **UI:** SwiftUI. UIKit where needed (UIActivityViewController, UIDocumentPickerViewController, PHPickerViewController, beginBackgroundTask).
- **Storage:** Keychain + sandbox. No database.
- **Memory safety:** MIE / Enhanced Security enabled. Hardware Memory Tagging (MIE/EMTE) protects vendored OpenSSL C code on supported A19/A19 Pro-or-newer devices.

---

## 10. MVP Scope & Roadmap

### 10.1 Shipped (v1.0 – v1.3)

- **v1.0 (MVP):** Dual-profile key generation, multi-key with default designation, expiry modification, auto-generated revocation certs; profile-aware encryption with auto format selection; key exchange via QR / Share Sheet / paste / photo QR with public-key update; text + file encrypt/decrypt with streaming I/O, cancel, disk-space validation, encrypt-to-self, and two-phase decrypt; signing/verification; contact management; backup & restore (Iterated+Salted / Argon2id); Standard + High Security auth with SE wrapping; compatibility check; dual-profile self-test; file/URL registration; clipboard notice; privacy screen + re-auth + content lifecycle; onboarding + guided tutorial; backup indicator; English + Chinese; zero permissions; background tasks; accessibility; MIE.
- **v1.1:** File-path-based streaming I/O with constant memory (64 KB buffers); fixed 100 MB limit replaced by runtime disk-space validation; progress reporting and cancellation for all file operations.
- **v1.2:** macOS 26.5+ support (same codebase) with separate entitlements and platform-conditional APIs; `aarch64-apple-darwin` slice in the Rust packaging workflow.
- **v1.3:** Native visionOS 26.5+ support (same codebase) with native device/simulator Rust release archives and the visionOS build probe.

### 10.2 v2.0 (Future)

Share Extension. Post-quantum cryptography — the IETF standard is published (RFC 9980, June 2026); active campaign: issue #567 and [POST_QUANTUM](POST_QUANTUM.md), which folds in the interop test-pack.

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

**Scenario 11: High-Risk User** — A journalist enables High Security Mode in Settings and generates a Profile B key. The App warns about backup necessity and requires Face ID confirmation. From this point, all decryption and signing requires biometric authentication at the private-key operation boundary; the device passcode cannot be used as a fallback to unlock those operations. The journalist's private keys are protected by both Secure Enclave hardware binding and biometric-only access control. Messages use AEAD (OCB) encryption. Argon2id protects key backups.
