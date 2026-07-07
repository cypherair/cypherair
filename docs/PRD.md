# Product Requirements Document (PRD)

> **Status:** Canonical current-state.<br>
> **Purpose:** Product scope, key families, user workflows, and product-level security behavior for CypherAir.<br>
> **Audience:** Human developers, product reviewers, and AI coding tools.<br>
> **Companion documents:** [TDD](TDD.md) · [ARCHITECTURE](ARCHITECTURE.md) · [SECURITY](SECURITY.md)<br>
> **Update triggers:** Product scope, user workflows, profile behavior, or roadmap change.<br>
> **Last reviewed:** 2026-07-05.

## 1. Product Overview

### 1.1 Goal

A fully offline OpenPGP encryption tool that enables everyday users to communicate securely with friends, preventing message content from being monitored by third parties.

### 1.2 Core Value Proposition

- **Truly Offline:** Zero network access; data leakage eliminated at the architectural level.
- **Minimal Permissions:** A single usage-description key and system-picker I/O only (the hard requirement is §2).
- **Standards-Compliant:** Compatible with GnuPG (Profile A), RFC 9580 (Profile B), and post-quantum RFC 9980.
- **Usable by Anyone:** No cryptographic knowledge required.

### 1.3 Supported Platforms

iOS 26.5+ / iPadOS 26.5+ / macOS 26.5+ / visionOS 26.5+ (same codebase). Minimum device: 8 GB RAM.

### 1.4 Explicit Exclusions

No messaging. No key-server sync. No custom encryption formats.

### 1.5 Open-Source License

`GPL-3.0-or-later OR MPL-2.0` for first-party code. All source code remains open-source.

### 1.6 Localization

English + Simplified Chinese, via the String Catalog (`.xcstrings`).

### 1.7 Accessibility

VoiceOver on all elements; fingerprints read segment-by-segment. Dynamic Type. 44×44pt touch targets. Text equivalents for all status indicators.

## 2. Offline & Permission Constraints

- **Fully offline (hard requirement):** No HTTP(S). No networked SDKs. No update checks. Code audit confirms zero network paths.
- **Minimal permissions (hard requirement):** The only `CypherAir-Info.plist` usage description is `NSFaceIDUsageDescription`, used for LocalAuthentication-backed biometric flows (not a runtime permission prompt). No camera (QR via system Camera + URL scheme), no photo library (PHPickerViewController), no other usage descriptions. Permitted I/O: app sandbox, Share Sheet, file picker, photo picker, `cypherair://` URL scheme, system "Open With" (file types: `.asc`, `.gpg`/`.pgp`, `.sig`). Clipboard: no proactive reading; paste areas only; copy shows a safety notice.

## 3. Encryption Profiles and Key Families

The App presents key generation as a choice between **key families** that combine message compatibility and private-key custody: **Portable Legacy** (Profile A software key, Ed25519 v4), **Portable Modern** (Ed25519 v6 software key), **Portable Modern · High** (Profile B / Ed448 v6 software key), **Portable Post-Quantum** (RFC 9980 ML-DSA-65/ML-KEM-768 software key), **Portable Post-Quantum · High** (RFC 9980 ML-DSA-87/ML-KEM-1024 software key), **Device-Bound Legacy** (Secure Enclave custody, P-256 v4), **Device-Bound Modern** (Secure Enclave custody, P-256 v6), **Device-Bound Post-Quantum** (RFC 9980 ML-DSA-65/ML-KEM-768 split custody), and **Device-Bound Post-Quantum · High** (RFC 9980 ML-DSA-87/ML-KEM-1024 split custody — the post-quantum components in the Secure Enclave, the classical components under the fixed-access envelope). Profile A (universal) and Profile B (advanced) remain the technical vocabulary for two of the classical software configurations, with the baseline Modern families (Ed25519 / P-256 v6) sitting between them; the family vocabulary is the product-facing layer above it. All nine families are product-selectable in the shipped key-generation surface (device-bound rows appear only on Secure Enclave hardware).

The post-quantum families ([POST_QUANTUM](POST_QUANTUM.md), [TDD](TDD.md) §1.3) cover generation, contact import/display, message classification, and the encrypt-surface quantum-safety indicator. Like the other RFC 9580-track families they are not compatible with GnuPG, and their public certificates exchange via file, share sheet, or clipboard — never QR (~30 KB armored).

### 3.1 Profile A: Legacy / Universal (Default)

The **Portable Legacy** and **Device-Bound Legacy** families. Maximum interoperability with all major PGP implementations, including GnuPG. v4 key format (RFC 4880), Ed25519+X25519, SEIPDv1, ~128-bit security. Algorithm suite: [SECURITY.md](SECURITY.md) §1.

**Compatible with:** GnuPG 2.1+, Sequoia, OpenPGP.js, GopenPGP, Thunderbird, Bouncy Castle — virtually all PGP tools.

### 3.2 Modern tier (RFC 9580): baseline and · High (Profile B)

The v6 RFC 9580 classical tier ships in two strengths (the **Portable/Device-Bound Modern** and **Portable Modern · High** families). **Modern** uses Ed25519+X25519 v6 with SEIPDv2 AEAD (~128-bit) — the widely supported modern default. **Modern · High** (Profile B) uses the stronger Ed448+X448 v6 (~224-bit), which some tools do not yet support. Algorithm suites: [SECURITY.md](SECURITY.md) §1.

**Compatible with:** Sequoia 2.0+, OpenPGP.js 6.0+, GopenPGP 3.0+, Bouncy Castle 1.82+, PGPainless 2.0+ (Ed448 requires the newer releases). **Not compatible with GnuPG.**

### 3.3 Key Type Selection UX

- **Key generation:** the user picks a key family from a flat "Key Type" list before generating (order below). Default: Portable Legacy.
  - "Portable Legacy" — "Works with all PGP tools including GnuPG. The private key can be exported and backed up."
  - "Portable Modern" — "Uses the modern OpenPGP standard (RFC 9580), widely supported by up-to-date tools. Not compatible with GnuPG. The private key can be exported and backed up."
  - "Portable Modern · High" — "Uses the modern OpenPGP standard (RFC 9580) with the stronger Ed448 curve; some tools do not yet support it. Not compatible with GnuPG. The private key can be exported and backed up."
  - "Portable Post-Quantum" — "Uses post-quantum encryption (RFC 9980) designed to resist future quantum computers. Not compatible with GnuPG. The private key can be exported and backed up."
  - "Portable Post-Quantum · High" — "Uses the strongest post-quantum encryption (RFC 9980, ML-KEM-1024) designed to resist future quantum computers. Not compatible with GnuPG. The private key can be exported and backed up."
  - "Device-Bound Legacy" — "Works with GnuPG and other OpenPGP tools. The private key lives in this device's Secure Enclave and cannot be exported or backed up."
  - "Device-Bound Modern" — "Uses the latest OpenPGP standard (RFC 9580). Not compatible with GnuPG. The private key lives in this device's Secure Enclave and cannot be exported or backed up."
  - "Device-Bound Post-Quantum" — "Uses post-quantum encryption (RFC 9980) designed to resist future quantum computers. Not compatible with GnuPG. The key is split for this device: the post-quantum half lives in the Secure Enclave, the classical half is sealed to this device. It cannot be exported or backed up."
  - "Device-Bound Post-Quantum · High" — "Uses the strongest post-quantum encryption (RFC 9980, ML-KEM-1024) designed to resist future quantum computers. Not compatible with GnuPG. The key is split for this device: the post-quantum half lives in the Secure Enclave, the classical half is sealed to this device. It cannot be exported or backed up."
  - Each row has an info button opening a detail sheet: algorithms, key version, message format, approximate security level, exportability, GnuPG compatibility, custody.
  - Device-bound families require passing a commitment sheet (custody, fixed biometric enforcement, non-exportability, loss consequence, public artifacts are not backups) before generation starts; the rows appear only where the capability resolver and a wired generation service allow them.
- **Encryption:** message format is determined automatically by recipient key version — v4 → SEIPDv1, v6 → SEIPDv2 (AEAD), mixed → SEIPDv1. Never a manual choice. See [TDD](TDD.md) §1.4.
- **Decryption:** the App accepts and decrypts both v4 and v6 messages regardless of the user's own key profile.
- **Multiple keys:** a user may hold keys of different families (e.g. a Profile A key for GnuPG contacts and a post-quantum key for the future-proof ones). One key is designated "Default." Profiles are immutable after generation — switching means generating a new key.

### 3.4 Apple Secure Enclave Custody (Device-Bound key families)

Secure Enclave custody is the hardware-backed private-key custody mode behind the Device-Bound families — a custody model, not a third `PGPKeyProfile`. Private-key operations happen inside the Secure Enclave and the long-term private scalar never enters CypherAir's Swift or Rust plaintext memory. Device-Bound Post-Quantum extends this as **split custody**: the ML-DSA-65/ML-KEM-768 components (or ML-DSA-87/ML-KEM-1024 for the · High tier) live in the enclave, the Ed25519/X25519 classical components (Ed448/X448 for · High) are sealed under a fixed-access envelope, and every composite signature or decryption requires an in-enclave operation — the classical component alone can do neither. Full custody contract and evidence: [SECURE_ENCLAVE_CUSTODY](SECURE_ENCLAVE_CUSTODY.md); split-custody rationale: [POST_QUANTUM](POST_QUANTUM.md).

The product tradeoff differs from software custody: the private key is device-bound, not exportable, and cannot be migrated or restored from backup. Device loss, key-handle loss, or loss of biometric access can make the key permanently unusable. The shipped UI presents this as an explicit opt-in (commitment sheet before generation), a distinct custody display (Key Type row with device-bound explainer, custody badges), and no backup badge or backup flow for device-bound keys.

### 3.5 Security Hard Rules

All failures produce user-understandable error messages (§4.7). The app-wide hard rules — AEAD hard-fail with no plaintext fragments, secure randomness, no secret logging, memory zeroing — are canonical in CLAUDE.md "Hard Constraints" and [SECURITY.md](SECURITY.md) §10.

## 4. User Workflows

### 4.1 First Run, Guided Tutorial, and Key Generation

```
Open App → Onboarding (3 pages) → tutorial decision page
→ Start Guided Tutorial OR Skip Tutorial and Enter App
→ If tutorial starts: isolated sandbox modules → explicit Finish → real app
→ Real app → Keys → Generate Key → select key family (§3.3)
→ Name (required) + email (optional, recommended) + expiry (default 2y)
→ Done → Prompt: back up private key & share public key
```

- The guided tutorial is a sandboxed learning path, not a key-generation prerequisite. Tutorial keys, contacts, messages, settings, and outputs never touch the real workspace ([SECURITY.md](SECURITY.md) §6). It can be skipped without being marked complete, and completion is recorded only on explicit Finish. Both onboarding and the tutorial are replayable from Settings.
- Revocation certificate auto-generated at key creation; exportable from the key detail page. The post-generation prompt makes revocation export the primary action for device-bound keys (no backup exists for them); for software keys it prompts backup and public-key sharing.
- **Key detail page:** full fingerprint, short key ID (de-emphasized), Key Type row (family name; device-bound keys drill into a custody explainer), backup status badge for software keys (device-bound keys show the non-exportable statement, no backup flow), expiry modification, key-level revocation export, and selective revocation launchers (subkey / User ID).

### 4.2 Public Key Exchange

- **QR via system Camera (recommended, classical families):** `cypherair://import/v1/<base64url binary, no padding>`. Alice shows the QR, Bob scans with the system Camera → "Open in CypherAir" → confirm → added. Fallback: QR from photo (PHPicker + CIDetector). Post-quantum certificates exchange via the non-QR methods, with an explicit unavailable state on QR surfaces (§3).
- **File:** share `.asc` via Share Sheet. **Clipboard:** copy ASCII armor; recipient pastes.
- **Unified import:** Contacts → Add Friend's Key → QR Photo | File | Paste, with a fingerprint-verification reminder. URL-scheme import always requires user confirmation before adding a key.
- **Public key update:** same User ID + same fingerprint absorbs new public material (revocations, refreshed bindings, added User IDs/subkeys); exact duplicates are a no-op. Same User ID + different fingerprint means the key was regenerated — warn and ask the user to verify with the contact before accepting.

### 4.3 Encryption

```
Home → Encrypt → plaintext → recipients → encrypt-to-self (ON) → signature (ON)
→ signing identity if multi-key → Encrypt → Copy / Share
```

Files: pick file → same flow; binary `.gpg` default; streaming I/O with progress and cancellation; file size validated against available disk space at runtime. Encrypt-to-self defaults ON (configurable in Settings); signing defaults ON per message with no global off. Format is auto-selected (§3.3); the compose surface shows a quantum-safety indicator derived from the produced artifact (fully quantum-safe only when every recipient key is post-quantum).

Before encryption the App rates recipient-key compatibility: ✅ can encrypt; ⚠️ possible risk (e.g. format downgrade to SEIPDv1 for a v4 recipient, or key nearing expiry); ❌ cannot encrypt (no valid encryption subkey, or expired).

### 4.4 Decryption

- **Phase 1 (no auth):** parse header, match keys. No match → error without any authentication prompt.
- **Phase 2 (auth):** match → device authentication → decrypt → display.
- **Content lifecycle:** text lives in memory only, zeroed on dismiss or grace-period expiry; file previews live in the temp directory, deleted on exit and at app launch.

### 4.5 Signing & Verification

Text: cleartext signature. File: detached `.sig`. Signatures auto-verify during decryption with graded results; verify and decrypt screens render detailed per-signature entries, with the overall verdict taken from the summary state. Contact detail includes a contact-scoped certificate-signature workflow: direct-key verification, User ID binding verification, and User ID certification generation. Password/SKESK message handling exists at the service layer but is not part of the shipped app surface.

### 4.6 Backup & Restore

- Backup: authenticate → passphrase → S2K protect (Iterated+Salted for Profile A; Argon2id for Profile B and Portable Post-Quantum) → `.asc` via Share Sheet.
- Restore: import `.asc` → passphrase → stored with SE protection.
- Device-bound keys have no backup flow (§3.4).

### 4.7 Error Messages

Every failure produces a user-understandable message; the exact copy is owned by the String Catalog. The semantic contract:

| Error | Severity | Meaning conveyed to the user |
|-------|----------|------------------------------|
| AEAD/MDC failure | ❌ hard error | Content may have been tampered with; nothing shown |
| No matching key | ❌ hard error | Message is not addressed to the user's identities |
| Unsupported algorithm | ❌ hard error | Method not supported |
| Corrupt data | ❌ hard error | Damaged input; ask the sender to resend |
| Wrong passphrase | ❌ hard error | Re-enter the backup passphrase |
| Invalid QR payload | ❌ hard error | Not a valid CypherAir public key |
| Bad signature | ❌ hard error | Content may have been modified |
| Key expired | ⚠️ warning | Ask the sender to update their key |
| Unknown signer | ⚠️ warning | Signer not in Contacts |
| Unsupported QR version | ⚠️ warning | A newer app version is required |

Format-downgrade situations are surfaced *before* encryption as a compatibility rating in the recipient chooser (§4.3), not as a post-hoc error.

### 4.8 Contacts

- Contacts are person-centered entries, not bare public-key files: one **preferred** key, optional **additional** active keys, and **historical** keys retained for signer recognition and audit context. Only the preferred key participates in encryption recipient resolution.
- Contact detail separates local manual fingerprint verification (a local user assertion) from OpenPGP certification (cryptographic evidence, exportable explicitly as certification signatures).
- Search and free-form tags. In Encrypt, a tag is a one-click batch selection that adds the tag's currently encryptable contacts to the explicit recipient selection; users then add, remove, or clear recipients. Contacts never store recipient lists.
- Contacts package exchange is not active. Any future complete Contacts backup or device migration must be mandatory encrypted export/import, never plaintext social-graph export.

### 4.9 App Protection

**Privacy cover and app lock** — two separate layers (cover ≠ lock):

- **Cosmetic privacy cover:** a content-obscuring overlay whenever the app is not foreground-active (multitasking snapshot, shoulder-surfing). No coupling to authentication.
- **App lock:** an explicit lock state. Leaving the foreground *covers* immediately; the app *locks* — clears decrypted content and requires re-authentication — after the grace period elapses following a genuine away event (iOS/iPadOS/visionOS: the app entering the background; macOS: app resign), or on the away event itself at grace = Immediately. macOS screen lock is different: it locks the app immediately, regardless of the grace setting. A biometric prompt's own transient deactivation is never an away event. While locked, an opaque lock surface (app name + caption) auto-invokes system authentication and hosts retry/lockout messaging.
- **Grace period:** Immediately / 1 min / 3 min (default) / 5 min. Within grace: resume normally, content retained (covered while away). Beyond grace: re-authentication required, content cleared, protected app data relocked.
- App-level auth is independent of per-operation Keychain auth. Each operation prompt runs inside a short operation-prompt session covering the prompt plus the immediately following Keychain/Secure Enclave work, so the sheet's lifecycle noise never locks the app mid-prompt while genuine away events under grace = 0 still relock promptly ([SECURITY.md](SECURITY.md) §4).

**Protected app data** — after app privacy authentication, protected app-data domains open through the same authenticated session (no redundant prompt). Coverage: protected settings, private-key control state, key metadata, and the protected Contacts domain; self-test reports stay short-lived export-only data. Row-level classification: [PERSISTED_STATE_INVENTORY](PERSISTED_STATE_INVENTORY.md).

**Authentication modes** — Settings → "Portable Key Protection":

- **Standard Mode (default):** biometrics with device-passcode fallback.
- **High Security Mode:** biometrics only; no passcode fallback for private-key operations. While biometrics are unavailable (sensor damage, lockout), decrypt/sign/export stay blocked.

Activation safeguards for High Security: a warning that losing biometric access means losing private-key access and that a current backup is needed (exact copy in the String Catalog), a backup check over software-custody keys (stronger warning + explicit acknowledgment when none is backed up; device-bound keys carry no backup obligation), and a biometric confirmation of the change. Device-bound keys always require biometrics — the enforcement is fixed and unaffected by this setting. Flag-level detail: [TDD](TDD.md) §3, [SECURITY](SECURITY.md) §4.

### 4.10 Self-Test

One-tap diagnostic: key generation, encrypt/decrypt, sign/verify, tamper, and key export/import round-trip run for each software profile (Profile A, Profile B, Post-Quantum), plus one profile-agnostic QR round-trip. Shareable report; report data is export-only and never persisted.

## 5. Technical Architecture (Summary)

Sequoia PGP (Rust, vendored OpenSSL backend) behind UniFFI; the Xcode project links the locally generated `PgpMobile.xcframework`. Private keys: Keychain + Secure Enclave wrapping for software custody, in-enclave operations for device-bound custody. UI: SwiftUI with UIKit system pickers. Everything else: [TDD](TDD.md), [ARCHITECTURE](ARCHITECTURE.md), [SECURITY](SECURITY.md).

## 6. Roadmap

- **Share Extension** (v2.0 candidate).
- Remaining post-quantum scope — the `sq` cross-implementation interop pack — is tracked on issue #567 ([POST_QUANTUM](POST_QUANTUM.md) §5).
