# Proof-of-Concept (POC) Test Plan

> **Version:** v3.9  
> **Companion to:** [PRD](PRD.md) · [TDD](TDD.md)  
> **Audience:** POC Developers

## 1. Objective

Validate Sequoia PGP 2.2.0 + crypto-openssl + UniFFI + Secure Enclave + dual Profile system + MIE on iOS before full development.

### 1.1 Environment

| Item | Requirement |
|------|-------------|
| Device | All models of iPhone 17 or iPhone Air (A19/A19 Pro, MIE) with iOS 26+, 8 GB+ RAM |
| Mac | Apple Silicon, Xcode latest stable |
| Rust | Stable latest + aarch64-apple-ios, aarch64-apple-ios-sim |
| Sequoia | sequoia-openpgp 2.2.0 |
| UniFFI | 0.29.x |
| GnuPG | Latest stable (macOS, for Profile A interop) |

---

## 2. Test Categories

### 2.1 Compilation & Integration

- [ ] C1.1: Build pgp-mobile with sequoia-openpgp 2.2.0 + crypto-openssl vendored on macOS. *Pass: no errors, no C dependency issues.*
- [ ] C1.2: Cross-compile to aarch64-apple-ios. *Pass: .a produced, no linker errors.*
- [ ] C1.3: Cross-compile to aarch64-apple-ios-sim. *Pass: simulator app launches.*
- [ ] C1.4: UniFFI bindgen generates Swift bindings. *Pass: .swift compiles in Xcode.*
- [ ] C1.5: XCFramework created and imported. *Pass: Rust callable from Swift.*
- [ ] C1.6: Binary size < 10 MB (release + LTO + strip).

### 2.2 Core OpenPGP — Profile A (v4 / Ed25519+X25519)

- [ ] C2A.1: Generate Ed25519+X25519 v4 key pair. *Pass: key version is 4.*
- [ ] C2A.2: Sign + verify text.
- [ ] C2A.3: Encrypt + decrypt text (SEIPDv1).
- [ ] C2A.4: Encrypt-to-self: sender decrypts own ciphertext.
- [ ] C2A.5: File encrypt/decrypt: 1, 10, 50, 100 MB.
- [ ] C2A.6: Export key with Iterated+Salted S2K. Re-import with correct passphrase.
- [ ] C2A.7: Re-import with wrong passphrase → graceful error.
- [ ] C2A.8: Generate + parse revocation cert.

### 2.3 Core OpenPGP — Profile B (v6 / Ed448+X448)

- [ ] C2B.1: Generate Ed448+X448 v6 key pair. *Pass: key version is 6, algo is Ed448/X448.*
- [ ] C2B.2: Sign + verify text.
- [ ] C2B.3: Encrypt + decrypt text (SEIPDv2 AEAD OCB).
- [ ] C2B.4: Encrypt-to-self.
- [ ] C2B.5: File encrypt/decrypt: 1, 10, 50, 100 MB.
- [ ] C2B.6: Export key with Argon2id (512 MB / p=4 / ~3s). Memory peak < 1024 MB.
- [ ] C2B.7: Re-import with correct passphrase.
- [ ] C2B.8: Re-import with wrong passphrase → graceful error.
- [ ] C2B.9: Generate + parse revocation cert.

### 2.4 Cross-Profile Interoperability

- [ ] C2X.1: Profile A user encrypts to Profile B recipient (v6 key). *Pass: message format is SEIPDv2. Recipient decrypts.*
- [ ] C2X.2: Profile B user encrypts to Profile A recipient (v4 key). *Pass: message format is SEIPDv1. Recipient decrypts.*
- [ ] C2X.3: Profile B user encrypts to mixed recipients (v4 + v6). *Pass: format is SEIPDv1. Both decrypt.*
- [ ] C2X.4: Profile B user with encrypt-to-self encrypts to v4 recipient. *Pass: SEIPDv1 (mixed rule). Both sender and recipient decrypt.*
- [ ] C2X.5: Profile A signature verified by Profile B user, and vice versa.

### 2.5 GnuPG Interoperability (Profile A Only)

- [ ] C3.1: Export Profile A pubkey → gpg --import succeeds.
- [ ] C3.2: App (Profile A) encrypt → gpg --decrypt succeeds.
- [ ] C3.3: App (Profile A) sign → gpg --verify "Good signature."
- [ ] C3.4: gpg encrypt → App decrypt succeeds.
- [ ] C3.5: gpg sign → App verify succeeds.
- [ ] C3.6: Tamper 1 bit → gpg fails.
- [ ] C3.7: Import gpg pubkey → App encrypt → gpg decrypt.
- [ ] C3.8: Profile B pubkey → gpg --import. *Pass: gpg rejects or ignores v6 key (not silent corruption).*

### 2.6 Argon2id Memory Safety (Profile B Only)

- [ ] C4.1: Decrypt Profile B key with 512 MB Argon2id → success on 8 GB+ device.
- [ ] C4.2: Decrypt key with 1 GB Argon2id (external) → success or graceful error. NO crash.
- [ ] C4.3: Decrypt key with 2 GB Argon2id → graceful refusal. NO crash.
- [ ] C4.4: os_proc_available_memory() guard blocks > 75% available.

### 2.7 FFI Boundary

- [ ] C5.1: Binary round-trip (both profiles): key bytes Rust → Swift → Rust = identical.
- [ ] C5.2: Unicode round-trip: Chinese + emoji User IDs survive.
- [ ] C5.3: Each PgpError variant → correct Swift enum case.
- [ ] C5.4: 100 encrypt/decrypt cycles (per profile). No memory leak (Instruments — manual).
- [ ] C5.5: KeyProfile enum passes correctly across FFI boundary.

### 2.8 Secure Enclave

- [ ] C6.1: Generate P-256 key in SE (CryptoKit).
- [ ] C6.2: Wrap Ed25519 key (Profile A) + wrap Ed448 key (Profile B) via self-ECDH + HKDF + AES-GCM. Both succeed.
- [ ] C6.3: Store, retrieve, unwrap. Byte-identical. Auth prompted.
- [ ] C6.4: Use unwrapped key for decrypt → success (both profiles).
- [ ] C6.5: Delete SE key → unwrap fails with clear error.
- [ ] C6.6: Full lifecycle × 10 cycles (each profile). No corruption.

### 2.9 Authentication Modes

- [ ] C7.1: Standard Mode: decrypt with Face ID. Fail Face ID → passcode fallback → success. *Pass: passcode fallback works.*
- [ ] C7.2: High Security Mode: decrypt with Face ID. Fail → NO passcode. Blocked. *Pass: no fallback. Operation denied.*
- [ ] C7.3: Switch Standard → High Security: re-wrap completes. Decrypt works (biometric). *Pass: existing keys accessible under new mode.*
- [ ] C7.4: Switch High Security → Standard: re-wrap completes. Passcode fallback restored. *Pass: fallback restored.*
- [ ] C7.5: Enable High Security without backup → stronger warning + acknowledgment required. *Pass: warning displayed, acknowledgment required.*

### 2.10 Memory Integrity Enforcement

- [ ] C8.1: Enable Enhanced Security capability in Xcode with Hardware Memory Tagging. *Pass: project builds without issues.*
- [ ] C8.2: Full workflow (both profiles: key gen, encrypt/decrypt, sign/verify) on iPhone 17 or iPhone Air (A19/A19 Pro). *Pass: all operations complete. No tag mismatch crashes in Console/crash logs.*
- [ ] C8.3: OpenSSL operations (AES-256, SHA-512, Ed25519, X25519, Ed448, X448, Argon2id) under MIE. *Pass: all crypto operations succeed. No memory tagging violations.*
- [ ] C8.4: 100 encrypt/decrypt cycles under MIE (both profiles). Monitor for intermittent tag mismatches. *Pass: zero tag violations across 100 cycles.*

---

## 3. Success Criteria

ALL items must pass on physical device. Upon success: full development begins.

**Failure classification:**
- **Blocking:** Fundamental incompatibility (e.g., Ed448 not functional on iOS). Re-evaluate.
- **Non-blocking:** Workaround available. Document and proceed.
- **Deferred:** Edge case, not MVP-affecting. Document for v1.1.

## 4. Time Estimate

| Category | Time | Notes |
|----------|------|-------|
| 2.1 Compilation | 1–2 days | First-time toolchain setup |
| 2.2–2.3 Core PGP (both profiles) | 3–4 days | Wrapper API development, double the single-profile estimate |
| 2.4 Cross-profile | 1 day | Depends on 2.2/2.3 |
| 2.5 GnuPG interop | 1 day | Profile A only, mostly scripted |
| 2.6 Argon2id | 0.5–1 day | Profile B only, external key generation |
| 2.7 FFI | 1 day | Both profiles, Instruments profiling |
| 2.8 SE | 1–2 days | Both profiles, CryptoKit + Keychain |
| 2.9 Auth modes | 0.5–1 day | Extends SE work |
| 2.10 MIE | 0.5 day | Xcode config + smoke test |
| **Total** | **9–13 days** | Can compress with parallel work |

---

## Appendix: Revision Log

| Version | Changes |
|---------|---------|
| v3.5 | Initial POC for single-profile (Ed25519+X25519 v6). Authentication modes and MIE tests added. |
| v3.6 | Dual profile system: Core PGP split into Profile A (2.2) and Profile B (2.3). Cross-profile interop tests added (2.4). GnuPG interop scoped to Profile A only with v6 rejection test (C3.8). Argon2id scoped to Profile B only. FFI, SE, and MIE tests extended to cover both profiles. Time estimate increased to 9–13 days. |
| v3.7 | Restored detailed pass criteria inadvertently simplified during v3.6 revision: C1.1 ("no C dependency issues"), C1.2 ("no linker errors"), C6.1 ("CryptoKit"), C7.1–C7.5 (full pass descriptions), C8.1–C8.4 ("with Hardware Memory Tagging", "without issues", full pass descriptions). Added Notes column detail to time estimate table. |
| v3.8 | Cross-version audit and completeness pass. C6.2 restored wrapping method description "(self-ECDH + HKDF + AES-GCM)" alongside dual-profile coverage. C8.2 restored explicit operation list "(key gen, encrypt/decrypt, sign/verify)". C8.4 restored monitoring instruction "Monitor for intermittent tag mismatches." |
| v3.9 | Version sync with PRD/TDD v3.9. No content changes to POC. |
