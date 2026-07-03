# Post-Quantum OpenPGP (RFC 9980) — Design

> **Status:** Active roadmap — approved campaign design (issue #567). **This document does not describe current shipped behavior**; it defines the invariants and red lines for the post-quantum key families before they exist in the product. As phases ship, the durable facts move into the canonical docs (PRD §3, TDD §1, SECURITY, SECURE_ENCLAVE_CUSTODY) per DOCUMENTATION_GOVERNANCE.md §6, and this document shrinks toward design rationale.<br>
> **Purpose:** Family model, invariants, and red lines for adding RFC 9980 post-quantum key families to CypherAir.<br>
> **Audience:** Maintainer, reviewers, and AI coding tools implementing campaign #567.<br>
> **Companion:** Issue #567 (settled decisions + phase gates) · Phase 0 evidence: `docs/PQC_SPIKE_2026-07.md` on branch `spike/rfc9980-pqc` · [PRD](PRD.md) §10.2 · [TDD](TDD.md) §1 · [SECURE_ENCLAVE_CUSTODY](SECURE_ENCLAVE_CUSTODY.md)<br>
> **Last reviewed:** 2026-07-02 (initial).<br>
> **Update triggers:** Any change to the family model, custody split, seam ownership, format floor, or exchange rules decided in campaign #567 review.

## 1. Scope

Two new key families, both built on composite algorithms from RFC 9980 (published June 2026, extending RFC 9580):

| Working name | Primary key | Encryption subkey | Custody |
|---|---|---|---|
| **Portable Post-Quantum** | ML-DSA-65+Ed25519 (algo 30), v6 | ML-KEM-768+X25519 (algo 35), v6 | Software, passphrase-protectable and exportable like today's portable families |
| **Device-Bound Post-Quantum** | algo 30, v6 | algo 35, v6 | **Split custody** (§3): PQ components Secure Enclave-resident, classical components software-wrapped |

In scope: generation, encryption/decryption, signing/verification, contact import/export of RFC 9980 certificates, the format floor (§4), and the key-exchange UX rules (§5). Final user-facing family names (en + zh-Hans) are a review item; "Portable/Device-Bound Post-Quantum" are working names aligned with the existing four-family vocabulary.

Out of scope, by decision (issue #567, 2026-07-02): the ML-DSA-87/ML-KEM-1024 tier (CryptoKit provides no X448/Ed448 for its classical halves), SLH-DSA, multi-part QR exchange (rejected), LibrePGP-format PQ of any kind, and any change to Profile A/B semantics. Families remain chosen at generation time and immutable per key; there is no migration or re-wrap of existing classical keys into PQ families.

## 2. Interoperability position

RFC 9980 is the IETF standards track. GnuPG follows LibrePGP, whose post-quantum wire format is different and encryption-only; the two do not interoperate. Consequences, stated plainly:

- Profile A (Universal) remains the GnuPG-compatibility story. The PQ families make no GnuPG compatibility claim, and product copy must not imply one.
- The interop test target for PQ artifacts is the Sequoia lineage (`sq` ≥ the RFC 9980 release) — this folds the PRD §10.2 "interop test-pack" roadmap item into the campaign.
- Dependency floor: `sequoia-openpgp ≥ 2.4.0` (the stable RFC 9980 release, 2026-07-02) with the `crypto-openssl` backend. 2.4.0 switches that backend to the `ossl` bindings; linkage must continue to flow through `openssl-sys` and therefore through the vendored CypherAir OpenSSL fork. **Red line: one OpenSSL — no second OpenSSL build may enter the dependency graph.**

## 3. Split custody (Device-Bound Post-Quantum)

The Secure Enclave implements ML-KEM-768, ML-KEM-1024, ML-DSA-65, and ML-DSA-87 (CryptoKit `SecureEnclave.*`, API-parity with `SecureEnclave.P256`: `generate()`, access-control + authentication-context initializers, `dataRepresentation` persistence). It does **not** implement X25519 or Ed25519, so a whole composite key cannot be enclave-resident. The design is split custody:

- The **PQ component** (ML-KEM-768 decapsulation key; ML-DSA-65 signing key) is generated in and never leaves the Secure Enclave. Its wrapped `dataRepresentation` blob (~3.6 KB / ~6 KB) is persisted through the existing envelope machinery.
- The **classical component** (X25519; Ed25519) is a software key wrapped under the existing private-key envelope, exactly like portable key material.

**Custody invariant (proposed wording for SECURE_ENCLAVE_CUSTODY.md, maintainer owns final language):** every composite decapsulation and every composite signature requires an in-enclave operation; no decryption or signing capability exists without the Secure Enclave. The PQ component is non-exportable. The classical component alone decrypts nothing and cannot produce a valid composite signature. This is a *component-precise* restatement of the device-bound promise — unlike Device-Bound Compatible/Modern, where the entire private key is enclave-resident, and the canonical custody doc must say so explicitly when Phase 3 ships.

Two structural rules from the Phase 0 seam analysis:

- **Never construct Sequoia's native composite secret-key material for device-bound keys.** `mpi::SecretKeyMaterial::MLKEM768_X25519 { ecdh, mlkem }` requires both components at once; split custody instead pairs the public key with custom `Decryptor`/`Signer` implementations — the proven `ExternalP256Decryptor` architecture.
- A split key must never be exportable in any form that yields an operable key, and the classical component must not be independently reachable through any export or backup path.

## 4. Seam invariant and the vendored combiner

**Seam invariant (settled 2026-07-02):** Swift custody providers perform *exactly* the enclave-resident primitive and nothing more — ML-KEM decapsulation returns the 32-byte key share; ML-DSA signing returns the 3,309-byte signature. All OpenPGP-standardized derivation — the RFC 9980 KEM combiner, AES key-wrap, packet assembly, format selection — stays in the Rust engine. The FFI is not a trust boundary (same process); this rule exists to keep wire-format cryptography single-sourced and vector-testable in Rust.

Phase 0 established that Sequoia's combiner (`multi_key_combine`) is crate-private, so `pgp-mobile` vendors the construction (≈10 lines, byte-verified against 2.4.0 source; full extraction in the spike report): `SHA3-256( mlkemShare ‖ ecdhShare ‖ ecdhCiphertext ‖ ecdhRecipientPublic ‖ algId ‖ "OpenPGPCompositeKDFv1" ‖ 0x15 )` → 32-byte AES-256 KEK → public `ecdh::aes_key_unwrap`. Composite signing needs no vendored crypto (two independent signatures over the same digest, assembled into a public-field `mpi::Signature` variant).

Rules:

- The vendored combiner must be covered by tests against RFC 9980 test vectors and by cross-checks against Sequoia's own encrypt path (encrypt with stock Sequoia → decrypt through the vendored path).
- An upstream request to export `multi_key_combine` (as `ecdh::decrypt_unwrap` already is) is part of the campaign; when Sequoia exposes it, the vendored copy is deleted.
- The 32-byte ML-KEM share crossing the FFI carries the same zeroize-both-sides obligation as the existing P-256 shared secret (`Zeroizing` carrier in Rust; `resetBytes`/managed lifetime in Swift).
- **Red line: no OpenPGP wire-format cryptography in Swift.** CryptoKit use is limited to the SE primitives (and the classical component operations only if Phase 3 review explicitly prefers them over the Rust-side implementation — default is Rust-side).

## 5. Format floor and key exchange

**Format selection.** The existing recipient-version-driven rule (TDD §1.4) already produces correct results with PQ recipients — verified empirically in Phase 0: PQ-only → SEIPDv2; PQ + Profile A-faithful v4 → SEIPDv1, both recipients decrypt. The campaign adds one invariant on top, from RFC 9980: **any PQ recipient ⇒ AES-256 floor**, in both SEIPD v1 and v2. Phase 2 encodes this as tests (and an assertion only if Sequoia's own selection is ever observed to violate it). Hard constraint #8 ("never SEIPDv2 to a v4 key holder") is unchanged.

**Quantum-safe indicator.** Mixed PQ/classical recipient sets are allowed (RFC 9980 MAY). The UI marks a message quantum-safe **only when every recipient key is post-quantum**; a mixed message gets a visible not-fully-quantum-safe state. Presentation depth is a Phase 1 review item; the invariant is that the quantum-safe claim is never shown for a mixed message.

**Key exchange.** Measured in Phase 0: a PQ public certificate armors to ~30 KB — an order of magnitude beyond single-QR capacity, and multi-part QR is rejected by decision. Rules: PQ public keys exchange via file / AirDrop / share sheet / armored clipboard copy; QR key-exchange surfaces show an explicit "not available for this key type" state (never a silent omission); fingerprint QR verification (small payloads) is retained for all families. Message and signature payloads (≈1.8 KB / ≈4.8 KB armored for short texts) remain clipboard-friendly.

## 6. Existing hard constraints, restated for PQ

CLAUDE.md hard constraints apply unchanged; the PQ-specific readings: AEAD hard-fail applies to SEIPDv2 PQ messages exactly as today (never partial plaintext); the ML-KEM share, session keys, and classical component secrets are zeroized on both sides of the FFI; all generation entropy comes from the platform sources already in use (`SecRandomCopyBytes` / SE TRNG / `getrandom`); no logging of any key material or shares.

## 7. Phases and gates (tracking lives in issue #567)

- **Phase 0 — done.** Feasibility spike; evidence in `docs/PQC_SPIKE_2026-07.md` (branch `spike/rfc9980-pqc`). Highlights: full Rust suite green on 2.4.0; PQ round-trips through the unmodified engine; CryptoKit↔OpenSSL component byte-compat all-pass including Secure Enclave paths on the maintainer's Mac.
- **Phase 1 — this document** (+ PRD §10.2 pointer update). Gate: maintainer review of the invariants above plus the named open items (§8).
- **Phase 2 — Portable Post-Quantum.** Sequoia-only: generation, family plumbing, format-floor tests, exchange-surface states, multi-family test matrix. Carries the `sequoia-openpgp = 2.4.0` dependency update (notices already regenerated in the spike). Updates TDD §1 and PRD §3 as canonical facts when it ships.
- **Phase 3 — Device-Bound Post-Quantum.** Split custody per §3–§4; security-sensitive review (SECURITY.md §10 gates); positive + negative tests; device lane on Apple Silicon; **oldest-supported-iPhone SE probe before any exposure**; SECURE_ENCLAVE_CUSTODY.md language lands here.
- **Phase 4 — exposure & release.** Product exposure decision, `sq` interop pack, localization. visionOS: proposal is to inherit the existing exposed-without-evidence accepted-risk stance; maintainer decides here.

Every phase requires explicit maintainer approval before its PR, per standing process.

## 8. Open items for Phase 1 review

1. Final family names + Simplified Chinese localization.
2. Quantum-safe indicator presentation depth (badge vs inline explanation vs both).
3. Custody-promise wording sign-off (§3) for SECURE_ENCLAVE_CUSTODY.md.
4. visionOS stance confirmation (§7 Phase 4).
5. Certificate shape: the default `general_purpose` builder adds a composite signing subkey, which is ~5.4 KB of the ~30 KB cert (subkey + its two composite signatures). Decide whether the PQ families keep the signing-subkey shape (symmetry with existing families) or sign with the primary only (smaller certs). Default proposal: keep symmetry; revisit only if exchange-size feedback demands it.
