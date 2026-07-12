# Post-Quantum OpenPGP (RFC 9980) — Design Rationale

> Status: Design rationale for the shipped post-quantum families (campaign #567). Current-state facts live in the canonical docs: PRD §3 (families), TDD §1 (profiles/formats), SECURE_ENCLAVE_CUSTODY §4.1 (split custody), PERSISTED_STATE_INVENTORY (storage rows). This document keeps the reasoning and red lines that are not obvious from the code, plus the remaining campaign scope.
> Purpose: Why the post-quantum families are shaped the way they are.
> Audience: Maintainer, reviewers, and AI coding tools.
> Update triggers: Any change to the custody split, seam ownership, format floor, or exchange rules.

## 1. Interoperability position

RFC 9980 is the IETF standards track (composite ML-DSA-65+Ed25519 primary/signing, algo 30; ML-KEM-768+X25519 encryption, algo 35; v6 certificates). GnuPG follows LibrePGP, whose post-quantum wire format is different and encryption-only; the two do not interoperate. Profile A remains the GnuPG-compatibility story — the PQ families make no GnuPG claim, and product copy must not imply one. The interop target for PQ artifacts is the Sequoia lineage (`sq` ≥ the RFC 9980 release). The higher ML-DSA-87+Ed448 / ML-KEM-1024+X448 tier (signing algo 31, encryption algo 36; NIST level 5) ships as both a portable software family (Portable Post-Quantum · High) and a device-bound split-custody family (Device-Bound Post-Quantum · High); its classical Ed448/X448 halves are generated and held in Rust/OpenSSL software — never in CryptoKit, whose Secure Enclave holds only the ML-DSA/ML-KEM halves — so no CryptoKit X448/Ed448 support is required. Out of scope: SLH-DSA, multi-part QR, and LibrePGP-format PQ. Families are chosen at generation and immutable; existing classical keys are never migrated or re-wrapped into PQ families.

**Red line: one OpenSSL.** `sequoia-openpgp ≥ 2.4.0` routes the `crypto-openssl` backend through `ossl`/`openssl-sys`; linkage must continue to flow through the vendored CypherAir OpenSSL fork — no second OpenSSL build may enter the dependency graph.

## 2. Split custody (why, and its red lines)

The Secure Enclave implements ML-KEM and ML-DSA but not the classical curves (X25519/Ed25519, or X448/Ed448 for the · High tier), so a whole composite key cannot be enclave-resident. Device-Bound Post-Quantum therefore splits custody: the PQ components are generated in and never leave the enclave; the classical components are sealed under the fixed-access envelope. The custody invariant (canonical in SECURE_ENCLAVE_CUSTODY §4.1): every composite signature and decryption requires an in-enclave operation, and the classical component alone can do neither.

Structural rules from the seam analysis:

- **Never construct Sequoia's native composite secret-key material for device-bound keys** — `mpi::SecretKeyMaterial::MLKEM768_X25519 { ecdh, mlkem }` requires both components at once. Split custody pairs the public key with custom `Decryptor`/`Signer` implementations (the proven external-P-256 architecture).
- A split key must never be exportable in any form that yields an operable key, and the classical component must not be independently reachable through any export or backup path.

## 3. Seam invariant and the vendored combiner

**Seam invariant:** Swift custody providers perform *exactly* the enclave-resident primitive — ML-KEM decapsulation returns the 32-byte key share; ML-DSA signing returns the signature. All OpenPGP-standardized derivation (the RFC 9980 KEM combiner, AES key-wrap, packet assembly, format selection) stays in the Rust engine. The FFI is not a trust boundary (same process); the rule exists to keep wire-format cryptography single-sourced and vector-testable in Rust. **Red line: no OpenPGP wire-format cryptography in Swift.**

Sequoia's combiner (`multi_key_combine`) is crate-private, so `pgp-mobile` vendors the construction, byte-verified against the 2.4.0 source (`pgp-mobile/src/composite_kem.rs`): `SHA3-256( mlkemShare ‖ ecdhShare ‖ ecdhCiphertext ‖ ecdhRecipientPublic ‖ algId ‖ "OpenPGPCompositeKDFv1" ‖ 0x15 )` → 32-byte AES-256 KEK → public `ecdh::aes_key_unwrap`. Composite signing needs no vendored crypto. When upstream exports the combiner (sequoia issue #1249), the vendored copy is deleted. The 32-byte ML-KEM share crossing the FFI carries the same zeroize-both-sides obligation as the P-256 shared secret.

## 4. Format floor and key exchange

The recipient-version-driven format rule (TDD §1.4) already produces correct results with PQ recipients; RFC 9980 adds one invariant on top: **any PQ recipient ⇒ AES-256 floor**, in both SEIPD v1 and v2. Hard constraint #8 (never SEIPDv2 to a v4 key holder) is unchanged.

The quantum-safe indicator claims quantum safety **only when every recipient key is post-quantum**; mixed sets get a visible not-fully-quantum-safe state — the claim is never shown for a mixed message.

A PQ public certificate armors to ~30 KB — an order of magnitude beyond single-QR capacity, and multi-part QR is rejected by decision. PQ public keys exchange via file / AirDrop / share sheet / armored clipboard; QR key-exchange surfaces show an explicit "not available for this key type" state (never a silent omission); fingerprint QR verification is retained for all families. Message and signature payloads (≈1.8 KB / ≈4.8 KB armored for short texts) remain clipboard-friendly.

## 5. Remaining scope (tracked on issue #567)

- **`sq` interop pack (landed):** cross-implementation RFC 9580/9980 fixtures plus live `sq` lanes, preserved under `pgp-mobile/tests/` and documented in [TESTING.md](TESTING.md) §5. The vendored-combiner cross-implementation check decrypts the committed `sq`-encapsulated post-quantum fixtures through the split-custody path — real-`sq` sample messages stand in for RFC-appendix sample-message vectors.
- Oldest-supported-iPhone Secure Enclave probe on maintainer hardware.
- Watch sequoia issue #1249 (`multi_key_combine` export) to delete the vendored combiner.
