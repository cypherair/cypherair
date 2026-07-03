# RFC 9980 Post-Quantum Feasibility Spike — Phase 0 Report

> Issue: #567 (Phase 0). Branch: `spike/rfc9980-pqc` (spike evidence only — never merges).
> Date: 2026-07-02/03. Executed on the maintainer's Apple Silicon Mac (macOS 26.5 SDK, Xcode 26.5).

## Verdict summary

| # | Phase 0 item (issue #567) | Result |
|---|---|---|
| 1 | Pin a PQC-capable Sequoia and build | **GO — better than planned:** stable `sequoia-openpgp 2.4.0` (the RFC 9980 release) shipped on crates.io **2026-07-02**, hours before this spike ran. The preview pin plan is obsolete. |
| 2 | RFC 9980 cert round-trip through the real pipeline | **GO — full suite green on 2.4.0 (400+ tests, 0 failures) and all 5 PQ spike tests pass through the unmodified `PgpEngine`.** |
| 3 | Five-target XCFramework through the pinned arm64e toolchain | **GO after one build-system fix** (§5): `ossl` forces openssl-sys's bindgen on, which needs per-target Apple sysroots — fixed in `scripts/build_apple_arm64e_xcframework.sh` on this branch. All eight slices then build; Swift unit lane 1,399/0 on the new artifact. |
| 4 | External-component injection seam (combiner placement) | **GO with one vendored piece:** implement `Decryptor`/`Signer` directly (the `ExternalP256Decryptor` architecture); vendor the ~10-line KEM combiner (crate-private upstream). Signing needs **zero** vendoring. |
| 5 | CryptoKit ↔ OpenSSL component byte-compat | **GO — all pass, including Secure Enclave paths.** |
| 6 | SE probe on oldest supported iPhone | **PENDING (maintainer device).** Mac SE passes everything. |

## 1. Dependency: Sequoia 2.4.0 (stable PQC) — released the day of this spike

- `sequoia-openpgp 2.4.0` published on crates.io 2026-07-02T20:32Z; NEWS: "adds support for post-quantum cryptography as defined in RFC 9980", supported on the OpenSSL and RustCrypto backends.
- The spike originally targeted the `2.2.0-pqc.1` preview and found a **hard blocker there**: the preview predates `CipherSuite::Cv448` (added in 2.3.0), so `pgp-mobile` (Profile B = Cv448 + RFC 9580) does not compile against it. The stable release erases this: `=2.4.0` compiles the existing crate unmodified.
- **Backend change to note:** 2.4.0's `crypto-openssl` moved from the `rust-openssl` bindings to the `ossl` crate (OpenSSL v3 EVP APIs; brings ML-KEM/ML-DSA/SLH-DSA). `ossl 1.5.2` is built with its `openssl-sys` feature, so linkage still flows through `openssl-sys` and therefore through the vendored CypherAir OpenSSL fork (3.6.2). Trade-off recorded in upstream NEWS: `ossl` drops RIPEMD-160 (v3-era legacy hash; CypherAir targets v4/v6 only) and adds CAST5/Blowfish decryption support.
- Open-source notices regenerated (120 notices): sequoia 2.3.0→2.4.0, new `ossl-1.5.2` (Apache-2.0), transitive refreshes. `pgp-mobile/Cargo.toml` pins `=2.4.0` on this branch; Phase 2 should carry the pin as a normal dependency-update commit.

## 2. RFC 9980 round-trip through the real pgp-mobile pipeline

Test file: `pgp-mobile/tests/pqc_spike.rs` (this branch). Generation uses the crate's existing CertBuilder pattern with `CipherSuite::MLDSA65_Ed25519` + `Profile::RFC9580`; everything else exercises the **unmodified** `PgpEngine` public API (`encrypt`, `decrypt_detailed`, `sign_cleartext`, `verify_cleartext_detailed`, `parse_recipients`).

**Results (all green; measurements from `--nocapture` runs):**

- The **entire existing Rust suite passes unmodified on 2.4.0** (400+ tests across 30+ binaries, 0 failures) — no API drift from 2.3.0 affects `pgp-mobile`.
- All five spike tests pass through the **unmodified** engine: PQ generation, encrypt/decrypt round-trip, cleartext sign/verify (`summary_state=Verified`), mixed-recipient encryption, and `parse_recipients` (returns the v6 subkey fingerprint — the app's recipient-matching path handles PQ as-is).

| Measurement | Value |
|---|---|
| PQ public cert, armored | **30,852 bytes** (~30 KB; `general_purpose` shape = MLDSA65+Ed25519 primary + composite signing subkey + MLKEM768+X25519 encryption subkey, each binding signature ~3.4 KB) |
| PQ TSK, binary | 22,860 bytes |
| Fits a single QR (≤2,953 B binary)? | **No — off by an order of magnitude.** File/AirDrop/clipboard exchange confirmed as the only viable v1 path; even multi-QR would need 10+ codes. |
| Encrypted message to one PQ recipient, armored | 1,823 bytes (clipboard-trivial) |
| Cleartext signature, armored | 4,825 bytes (~4.8 KB per signed text — UX sizing note for Phase 1) |

**Format selection (hard constraint #8) — already correct with PQ present:**

| Recipient set | PKESKs | SEIPD |
|---|---|---|
| PQ only (v6) | `[MLKEM768_X25519]` | **v2** |
| PQ + feature-defaulted v4 (advertises SEIPDv2) | `[MLKEM768_X25519, ECDH]` | v2 (legitimate: the v4 cert advertises v2 support) |
| PQ + **Profile A-faithful** v4 (SEIPDv1-only features, as the engine generates) | `[MLKEM768_X25519, ECDH]` | **v1** — engine correctly falls back; both recipients decrypt |

This empirically confirms RFC 9980's design point that ML-KEM-768+X25519 (algorithm 35) interoperates with SEIPDv1 for mixed v4 recipient sets, and that Sequoia's feature-driven negotiation — which the engine already relies on — extends to PQ without modification. Phase 2's matrix work reduces to *tests + the AES-256-floor assertion*, not new selection logic.

## 3. Custody seam analysis (split custody, Option A)

Analyzed on `2.2.0-pqc.1` by a dedicated source-reading pass and re-verified against `2.4.0` (`~/.cargo/registry/src/…/sequoia-openpgp-2.4.0`): all load-bearing facts identical.

**Decryption (algorithm 35, ML-KEM-768+X25519):**
- `PKESK::decrypt` → `decrypt_common` (`src/packet/pkesk.rs:318`) calls `crypto::Decryptor::decrypt(&mpi::Ciphertext, …)` and expects the **final session key** back. There is no post-processing seam like the public `ecdh::decrypt_unwrap` used by today's P-256 custody.
- The composite pipeline (X25519 share + ML-KEM share → combiner → AES-KW unwrap) lives inside `KeyPair::decrypt` (`src/crypto/asymmetric.rs:415-442`), and the combiner `multi_key_combine` (`asymmetric.rs:485`) is `pub(crate)` inside `pub(crate) mod asymmetric` (`crypto/mod.rs:32`) — **unreachable from outside the crate**.
- Everything else needed is public: `mpi::Ciphertext::MLKEM768_X25519 { ecdh: [u8;32], mlkem: [u8;1088], esk }` (public fields), `HashAlgorithm::SHA3_256.context()`, `Context::update/digest`, `PublicKeyAlgorithm → u8`, and `crypto::ecdh::aes_key_wrap`/`aes_key_unwrap` (RFC 3394).
- **Conclusion: vendor the combiner in `pgp-mobile` (~10 lines, Rust, vector-testable).** Exact construction (verified verbatim in both versions): `SHA3-256( mlkemShare ‖ ecdhShare ‖ ecdhCiphertext ‖ ecdhRecipientPublic ‖ algId(1 byte) ‖ "OpenPGPCompositeKDFv1" ‖ 0x15 )` → 32-byte AES-256 KEK → `aes_key_unwrap` of the ESK. The custom `PqExternalDecryptor` performs: SE callback for the ML-KEM share (32 bytes over the FFI, `Zeroizing`), software X25519 for the ECDH share (Rust-side; `Backend::x25519_shared_point` is crate-internal, so use the already-linked `openssl` crate's X25519 derive), vendored combiner, public `aes_key_unwrap`.
- **Follow-up filed upstream (recommended):** ask Sequoia to export `multi_key_combine` the way `ecdh::decrypt_unwrap` is exported — would delete our vendored copy.

**Signing (algorithm 30, ML-DSA-65+Ed25519):** strictly simpler — there is no combiner. `mpi::Signature::MLDSA65_Ed25519 { eddsa: [u8;64], mldsa: [u8;3309] }` has public fields; both components sign the **same digest** with no extra context. A custom `Signer` calls the SE for the ML-DSA signature, signs the digest with the software Ed25519 key, and constructs the variant directly. **Zero vendored crypto.**

**Split-custody structural note:** `mpi::SecretKeyMaterial::MLKEM768_X25519 { ecdh, mlkem }` is a both-fields-required enum variant. A split-custody key must therefore never construct sequoia's native secret material — exactly how `ExternalP256Decryptor` already works (public key + custom trait impl, no `SecretKeyMaterial`).

**Policy:** `StandardPolicy` ACCEPTs all seven PQ algorithms by default (`src/policy.rs:717-749`) — the unmodified app pipeline reaches PQ recipients without policy changes (empirically confirmed by §2).

## 4. CryptoKit ↔ OpenSSL cross-implementation check — ALL PASS

Method (production-faithful directions — CryptoKit only ever *decapsulates* and *signs* in split custody; Sequoia/OpenSSL does everything else):

1. CryptoKit generates ML-KEM-768 (software **and** `SecureEnclave.MLKEM768`); raw public key (1184 B) spliced into a SubjectPublicKeyInfo template; **OpenSSL 3.6.2** (same version lineage as the vendored fork) runs `pkeyutl -encap`; CryptoKit/SE decapsulates; shared secrets compared.
2. CryptoKit signs with ML-DSA-65 (software **and** `SecureEnclave.MLDSA65`); OpenSSL runs `pkeyutl -verify -rawin` against the spliced public key.

Results (2026-07-02, maintainer Mac, OpenSSL 3.6.2):

```
PASS mlkem768 sw: openssl-encap -> cryptokit-decap shared secrets MATCH (32 bytes)
PASS mlkem768 SE: openssl-encap -> SecureEnclave-decap shared secrets MATCH
PASS mldsa65 sw: cryptokit-sign -> openssl-verify           (pub 1952 B, sig 3309 B)
PASS mldsa65 SE: SecureEnclave-sign -> openssl-verify
```

Notable: the SE paths worked from an ad-hoc CLI binary (no app container needed on macOS), and CryptoKit's ML-DSA mode matches OpenSSL's default (pure ML-DSA, empty context) — the exact mode Sequoia's backend uses. Probe sources: `/tmp/pqcheck/{main.swift,run.sh}` (reproduced in Appendix A).

API note for Phase 3: CryptoKit's ML-DSA verify entry point is `isValidSignature(_:for:)` — Apple's sample article shows a stale `signature:` label that does not compile on SDK 26.5. Software `MLKEM768.PrivateKey` seed import is `init(seedRepresentation:publicKey:)` (the `publicKey` parameter is optional/nullable).

## 5. XCFramework + Swift lane on 2.4.0

**Finding (the one real build-system break, now fixed):** `ossl` hard-enables `openssl-sys`'s `bindgen` cargo feature (`cargo tree -i openssl-sys -e features`: `openssl-sys feature "bindgen" ← ossl v1.5.2 ← sequoia-openpgp v2.4.0`). openssl-sys therefore runs bindgen at build time for **every** target — new behavior; the previous `rust-openssl`-only path never invoked bindgen. bindgen (libclang) does not infer Apple cross-target sysroots the way `cc`/`openssl-src` do, so it parsed **macOS SDK headers for all targets**. Six of eight slices (iOS device arm64+arm64e, iOS sim, macOS arm64+arm64e, and the bindings step) built anyway — the wrong-sysroot parse is silently tolerated for iOS — but the visionOS targets hard-fail on availability attributes (`'__darwin_check_fd_set_overflow' is unavailable: not available on visionOS`).

**Fix (this branch, `scripts/build_apple_arm64e_xcframework.sh`):** a per-target `BINDGEN_EXTRA_CLANG_ARGS_<triple>` export mapping each Rust target to its SDK sysroot and clang target (iphoneos / iphonesimulator / macosx / xros / xrsimulator, arm64 + arm64e). This also stops the iOS/macOS slices from parsing the wrong SDK "successfully". The fix is required for Phase 2's dependency update regardless of anything PQ-specific.

**Results with the fix:**

- `./build-xcframework.sh --release` through the pinned arm64e stage1 toolchain: **success** — all eight slices built and packaged (iOS arm64+arm64e fat, iOS-sim, macOS arm64+arm64e fat, visionOS arm64+arm64e fat, visionOS-sim), `PgpMobile.arm64e-build-manifest.json` refreshed, generated UniFFI bindings byte-identical (no interface change — a pure dependency bump needs no Swift-side regen churn).
- **Swift unit lane (`CypherAir-UnitTests`, macOS arm64e): 1,399 tests, 0 failures** against the 2.4.0 artifact. The only casualties of the bump were three version-literal assertions in `OpenSourceNoticeStoreTests` pinning `sequoia-openpgp@2.3.0` (updated — the same class of change as the PR #518 dependency refresh).
- App-level visionOS build probe (`xcodebuild build -destination 'generic/platform=visionOS'`): **not runnable in this environment** — the visionOS 26.5 platform component is not installed in Xcode on this machine (the XROS SDKs used for Rust cross-compilation are). The Rust xros slices packaging is the spike-level evidence; the app probe joins the pending list below.

## 6. Remaining items for later phases

- **Oldest-device probe (pending, maintainer):** run the §4 probe (or the Phase 3 device tests) on the oldest supported iPhone to pin down SE PQ hardware coverage; Apple documents no explicit hardware gate, so runtime evidence is the arbiter. visionOS: proposal remains to inherit the existing exposed-without-evidence stance.
- **App-level visionOS build probe (pending, environment):** requires installing the visionOS 26.5 platform component in Xcode (Settings → Components) on the build machine; run `xcodebuild build -scheme CypherAir -destination 'generic/platform=visionOS'` once available. The freshly packaged xros slices are the current evidence.
- **RIPEMD-160 removal:** confirm nothing in the fixture/interop corpus relies on RIPEMD-160 (v3-era; expected no impact).
- **Upstream ask:** public `multi_key_combine` (see §3).

## Appendix A — cross-check probe method

The probe ran outside the repo tree (`/tmp/pqcheck`) to keep the branch free of throwaway tooling. Reproduction recipe:

1. **Swift side** (`swiftc -O main.swift -o pqprobe`, macOS 26.5 SDK): three subcommands — `mlkem-gen <sw|se>` (writes `seedRepresentation`/`dataRepresentation` + `publicKey.rawRepresentation`), `mlkem-decap <sw|se>` (reads key + ciphertext, writes `decapsulate(_:)` output), `mldsa-sign <sw|se>` (generates, writes public key + `signature(for:)` over a message file).
2. **SPKI splice:** generate a throwaway OpenSSL key of the same algorithm, take its `-pubout -outform DER` output minus the trailing raw-key bytes (1184 for ML-KEM-768, 1952 for ML-DSA-65) as a SubjectPublicKeyInfo prefix, and append CryptoKit's raw public key.
3. **OpenSSL side** (`/opt/homebrew/opt/openssl@3.6/bin/openssl`, 3.6.2): `pkeyutl -encap -inkey <spliced.der> -keyform DER -pubin -out ct.bin -secret ss.bin` for KEM; `pkeyutl -verify -pubin -inkey <spliced.der> -keyform DER -rawin -in msg.bin -sigfile sig.bin` for ML-DSA.
4. Compare the KEM shared secrets byte-for-byte; require "Signature Verified Successfully" for ML-DSA.

Run all four combinations (software/SE × KEM/DSA); all four passed on 2026-07-02.
