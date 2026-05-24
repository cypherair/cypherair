# Apple Secure Enclave Custody POC Phase 4 Evidence

Status: passed for production-proximate ECDH and decrypt feasibility on the
tested macOS machine. Phase 5 is still required before Apple Secure Enclave
custody can become product-selectable.

## Scope

Phase 4 tested whether Secure Enclave P-256 ECDH private-key operations can be
used through Sequoia's external decryptor seam to recover OpenPGP session keys
and decrypt v4/v6 encrypted messages while preserving tamper hard-fail behavior.

This POC did not test production custody metadata, UI, migration, recovery,
lifecycle UX, or app architecture integration.

## Environment

- macOS 26.5, build 25F71.
- Xcode 26.5, build 17F42.
- Rust `rustc 1.95.0`, Cargo `1.95.0`.
- Architecture: Apple Silicon `arm64`; Xcode selected an `arm64e` macOS build
  destination for the signed probe.
- Probe target: `SecureEnclaveCustodyProbe`.
- Bundle identifier:
  `com.chentianren.cypherair.poc.secureenclavecustody.probe`.

## Signed Probe Evidence

The existing `SecureEnclaveCustodyProbe` target was reused as an Xcode-signed
macOS `.app` with app sandbox enabled, a POC-only Keychain access group, and the
production-matching hardened/enhanced security entitlement classes from the
Phase 3 POC.

`codesign -d --entitlements -` showed the expected app sandbox, Keychain access
group, hardened-process/enhanced-security keys, and Apple-injected application
and team identifiers. As in Phase 3, `codesign --verify --strict --verbose=4`
reported `CSSMERR_TP_NOT_TRUSTED` only inside the ordinary Codex command
sandbox and passed outside that sandbox, so this remains classified as a Codex
keychain/trust visibility artifact.

## Secure Enclave Runtime Evidence

`bootstrap` completed successfully with Secure Enclave available, two generated
keys, distinct signing and key-agreement public keys, and 65-byte X9.63 public
keys. Runtime state, fixture, request, and response files were stored in a
private app-container run directory using `0700` directories and `0600` files.

`derive-shared` reloaded the key-agreement `SecKey` from Keychain and
revalidated public-key equality, role binding, key type, key size, Secure
Enclave token, access group, and signing/agreement distinctness before each
operation. `SecKeyCopyKeyExchangeResult` with `ecdhKeyExchangeStandard`
returned a 32-byte raw P-256 shared secret. Swift did not run the OpenPGP KDF or
AES Key Wrap unwrap.

No shared secrets, session keys, KEKs, plaintext, Keychain locators, stable
fingerprints, raw certificates, or temp capability paths were printed in probe
summaries.

Residual POC boundary: the raw shared secret crossed from the signed Swift probe
to Rust through a `0600` JSON response file in the private `0700` run directory
as hex-encoded `sharedSecretHex`. The probe did not print the value and normal
successful runs clean up the response file, but Swift `Data` and JSON/hex
intermediates are not explicitly zeroized, and malformed response read/parse
failures may leave the private response file behind for diagnosis. This is
acceptable only for Phase 4 POC evidence; Phase 5 and any production design must
narrow or remove this disk and heap exposure boundary.

## OpenPGP Evidence

Rust `mock-control` passed first, proving the Sequoia decryptor plumbing without
Secure Enclave hardware.

`secure-enclave-decrypt` passed with the signed probe as the ECDH oracle:

| Candidate | SEIPD | Session key recovered | Plaintext matched | Signature verified | Shared secret length |
| --- | --- | --- | --- | --- | --- |
| P-256 v4 | v1/MDC | passed | passed | passed | 32 bytes |
| P-256 v6 | v2/AEAD | passed | passed | passed | 32 bytes |

Recorded ciphertext lengths were 425 bytes for the v4 candidate and 470 bytes
for the v6 candidate. Public certificate lengths remained 639 bytes for v4 and
547 bytes for v6. The Rust harness performed PKESK matching, OpenPGP ECDH KDF,
AES Key Wrap unwrap, payload decrypt, signature verification, and zeroization of
plaintext buffers after comparison.

## Phase 4.5 GnuPG Interop Control

The Phase 4 Rust harness now includes a GnuPG-focused compatibility control for
Secure Enclave shaped v4 material. `gnupg-mock-control` uses a software P-256
v4 control certificate with the same public OpenPGP shape expected from the SE
path: ECDSA P-256 primary key with certify/sign flags, ECDH P-256 subkey with
SHA256 KDF and AES256 KEK, and user-id features limited to SEIPDv1/MDC.

On the tested machine, isolated `GNUPGHOME` execution with GnuPG 2.5.19 passed
for:

- importing the v4 P-256 public certificate into GnuPG;
- confirming primary algorithm 19, subkey algorithm 18, `nistp256`, and matching
  fingerprint through `--with-colons`;
- verifying a Sequoia/SE-shaped detached ECDSA signature with `GOODSIG` and
  `VALIDSIG`;
- rejecting tampered signed data;
- encrypting with GnuPG to the v4 P-256 ECDH certificate and confirming the
  packet shape is PKESK v3 ECDH plus SEIPDv1/MDC, not AEAD/tag 20;
- decrypting that GnuPG ciphertext through the external decryptor seam; and
- rejecting tampered encrypted data without accepting partial plaintext.

The companion `gnupg-interop --request <0600 json>` mode uses the signed Swift
probe for the real Secure Enclave signing and ECDH operations and adds the
bidirectional full-message scenarios: SE sign+encrypt to a temporary GnuPG
P-256 recipient, and GnuPG sign+encrypt back to the SE v4 certificate. That mode
is hardware/request-state dependent and was added as a manual evidence path; it
must not be treated as CI-mandatory.

## Failure And Cleanup Evidence

Swift failure coverage passed for invalid peer public key, wrong expected
agreement public key, missing agreement Keychain row, substituted signing tag,
non-Secure Enclave agreement key material, and wrong agreement key-size
metadata, in addition to the existing Phase 3 signing failures.

Rust failure coverage passed for duplicate public keys, swapped public keys,
wrong agreement public key, bad ephemeral point, bridge failure without
fallback, corrupted shared-secret response, symlinked request files, invalid
request permissions, tampered PKESK/recipient material, and tampered SEIPDv1/SEIPDv2
ciphertexts. Tampered messages were rejected without returning accepted
plaintext.

Cleanup deleted two POC Keychain private-key rows and all runtime capability
files; the app-container run directory was removed.

## Conclusion

Phase 4 production-proximate decrypt feasibility is proven for the tested
environment:

- The custody boundary used the signed sandboxed POC app and permanent Secure
  Enclave Keychain key rows.
- Secure Enclave performed only the P-256 ECDH private-key operation.
- Rust/Sequoia owned OpenPGP packet handling, KDF, AES unwrap, decrypt,
  verification, tamper handling, and zeroization.
- v4 SEIPDv1/MDC and v6 SEIPDv2/AEAD encrypted messages decrypted through the
  SE-backed `Decryptor` seam and rejected tampering without fallback.

Apple Secure Enclave custody remains non-selectable for product use until
Phase 5 validates app architecture, lifecycle, routing, and CI-test boundaries.
