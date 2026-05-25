# Apple Secure Enclave Custody POC Phase 3 Evidence

> Status: Archived historical Secure Enclave Custody POC material.
> Archived: 2026-05-25.
> Archive reason: Secure Enclave Custody POC closeout; future product, architecture, and security docs will be rewritten separately.
> Successor: None yet.
> Current-state note: Current code and active docs outrank this archived file; use it only as historical evidence and context.


Status: passed for production-proximate external signing feasibility on the
tested macOS machine. Phase 4 is still required before Apple Secure Enclave
custody can become product-selectable.

## Scope

Phase 3 tested whether Secure Enclave P-256 ECDSA private-key operations can be
used through Sequoia's external signer seam to produce OpenPGP signatures that
CypherAir's verification paths accept.

This POC did not test OpenPGP ECDH session-key recovery, decrypt behavior,
production custody metadata, UI, migration, recovery, or lifecycle UX.

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

The probe was built as an Xcode-signed macOS `.app` with app sandbox enabled,
automatic signing, generated Info.plist, and a POC-only Keychain access group.

The signed product used a bundle-id-specific macOS provisioning profile and
included these entitlement classes:

- `com.apple.security.app-sandbox`
- `keychain-access-groups`
- `com.apple.security.hardened-process`
- checked allocations, pure data, dyld read-only, hardened heap, and platform
  restriction enhanced-security keys
- Apple-injected application and team identifiers

`codesign -d --entitlements -` successfully showed the expected entitlements on
the built `.app`; `CSSMERR_TP_NOT_TRUSTED` appeared only inside the ordinary
Codex command sandbox, while `codesign --verify --strict --verbose=4` passed
outside that sandbox, so it is classified as a Codex keychain/trust visibility
artifact rather than a probe entitlement or app-sandbox failure.

## Secure Enclave Runtime Evidence

`bootstrap` completed successfully with:

- `secureEnclaveAvailable = true`
- two generated keys
- distinct signing and key-agreement public keys
- X9.63 public-key lengths of 65 bytes
- POC Keychain access group visible through the signed app entitlement

The probe created permanent Secure Enclave P-256 `SecKey` private-key rows via
the Security framework path and wrote only local capability state plus a public
fixture under a private app-container run directory. The run directory was mode
`0700`; state, fixture, request, and response files were mode `0600`.

`sign-digest` completed successfully for SHA-256. The signing operation reloaded
the signing key from Keychain and revalidated public-key equality, key type,
key size, Secure Enclave token, access group, role binding, and signing/agreement
distinctness before signing. The supported signature encoding was
`ecdsa-rfc4754-raw`, producing fixed-width 32-byte `r` and 32-byte `s` values.
The DER fallback path was not needed on this machine.

No raw key handles, private material, raw signatures, digests, certificates,
Keychain tags, stable fingerprints, or temp capability paths were printed in
the probe summaries.

## OpenPGP Evidence

Rust `mock-control` passed first, proving the Sequoia `Signer` seam, packet
construction, SHA-256 restriction, and CypherAir verification plumbing without
Secure Enclave hardware.

`secure-enclave-bindings` passed with the signed probe as the signing oracle:

| Candidate | User ID self-certification | ECDH subkey binding | Public cert validation | Selector discovery | Transport recipient selection |
| --- | --- | --- | --- | --- | --- |
| P-256 v4 | passed | passed | passed | passed | passed |
| P-256 v6 | passed | passed | passed | passed | passed |

Recorded public certificate byte lengths were 639 bytes for the v4 candidate and
547 bytes for the v6 candidate. The primary key algorithm was ECDSA P-256 and
the transport encryption subkey algorithm was ECDH P-256 with SHA-256/AES-256
preferences.

`message-shapes` passed with Secure Enclave-backed signing:

- Detached signature produced and verified.
- Cleartext signature produced and verified through CypherAir verification.
- Binary signed message produced and verified through Sequoia stream
  verification.

## Failure And Cleanup Evidence

Swift failure coverage passed for unsupported hash, wrong digest length, wrong
expected public key, missing Keychain row, signing/agreement tag substitution,
corrupted state, symlinked state, invalid state permissions, non-Secure Enclave
key material, and wrong key-size metadata.

Rust failure coverage passed for duplicate public keys, swapped public keys,
wrong role metadata, unsupported hash, wrong digest length, bridge failure
without fallback, corrupted signature response, and symlinked request files.

Per-signature bridge request/response files were removed after Rust signing
calls. Cleanup deleted two POC Keychain private-key rows and all runtime
capability files; the app-container run directory had no remaining entries.

## Conclusion

Phase 3 production-proximate signing feasibility is proven for the tested
environment:

- The custody boundary used an Xcode-signed sandboxed macOS app with a POC
  Keychain access group.
- Secure Enclave keys were created and persisted through `SecKeyCreateRandomKey`
  and permanent Keychain key rows.
- Sequoia owned OpenPGP packet construction, hashing, signature preimages, and
  verification.
- The signed probe performed only the P-256 ECDSA private-key operation and
  returned OpenPGP-compatible `r`/`s` signature material.

Apple Secure Enclave custody remains non-selectable for product use until
Phase 4 proves ECDH session-key recovery and decrypt hard-fail behavior.

> Status: Archived historical Secure Enclave Custody POC material.
> Archived: 2026-05-25.
> Archive reason: Secure Enclave Custody POC closeout; future product, architecture, and security docs will be rewritten separately.
> Successor: None yet.
> Current-state note: Current code and active docs outrank this archived file; use it only as historical evidence and context.

