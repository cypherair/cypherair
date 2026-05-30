# Round 2 Adversary: cluster-rust-crypto-inputs

Current HEAD inspected: `d075268f61154227b5ff8545bb53808cccfda66c`.

## CA-30: Predictable decrypt temp file enables plaintext and symlink attacks

### Challenge summary

The original predictable-path claim is materially stale in current HEAD. Rust no longer stages plaintext at fixed `<output>.tmp`; it uses `<output>.<64-bit-random-hex>.tmp`, and the shipped Swift file-decrypt path places output in an app-owned per-operation UUID directory. The remaining issue is a narrower Rust primitive hardening gap: `File::create` and `secure_delete_file` still follow symlinks if an attacker can control or race the temp path.

### Strongest evidence against real impact

- The CSV describes fixed `format!("{output_path}.tmp")`, but current Rust generates 8 random bytes and uses `"{output_path}.{hex_suffix}.tmp"` before `File::create`.
- Shipped Swift does not let the user choose the output directory. `DecryptionService` creates an `AppTemporaryArtifact` under `FileManager.temporaryDirectory/decrypted/op-<UUID>/...` and passes that private artifact path to Rust.
- The user-controlled input filename is reduced to a last path component before becoming the output basename.
- Tampered streaming decrypt tests assert no final output and no `.tmp` leftovers on auth/integrity failure.
- A practical symlink precreation attack now requires write/list access inside the app temp artifact area plus guessing or racing a fresh operation UUID and 64-bit random suffix. That is not a credible shipped app threat without a much stronger local compromise.

### Strongest evidence supporting real impact

- The UniFFI-exposed Rust primitive still accepts arbitrary `output_path`; only current Swift callers make it private.
- `File::create(&temp_path)` follows symlinks and truncates if the attacker somehow precreates the randomized temp path.
- `secure_delete_file` uses `fs::metadata` and `OpenOptions::open`, both symlink-following, so a replace-after-error race by an attacker with write access to the output directory could zero the symlink target before removing the link.
- Plaintext is necessarily written to the temp file before the final AEAD/MDC outcome is known; safety depends on private directory realism plus cleanup.

### Practical shipped scenario, if any

No credible normal shipped scenario found. A plausible scenario requires local malware or another same-user process that can write inside the app's private temporary artifact directory during a decrypt operation. On macOS, same-user local compromise may make that more plausible than on iOS, but it is still outside the ordinary attacker-controlled OpenPGP file model.

### Final recommendation

`real-low`

The original predictable-temp-path finding should not be treated as still present, but the symlink-following temp creation/deletion behavior is real enough to harden at the Rust primitive boundary.

### Confidence

Medium-high.

### Questions for main Codex/user discussion

- Should this be tracked as a narrowed follow-up: "use exclusive/no-follow temp creation and symlink-safe cleanup in `decrypt_file_detailed`" rather than the original predictable-path issue?
- Is same-user macOS access to the app container considered inside the threat model for plaintext temp files?
- Should Rust set restrictive file permissions/protection for temp plaintext independent of Swift's artifact-store protection?

## CA-34: Bad signatures no longer hard-fail verification

### Challenge summary

This is a false positive against the current product and FFI contract. CypherAir's hard-fail invariant applies to payload authentication failures that could expose unauthenticated plaintext after decrypt. Standalone signature verification is intentionally a graded-result API: parse/setup failures throw, while cryptographic signature invalidity returns `Bad`/`Invalid` status and the shipped UI presents that status.

### Strongest evidence against real impact

- `docs/TDD.md` explicitly says parse/setup failures return `Err(PgpError)`, while successful parsing followed by crypto failure should stay in result or graded-status types.
- `docs/ARCHITECTURE.md` labels `verify.rs` as cleartext verification helpers with graded results, and lists richer signature results as shipped through `SigningService`, `DecryptionService`, `VerifyScreenModel`, `DecryptScreenModel`, and `DetailedSignatureSectionView`.
- `docs/PRD.md` says "AEAD hard-fail" but "Sig failure communicated" and describes signing/verification as graded results.
- Shipped Verify UI stores the returned detailed verification and renders invalid signatures with a red invalid status and "Signature verification failed - content may have been modified."
- Current service/self-test callers that need validity explicitly check `legacyStatus == .valid`; I found no shipped caller that treats non-throwing verify as valid.
- Rust, Swift service, and FFI tests assert tampered cleartext/detached signatures return `Bad`, not throw.

### Strongest evidence supporting real impact

- The Rust and Swift APIs are still shaped as `Result` / `throws`, so a future caller could mistakenly equate "did not throw" with "valid signature."
- `verify_cleartext_detailed` can return the signed content along with `legacy_status == Bad`, so status inspection is mandatory.
- A stale comment in `pgp-mobile/src/decrypt.rs` still says standalone verify hard-fails, which could mislead future maintainers.

### Practical shipped scenario, if any

None found. The shipped Verify screen and self-test paths inspect and present/check status. Bad signatures do not bypass AEAD/MDC payload authentication, and decrypt payload auth failures still throw before returning plaintext.

### Final recommendation

`false-positive`

Optionally file a small documentation/API-ergonomics cleanup for the stale hard-fail comment and to make future status-ignoring harder, but do not treat graded bad signatures as a security invariant violation.

### Confidence

High.

### Questions for main Codex/user discussion

- Should the stale standalone-verify hard-fail comment in `decrypt.rs` be corrected as part of audit cleanup?
- Do maintainers want helper properties or naming that makes "must inspect verification status" harder to miss for future callers?

## CA-39: Unbounded SKESK S2K can exhaust memory

### Challenge summary

The mechanism is real in the Rust/FFI password-message service, but it is not reachable from the shipped UI. This should be treated like a latent service-layer availability issue, adjacent to the already documented CA-21 SKESK amplification finding, rather than a current end-user attack path.

### Strongest evidence against real impact

- Product and architecture docs state Password/SKESK workflows are service-only with no shipped route or screen-model owner.
- `AppRoute` has no password-message route; `rg` found `PasswordMessageService` instantiated in the service graph and used in tests, but not consumed by app UI.
- Impact is availability-only: expensive SKESK/S2K processing can hang/crash the app, but it does not weaken payload authentication or return unauthenticated plaintext.
- Password-message tamper tests still expect fatal integrity/auth errors for SEIPDv1/SEIPDv2 payload tampering.

### Strongest evidence supporting real impact

- `collect_message_context` pushes every SKESK before the encrypted container into an unbounded `Vec`.
- `decrypt` iterates every collected SKESK and calls `skesk.decrypt(password)` for each candidate without a count cap, memory preflight, or total KDF-work budget.
- Validation before KDF only checks packet version plus supported symmetric/AEAD algorithms; it does not bound S2K cost.
- `Argon2idMemoryGuard` explicitly applies only to passphrase-protected key import, not message SKESKs, and is only wired through key import.
- Existing tests intentionally preserve multi-SKESK fall-through behavior, confirming repeated candidate work is an intended current path.

### Practical shipped scenario, if any

No current shipped UI scenario found. A future password-message import/decrypt screen would make this immediately user-reachable: an attacker sends a password-encrypted OpenPGP message containing many SKESKs or high-cost Argon2id S2K parameters, and the victim attempts password decrypt.

### Final recommendation

`real-low`

Fix before exposing password-message workflows in product UI. A reasonable fix would bound SKESK count and reject or budget high-memory/high-work S2K parameters in Rust before `skesk.decrypt(password)`.

### Confidence

High.

### Questions for main Codex/user discussion

- What SKESK count and total KDF budget should CypherAir support for interoperability?
- Can Sequoia expose enough SKESK S2K metadata to reject excessive Argon2id cost before allocation?
- Should the existing Swift key-import memory guard be mirrored in Rust for message SKESKs, or should message S2K policy live entirely at the Rust boundary?
