---
name: security-review
description: Review code changes touching security-critical paths
disable-model-invocation: true
---

Review the current diff or specified files against Cypher Air's security invariants.

## Security Invariants Checklist

1. **Zero network access** — No HTTP, URLSession, NWConnection, no networked SDKs added.
2. **No plaintext in logs** — No `print()`, `os_log()`, or `NSLog()` of key material, passphrases, or decrypted content. Not even in DEBUG builds.
3. **Memory zeroing** — All sensitive `Data` buffers use `resetBytes(in:)`. Rust side uses `zeroize` crate. Verify no early returns bypass zeroization.
4. **AEAD hard-fail** — Authentication failure during decryption must abort immediately. No partial plaintext returned.
5. **SE wrapping scheme** — HKDF info string (`"CypherAir-SE-Wrap-v1:" + hexFingerprint`) unchanged. Access control flags match the documented modes.
6. **Permissions** — Only `NSFaceIDUsageDescription` in Info.plist. No other usage descriptions added.
7. **Secure random** — Only `SecRandomCopyBytes` / CryptoKit (Swift) or `getrandom` (Rust). No `arc4random`, no `Int.random`.
8. **Profile correctness** — v4 recipient → SEIPDv1. v6 recipient → SEIPDv2. Mixed → SEIPDv1.
9. **Phase 1/Phase 2 boundary** — DecryptionService Phase 2 auth check not bypassed.

## Review Process

1. Read the changed files (use `git diff` or specified file paths).
2. Check each change against every invariant above.
3. For files listed in SECURITY.md §7 "AI Coding Red Lines", flag that human review is required.
4. Report findings organized by priority:
   - **Critical** — Must fix before merge (invariant violation).
   - **Warning** — Should fix (potential risk, missing test).
   - **OK** — No issues found for this invariant.
