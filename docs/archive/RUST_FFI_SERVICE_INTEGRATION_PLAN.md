# Rust / FFI Service Integration Plan

> Status: Archived snapshot from 2026-04-20.
> Archival reason: The remaining rollout queue collapsed into canonical shipped/deferred documentation.
> Purpose: Preserve the final standalone downstream-rollout snapshot from the Rust/FFI rollout.
> Audience: Human developers, reviewers, and AI coding tools.
> Successor docs: [ARCHITECTURE](../ARCHITECTURE.md) · [PRD](../PRD.md) · [TESTING](../TESTING.md) · [TDD](../TDD.md) · [SECURITY](../SECURITY.md)
> Historical note: Current code and active canonical docs outrank this historical file.

## 1. Role And Scope

Use the baseline document for current state.

Use this document for:

- the conclusion of the current service-layer rollout
- the remaining downstream adoption queue after that rollout
- validation and review posture for any follow-on work that still touches these families

Do not use this document as a to-do list for selector discovery, `CertificateSignatureService`, selective revocation, or detailed-result service APIs. Those items are already landed in the current repository.

## 2. Service-Layer Rollout Conclusion

The tracked service-layer rollout is complete for the currently scoped families:

1. selector discovery and selector-bearing Swift metadata are landed
2. `CertificateSignatureService` is landed
3. selective revocation is landed through the `KeyManagementService` facade
4. detailed-result service APIs are landed in both `SigningService` and `DecryptionService`

There is no remaining service-boundary rollout item in this document's tracked family set.

## 3. Remaining Downstream Queue

There is no active downstream adoption item left in this document's tracked family set.

### 3.1 Password-Message App Ownership

`PasswordMessageService` remains intentionally out of scope for this document's active downstream queue.

- The service-layer capability remains supported.
- Any future app exposure requires a separate product-scoped decision about plaintext handling, export UX, and route ownership.

## 4. Validation And Review Posture

- Any new Rust / UniFFI public-surface change still requires regeneration and cross-layer validation under [TESTING.md](../TESTING.md) and [CODE_REVIEW.md](../CODE_REVIEW.md).
- Any future `DecryptionService` change remains security-sensitive and requires human review under [SECURITY.md](../SECURITY.md).
- Any future app adoption work for `CertificateSignatureService` should update this document only if it changes the remaining downstream queue. Routine UI implementation detail belongs in the app-surface plan instead.

## 5. Update Triggers

Update this document when one of the following becomes true:

- a new tracked Rust / FFI family requires real downstream adoption planning again
- `PasswordMessageService` app exposure becomes approved product scope

Until one of those triggers fires, this document should stay short and should not be expanded back into a historical rollout log.
