# #577 Triage: open findings from the 2026-06-14 whole-codebase review

Migrated from `docs/WHOLE_CODEBASE_REVIEW_2026-06-14.md` (report-only doc, being retired in the documentation refactor). Disposition is unassigned — this is a findings record to triage/fix/drop alongside the other open security items, not a fix plan. Crown-jewel invariants (AEAD hard-fail, profile/format auto-selection, SE-custody external-operation boundary) were re-confirmed sound; no findings there.

## The one real confidentiality defect

**WCR-01 — `encrypt()` targets a revoked encryption subkey when the primary key is still live · High**
- Where: `pgp-mobile/src/encrypt.rs` `collect_recipients` (~:65-72) and `build_recipients` (~:94-103); UI mirror `pgp-mobile/src/keys/key_info.rs` (~:22-34).
- What: recipient selection chains `.with_policy(policy, None).supported().alive().for_transport_encryption()` and **never calls `.revoked(false)`**. `.alive()` checks only expiry, not revocation; `collect_recipients` rejects only *primary-key* revocation. So a cert with a live primary but a hard-revoked (e.g. `KeyCompromised`) encryption subkey is accepted and a PKESK is built for the revoked subkey — and the contact shows as fully valid. All recipient entry points share these helpers (`encrypt`, `encrypt_binary`, `encrypt_with_external_p256_signer`, streaming `encrypt_file*`).
- Fix shape: add `.revoked(false)` to the recipient key-amalgamation chain; add a negative test (live primary + hard-revoked encryption subkey ⇒ rejected). Small and well-scoped. Existing recipient-policy tests cover only primary-key revocation.

Note: the composite/PQC families added since this review share the same recipient-selection helpers, so the fix covers them too.

## Low

| ID | Summary | Where |
|----|---------|-------|
| WCR-02 | Untrusted `cypherair://` import processed + confirmation sheet presented while the app is locked (presentation-layering + missing URL gate) | IncomingURLImportCoordinator / lock surface |
| WCR-03 | Derived wrapping-root-key `Data` left un-zeroed at domain-provisioning sites | ProtectedData domain provisioning |
| WCR-04 | Crash between modify-expiry pending-bundle save and journal write orphans a usable wrapped private-key copy (does not survive reset) | modify-expiry recovery |
| WCR-05 | Encrypt-to-Self picker selection never re-validated; stale/deleted self-key silently falls back to default | Encrypt screen / `encryptToSelfFingerprint` |
| WCR-06 | High Security confirmation offers a "proceed at your own risk" path the service unconditionally rejects (UI↔service contradiction) | AuthMode confirmation flow |
| WCR-07 | `ProtectedOrdinarySettingsCoordinator` is a lock/recovery/relock state machine living in `Sources/Models`, consumed directly by views | architecture debt |
| WCR-16…19 | Test-quality: brittle/low-value assertions with concrete removal recommendations | test suite |

## Informational

| ID | Summary |
|----|---------|
| WCR-09 | `refreshProtectedOrdinarySettings` can silently discard the explicit per-message "Encrypt to Self" toggle |
| WCR-10 | Contact-level "OpenPGP Certification: Certified" badge aggregates across all keys (trust overstatement; related to SR-FIX-05) |
| WCR-11 | `AppConfiguration` (Models) owns auth policy + private-key-control + session/recovery lifecycle (sharper than the retired architecture baseline) |
| WCR-12 | `DetailedSignatureVerification.summaryEntryIndex` threaded across FFI but never read by app code |
| WCR-13 | `PGPKeyOperationFailureCategory.prohibitedFallbackAttempted` orphan case with shipped localized strings |
| WCR-14 | `PGPKeyOperationResolution` carries ~80 lines of invariant-enforcing `Codable` that is never serialized |
| WCR-15, WCR-20…22 | Additional test-quality cleanup / removal candidates |

Full original text is in git history (`docs/WHOLE_CODEBASE_REVIEW_2026-06-14.md`, last at commit before the docs refactor).
