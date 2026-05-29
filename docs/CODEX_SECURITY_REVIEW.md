# Codex Security Review — Verified Follow-ups

> Purpose: Track Codex cloud security-review findings that, after manual verification
> against the current code, are **real and worth acting on**. Confirmed false positives
> / by-design items are closed directly in Codex and are not duplicated here.
> Source: Codex cloud security review (`chatgpt.com/codex/cloud/security`).
> Verified against: branch `main`, HEAD `40ea2fa`. Code is referenced by file + symbol
> name (not line number) so references stay valid as the tree moves.
> Convention: keep each entry short — impact in 1–2 lines, the current code locations,
> and the Codex link so the finding can be closed once fixed.

**Status:** `open` = verified, not yet fixed · `in-progress` · `fixed` (then close in Codex). Findings judged false-positive / by-design are closed directly in Codex and never recorded here — this file only holds items we intend to fix.

---

## [open] Selector discovery surfaces unauthenticated User IDs

- **Codex:** https://chatgpt.com/codex/cloud/security/findings/f6c9737226248191a651f043b8b6f146 — severity **low**
- **Verified real & reachable.** A crafted public certificate with a bare (un-self-signed)
  User ID survives import and appears in the contact certificate-signature UI looking
  identical to a validly-bound User ID. The app treats unauthenticated == normal at all
  three layers: data (no validity field), UI (only `Primary` / `Revoked` badges), and
  operation (`certify` succeeds with no binding check).
- **Impact (low, bounded):** A user can be socially engineered into producing / sharing a
  certification for an identity the key owner never bound. No in-app trust propagation
  (certifications are crypto-only); recipient selection is unaffected (keyed by key, not
  by these selectors). Real harm requires an external web-of-trust consumer.
- **Current code:**
  - `pgp-mobile/src/keys/selector_discovery.rs` — `discover_certificate_selectors` (enumerates every raw User ID packet)
  - `pgp-mobile/src/keys.rs` — `current_user_id_occurrence_state` (bare packet → `primary=false, revoked=false`), `find_user_id_by_selector` (validates occurrence index + bytes only, no binding), `struct DiscoveredUserId`
  - `Sources/Models/UserIdSelectionOption.swift` — no validity / authenticated field
  - `Sources/Services/CertificateSelectionCatalogMapper.swift` — forwards fields unchanged
  - `Sources/App/Contacts/ContactCertificateSignaturesView.swift` — User ID rows render only `Primary` / `Revoked` badges
- **Fix idea:** Add a `hasValidSelfBinding` (authenticated) flag to `DiscoveredUserId` →
  `UserIdSelectionOption` — the per-occurrence binding is already computed in Rust. Surface
  it in the UI ("not authenticated by this key") and/or gate `certify`. `DiscoveredUserId`
  is a `#[uniffi::Record]`, so this is a UniFFI-visible, multi-layer change (regenerate
  bindings + rebuild XCFramework + both-profile tests). While reworking this UI, also
  consider surfacing signer-key expiry/revocation status alongside User-ID binding
  validity — a related OpenPGP validity-display improvement on the same screen.
