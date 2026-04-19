# Compliance Remediation Plan

> Status: Active roadmap.
> Purpose: Record the current evidence, open legal-risk questions, migration workstreams, and downstream documentation impacts for CypherAir's licensing and distribution-compliance remediation work.
> Audience: Human developers, reviewers, release owners, and AI coding tools.
> This document is not a statement of current shipped compliance or a substitute for legal advice. Current code and active canonical docs describe shipped behavior unless explicitly superseded.
> Companion documents: [README.md](../README.md) · [CLAUDE.md](../CLAUDE.md) · [AGENTS.md](../AGENTS.md) · [TDD.md](TDD.md) · [TESTING.md](TESTING.md) · [XCFRAMEWORK_RELEASES.md](XCFRAMEWORK_RELEASES.md) · [DOCUMENTATION_GOVERNANCE.md](DOCUMENTATION_GOVERNANCE.md)

## 1. Role And Scope

This document is CypherAir's active migration and remediation plan for licensing and distribution-compliance questions.

Use this document to:

- record the evidence currently supported by the repository and release configuration
- separate confirmed facts from legal-risk hypotheses and open questions
- define the migration workstreams and decision points that must be resolved before licensing changes are implemented
- track which canonical docs, product metadata, and release surfaces must be updated together once a licensing decision is made

Do not use this document as a description of already-resolved compliance outcomes.

## 2. Current Evidence-Backed State

The following points are supported by the current repository state:

- The App already includes an in-product license and notices experience via the Settings flow.
- The bundled notices payload includes full license texts and highlights core direct dependencies in the current UI grouping.
- `sequoia-openpgp` currently appears unmodified in-repo. The checked-in Rust manifest shows no local patch override for `sequoia-openpgp`; the current `[patch.crates-io]` override is limited to `openssl-src`.
- The current Rust integration uses `staticlib` packaging into `PgpMobile.xcframework`.
- The project also distributes `PgpMobile.xcframework` as a standalone binary release artifact through the documented XCFramework release channel.
- Current first-party repo and product-license messaging still says `GPLv3`.
- This plan assumes Apple standard EULA coverage is in effect for the App Store build unless and until a custom EULA is adopted.

This document treats those points as the current planning baseline.

## 3. Primary Compliance Questions

The current migration work is centered on three questions:

1. Whether first-party `GPLv3` distribution through the App Store remains tenable when the App is distributed under Apple's standard EULA and related App Store distribution terms.
2. What materials, notices, and release mechanics are required to satisfy `LGPL-2.0-or-later` obligations for `sequoia-openpgp` and `buffered-reader` in the current static-link distribution model.
3. Whether the current `MPL-2.0` source-availability posture for the UniFFI-related components is sufficient as-is or requires tighter, version-pinned documentation.

These questions are active planning topics. They are not resolved by this document.

## 4. Risk Ranking

Current working risk ranking:

- High: first-party `GPLv3` plus App Store distribution under the standard EULA and Apple distribution terms
- High: `LGPL-2.0-or-later` Section 6 fulfillment for Sequoia-linked binaries distributed through both the App and the standalone XCFramework channel
- Medium: active docs that overstate legal conclusions, especially unqualified compatibility claims for the current Sequoia / `GPLv3` / App Store posture
- Lower: permissive-license notice completeness, because the repository already ships a substantial bundled notice system and in-product notices UI

This ranking is intentionally conservative and should be revisited after a written first-party license decision and a written Sequoia-fulfillment approach exist.

## 5. Migration Options To Study

The active options to study are:

- a first-party relicensing path for CypherAir
- continuing to use Sequoia while documenting and shipping a concrete `LGPL-2.0-or-later` fulfillment package for each distribution channel
- continuing to use Sequoia under a different commercial or negotiated arrangement if that becomes desirable later
- replacing Sequoia only as a fallback option, not as the assumed default path

This document does not select one of these options yet. Its job is to keep the decision surface explicit and connected to the repo's real distribution model.

## 6. Required Outputs Before Any Implementation Change

Before any product-license migration or distribution-policy implementation change is treated as approved, this work must produce:

- a written first-party license decision for CypherAir
- a written Sequoia / `LGPL-2.0-or-later` fulfillment approach for both App distribution and standalone XCFramework distribution
- a concrete list of canonical docs, product metadata, and release surfaces that must be updated together once a decision is made
- a release-time checklist that identifies which artifacts and notices are required for each shipping channel

Until those outputs exist, this document should remain a planning artifact rather than implementation guidance.

## 7. Exit Criteria

This remediation plan can be considered complete only when all of the following are true:

- no active canonical doc makes an unqualified legal-compatibility claim that this plan is actively questioning
- the first-party license and distribution model are explicitly chosen
- the Sequoia fulfillment path is documented for each shipping channel that distributes Sequoia-linked binaries
- a release and documentation update checklist is defined for the chosen path

## 8. Downstream Docs And Metadata To Update Later

Once a licensing decision is made, the following surfaces are expected to require synchronized updates:

- root entry docs such as `README.md`, `CLAUDE.md`, and `AGENTS.md`
- canonical technical docs including `TDD.md`, and any other active doc that describes licensing-sensitive build or distribution posture
- product-facing metadata and release notes that describe the App's license or the XCFramework release channel
- any compliance-facing links or explanatory text that need to accompany binary releases

This section is intentionally directional rather than exhaustive. The final implementation checklist should name the exact files and release surfaces for the chosen migration path.
