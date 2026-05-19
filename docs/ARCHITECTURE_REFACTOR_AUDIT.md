# Architecture Refactor Current-State Audit

> Status: Audit snapshot.
> Date: 2026-05-14.
> PR2A update: 2026-05-15 refreshed generated-enum, signature, and selector
> evidence after Phase 2 PR2A; Models now use app-owned profile,
> certification-kind, message-signature, detailed-signature, and selector
> vocabulary while generated enum conversion stays in the FFI adapter boundary.
> PR2B update: 2026-05-15 refreshed generated-error evidence after Phase 2
> PR2B validation.
> PR2C update: 2026-05-15 refreshed presentation-boundary evidence after
> Phase 2 PR2C; Models no longer import SwiftUI or own localized presentation
> text in current production code.
> PR2D update: 2026-05-15 refreshed Security vocabulary evidence after
> Phase 2 PR2D; Models no longer reference ProtectedData / Security
> implementation vocabulary in current production code.
> PR3B update: 2026-05-18 moved Contact Detail workflow state and mutations
> behind `ContactDetailScreenModel`; the route now renders current Contacts
> summaries and routes delete, merge, tag, verification, and key-usage actions
> through ScreenModel-owned actions.
> Phase 3 close-out update: PR3A through PR3D are accepted as complete for the
> Contacts runtime consolidation scope. Production `Sources/` have zero flat
> `[Contact]` exceptions and no legacy flat Contacts projection types.
> PR4A update: 2026-05-19 moved key generation, private-key import, backup
> export, and expiry modification workflow state behind key-route ScreenModels.
> Existing Key Detail and Selective Revocation ScreenModels are accepted as
> Phase 4 PR4A coverage, with additional stale-export suppression and
> source-audit guardrails for key-route view orchestration.
> PR4B update: 2026-05-19 moved QR display generation/rendering behind
> `QRDisplayScreenModel`, tightened Add Contact QR-photo loader ownership inside
> `AddContactScreenModel`, accepted existing Contact Detail, Contacts list, tag,
> import-confirmation, and incoming-URL coordinators for the Contacts route
> scope, and added source-audit guardrails for Contacts route view orchestration.
> Scope: First-party Swift app code under `Sources/`. Generated UniFFI Swift
> bindings in `Sources/PgpMobile/pgp_mobile.swift` are used only as evidence for
> generated type origins, not classified as hand-maintained architecture debt.
> Purpose: Record current architecture boundary problems that affect
> maintainability, using the architecture refactor goals as audit dimensions
> while grounding findings in current code.
> Audience: CypherAir maintainers, reviewers, and coding agents preparing future
> architecture refactor work.
> Truth sources: Current repository files, targeted `rg` reference checks,
> `docs/ARCHITECTURE_REFACTOR_GOALS.md`,
> `docs/ARCHITECTURE_REFACTOR_TARGET.md`, `docs/ARCHITECTURE.md`,
> `docs/SECURITY.md`, `docs/CONVENTIONS.md`,
> `docs/PERSISTED_STATE_INVENTORY.md`, and
> `docs/DOCUMENTATION_GOVERNANCE.md`.

This document is a point-in-time audit. It is not a target architecture, an
implementation plan, a phase plan, or a canonical current-state replacement for
`ARCHITECTURE.md` or `SECURITY.md`. Current code and canonical current-state
documentation outrank this snapshot whenever they drift.

## Summary

CypherAir has already moved several important workflows toward clearer
ownership, especially newer ScreenModel-backed encrypt/decrypt/sign/verify
screens, the FFI adapter boundary, app-owned Models, and the protected Contacts
domain. The current codebase still has material architecture debt around layer
boundaries, Contacts runtime shape, and security workflow placement.

The most persistent problem is not one isolated file. It is that generated
UniFFI interaction still requires a well-maintained adapter boundary, Contacts
protected-domain coordination remains concentrated in the facade, and several
App and ScreenModel flows still coordinate Security implementation details
directly. That makes code harder to reason about because changes to Rust
bindings, Contacts storage, or security authorization rules can ripple into
ScreenModels, UI, services, and tests.

Representative search snapshot:

- `PgpEngine` appears in app composition, tutorial sandbox composition, and
  `Sources/Services/FFI` adapter files; normal production Services use
  operation adapters rather than storing the generated engine directly.
- Phase 2 PR2A validation found generated profile, certification, signature,
  and selector vocabulary replaced by app-owned values in Models, Services,
  ScreenModels, and UI-facing summaries. Generated conversions now live in
  `Sources/Services/FFI`, with historical raw values preserved for persisted
  compatibility.
- Phase 2 PR2B validation found generated `PgpError` mapping contained in
  `Sources/Services/FFI/PGPErrorMapper.swift` and FFI adapter files, with
  `CypherAirError` remaining the app-owned error vocabulary in Models.
- Phase 2 PR2C validation found SwiftUI color/icon/status presentation and
  localized display text moved out of `Sources/Models` into App-layer
  presentation helpers, with source-audit coverage blocking regression.
- Phase 2 PR2D validation found ProtectedData and Security implementation
  vocabulary moved out of `Sources/Models`; Contacts validation now uses an
  app-owned validation error that the ProtectedData storage boundary maps back
  to `ProtectedDataError.invalidEnvelope(...)`, and Contacts post-auth decisions
  store app-level availability rather than ProtectedData outcome/state values.
- Phase 3 PR3A moved primary Contacts import, verification, certificate-signature,
  tutorial, and URL-import call sites to person-centered summaries,
  `ContactKeyRecord`, and `ContactsVerificationContext` contracts.
- Phase 3 PR3B moved Contact Detail route workflow state and contact mutations
  to `ContactDetailScreenModel`, closing the direct view-level mutation gap for
  contact delete, merge, tags, manual verification, preferred key, and key usage.
- Phase 3 PR3C removed the flat `[Contact]` runtime projection from
  `ContactService` and `ContactImportMatcher`.
- Phase 3 PR3D cut off legacy flat Contacts support entirely. Production no
  longer defines or reads flat `Contact`, `ContactRepository`,
  `ContactsLegacyMigrationSource`, or `ContactsCompatibilityMapper`; first
  protected `contacts` domain creation starts empty.
- Phase 3 close-out validation accepted PR3A through PR3D as complete for the
  Contacts runtime scope. Remaining Contacts service coupling stays recorded as
  future architecture debt rather than a Phase 3 exit blocker.
- Phase 4 PR4A moved remaining workflow-heavy key-management routes behind
  `KeyGenerationScreenModel`, `ImportKeyScreenModel`,
  `BackupKeyScreenModel`, and `ModifyExpiryScreenModel`. `KeyDetailScreenModel`
  and `SelectiveRevocationScreenModel` now cover key detail, revocation export,
  and selective-revocation lifecycle behavior for the PR4A key-route scope.
- Phase 4 PR4B moved QR display generation/rendering behind
  `QRDisplayScreenModel`, tightened Add Contact QR-photo import handling inside
  `AddContactScreenModel`, and accepted existing Contacts route ScreenModels and
  narrow import coordinators for Contact Detail, Contacts, tag, import
  confirmation, and incoming URL import behavior.
- Several UI routes and ScreenModels still call concrete services or security
  workflows directly, while other routes already use more focused ScreenModels.

## Classification

| Classification | Meaning | Current treatment |
| --- | --- | --- |
| Boundary Violation | A layer depends on details that should be contained behind another boundary. | Record as architecture debt even when behavior is currently correct. |
| Mixed Responsibility | A type owns multiple concerns such as domain data, presentation, persistence validation, and error mapping. | Record as maintainability risk, not necessarily a functional bug. |
| Runtime Compatibility Debt | Legacy compatibility projection or migration logic remains in ordinary runtime paths. | Record where compatibility behavior is active outside a narrow migration boundary. |
| Security-Sensitive Coupling | App or ScreenModel code coordinates Security or ProtectedData internals directly. | Record separately because future edits cross sensitive review boundaries. |
| Acceptable Composition Exception | Concrete dependency construction is expected, but policy ownership may still be too broad. | Do not classify construction alone as a problem. |

## Inventory

| Area | Representative evidence | Current problem | Risk |
| --- | --- | --- | --- |
| Generated enum and selector vocabulary is app-owned above the FFI boundary | Phase 2 PR2A source inspection found persisted and UI-facing key profile values use `PGPKeyProfile` in [Sources/Models/PGPKeyProfile.swift](../Sources/Models/PGPKeyProfile.swift), `PGPKeyIdentity`, `PGPKeyMetadata`, `ContactKeyRecord`, and `ContactKeySummary`. Certificate artifacts and contact-certificate ScreenModels use `OpenPGPCertificationKind` from [Sources/Models/OpenPGPCertificationKind.swift](../Sources/Models/OpenPGPCertificationKind.swift). User ID selection state uses app-owned `UserIdSelectionOption` in [Sources/Models/UserIdSelectionOption.swift](../Sources/Models/UserIdSelectionOption.swift), while generated `UserIdSelectorInput` construction lives in [Sources/Services/FFI/PGPCertificateSelectionAdapter.swift](../Sources/Services/FFI/PGPCertificateSelectionAdapter.swift). | The former generated-enum vocabulary leak is resolved for current production code. Historical raw values such as `universal`, `advanced`, and certification-kind names are intentionally retained by app-owned Codable enums as a schema compatibility contract. | Low residual risk, guarded by generated-FFI source-audit coverage and model tests for historical raw-value compatibility. |
| Generated FFI error mapping is contained at the FFI boundary | Phase 2 PR2B source inspection found `CypherAirError.from(_:)` in [Sources/Models/CypherAirError.swift](../Sources/Models/CypherAirError.swift) only preserves existing `CypherAirError` values and applies app-owned fallbacks. Generated `PgpError` normalization lives in [Sources/Services/FFI/PGPErrorMapper.swift](../Sources/Services/FFI/PGPErrorMapper.swift). | The former Models-layer generated-error mapping debt is resolved for current production code. The active concern is regression prevention: non-FFI layers should not reintroduce `PgpError` or `PGPErrorMapper` use. | Low residual risk, guarded by source-audit tests for generated error mapper containment and App-layer `PgpError` handling. |
| Generated signature result mapping is contained at the FFI boundary | Phase 2 PR2A source inspection found `SignatureVerification` stores app-owned `MessageSignatureStatus` in [Sources/Models/SignatureVerification.swift](../Sources/Models/SignatureVerification.swift), and `DetailedSignatureVerification` stores app-owned `DetailedSignatureVerification.Entry.Status` plus app-owned verification state in [Sources/Models/DetailedSignatureVerification.swift](../Sources/Models/DetailedSignatureVerification.swift). Generated `SignatureStatus`, `SignatureVerificationState`, `DetailedSignatureEntry`, and `DetailedSignatureStatus` mapping lives in [Sources/Services/FFI/PGPMessageResultMapper.swift](../Sources/Services/FFI/PGPMessageResultMapper.swift). | The former generated signature model-state debt is resolved for current production code. The active concern is regression prevention because signature state remains trust-facing. | Low to Medium residual risk, guarded by generated-FFI source-audit coverage and existing detailed signature tests. |
| FFI adapter boundary exists for normal production services | `AppContainer` and `TutorialSandboxContainer` still construct `PgpEngine`, which is an acceptable composition-root exception. Normal production Services store operation adapters such as `PGPMessageOperationAdapter`, `PGPKeyOperationAdapter`, `PGPCertificateOperationAdapter`, `PGPContactImportAdapter`, and `PGPSelfTestOperationAdapter`, while direct generated calls and generated result mapping live under [Sources/Services/FFI](../Sources/Services/FFI). | The former direct-engine ownership in primary Services is resolved for current production code. Residual risk is regression prevention and the need to keep new OpenPGP work inside adapter files instead of spreading generated calls back into services or App code. | Low to Medium residual risk, guarded by source-audit tests for generated UniFFI type containment and App-layer adapter usage. |
| Generated cancellation policy is normalized before reaching App code | [Sources/Services/FFI/PGPErrorMapper.swift](../Sources/Services/FFI/PGPErrorMapper.swift) maps generated `.OperationCancelled` to `CypherAirError.operationCancelled`. Current App and ScreenModel cancellation checks inspect only that app-owned case, for example [Sources/App/Common/OperationController.swift](../Sources/App/Common/OperationController.swift), [Sources/App/Keys/ImportKeyView.swift](../Sources/App/Keys/ImportKeyView.swift), and contact/key ScreenModels. | Direct generated `PgpError` interpretation no longer appears in production App or Models. FFI adapter files still own generated-error interpretation, while Services and App code consume `CypherAirError` or feature-specific app-owned errors. | Low to Medium. Future FFI calls must continue to normalize generated cancellation at the adapter boundary before App or ScreenModel code handles it. |
| Models SwiftUI presentation policy is extracted | Phase 2 PR2C source inspection found no `import SwiftUI` in `Sources/Models`. `ColorTheme` now stays a persisted enum in [Sources/Models/ColorTheme.swift](../Sources/Models/ColorTheme.swift), while display names, tint colors, action colors, and swatches live in [Sources/App/Common/ColorTheme+Presentation.swift](../Sources/App/Common/ColorTheme+Presentation.swift). `SignatureVerification` keeps app-owned verification state in [Sources/Models/SignatureVerification.swift](../Sources/Models/SignatureVerification.swift), while SF Symbols, status colors, and localized status text live in [Sources/App/Common/SignatureVerification+Presentation.swift](../Sources/App/Common/SignatureVerification+Presentation.swift). | The former SwiftUI import and color/icon policy debt is resolved for current production code. The active concern is regression prevention: core Models should not regain SwiftUI presentation dependencies. | Low residual risk, guarded by source-audit tests for SwiftUI imports in Models. |
| Models localized display text is extracted | Phase 2 PR2C source inspection found no `String(localized:)` or `String.localizedStringWithFormat` in `Sources/Models`. Profile labels, Contacts availability text, contact key-count text, grace-period picker labels, signature identity text, and `CypherAirError` localized descriptions moved to App-layer presentation helpers. `AppConfiguration` keeps only numeric grace-period values, and `IdentityPresentation.displayName(from:)` now uses a stable nonlocalized domain fallback for compatibility. | The former Models-layer localized presentation debt is resolved for current production code. The remaining concern is keeping future display text in App presentation helpers or ScreenModel-prepared display state. | Low residual risk, guarded by source-audit tests for localized presentation calls in Models. |
| Models Security vocabulary is extracted | Phase 2 PR2D source inspection found no production `Sources/Models` references to `ProtectedDataError`, `ProtectedDataPostUnlockOutcome`, `ProtectedDataFrameworkState`, `ProtectedSettingsStore`, `ProtectedSettingsDomainState`, `LAContext`, Keychain, Secure Enclave, or `AuthenticationManager` code symbols. Contacts validation uses [Sources/Models/Contacts/ContactsDomainValidationError.swift](../Sources/Models/Contacts/ContactsDomainValidationError.swift), while ProtectedData storage files map that app-owned error back to protected-domain envelope failures. Contacts post-auth gate decisions live in [Sources/Services/ContactsPostAuthGateDecision.swift](../Sources/Services/ContactsPostAuthGateDecision.swift), and the protected-settings ordinary-settings adapter lives in [Sources/Security/ProtectedData/ProtectedSettingsOrdinarySettingsPersistence.swift](../Sources/Security/ProtectedData/ProtectedSettingsOrdinarySettingsPersistence.swift). | The former Models-layer ProtectedData/Security vocabulary debt is resolved for current production code. The active concern is regression prevention: app-owned Models should keep expressing validation and availability without storing Security implementation state. | Low residual risk, guarded by source-audit tests for ProtectedData and Security implementation vocabulary in Models. |
| Legacy `Contact` projection is removed | `ContactService` no longer stores `contacts: [Contact]` or rebuilds runtime state from legacy/quarantine files. `ContactImportMatcher` no longer performs legacy flat key-replacement checks. PR3D deleted `Contact`, `ContactRepository`, `ContactsLegacyMigrationSource`, and `ContactsCompatibilityMapper`. | Phase 3 PR3D removed the ordinary runtime projection and the retained old-install migration path from active `Documents/contacts`. First protected-domain creation now uses `ContactsDomainSnapshot.empty()`. | Low to Medium. The current risk is regression prevention and protected-domain recovery behavior, guarded by source-audit coverage. |
| ContactService owns too many Contacts responsibilities | `ContactService` opens the protected domain after post-auth, performs imports/updates/removals, exposes summaries and verification contexts, manages search/tag/certification behavior, performs protected snapshot rollback/persistence, and owns relock cleanup. | The facade no longer owns legacy runtime fallback, flat projection state, or legacy migration cleanup, but it still coordinates availability, mutation, search/tag summaries, certification artifacts, and persistence coordination. | High. The file remains a high-coupling center where current product behavior and protected persistence coordination are hard to separate, even after the major runtime-projection cleanup. |
| UI / ScreenModel adoption is uneven | Newer flows use ScreenModels, for example `DecryptView` constructs `DecryptScreenModel` in [Sources/App/Decrypt/DecryptView.swift](../Sources/App/Decrypt/DecryptView.swift), Phase 3 PR3B moved Contact Detail mutations into [Sources/App/Contacts/ContactDetailScreenModel.swift](../Sources/App/Contacts/ContactDetailScreenModel.swift), Phase 4 PR4A moved key generation, import, backup, expiry modification, key detail, and selective revocation behind key-route ScreenModels, and Phase 4 PR4B moved QR display/generation behind [Sources/App/Contacts/QRDisplayScreenModel.swift](../Sources/App/Contacts/QRDisplayScreenModel.swift) while tightening Add Contact QR-photo processing in [Sources/App/Contacts/AddContactScreenModel.swift](../Sources/App/Contacts/AddContactScreenModel.swift). | The PR4A key-management route scope and PR4B Contacts/QR route scope are resolved for normal production views. Settings-adjacent routes still keep security-facing orchestration for later Phase 4/5 work. | Medium. Behavior remains localized, but remaining settings-adjacent orchestration makes future workflow changes harder to test consistently. |
| ScreenModels expose concrete service and workflow infrastructure | `DecryptScreenModel` action types expose `DecryptionService.Phase1Result`, `FileProgressReporter`, and `AppTemporaryArtifact` in [Sources/App/Decrypt/DecryptScreenModel.swift:6](../Sources/App/Decrypt/DecryptScreenModel.swift#L6). Contact certificate ScreenModels now expose app-owned `OpenPGPCertificationKind` and `CertificateSignatureVerification` state in [Sources/App/Contacts/ContactCertificateSignaturesScreenModel.swift](../Sources/App/Contacts/ContactCertificateSignaturesScreenModel.swift) and [Sources/App/Contacts/ContactCertificationDetailsScreenModel.swift](../Sources/App/Contacts/ContactCertificationDetailsScreenModel.swift). | ScreenModels improve UI separation, but some public state and action signatures still carry service internals and file/progress infrastructure that Phase 4 can narrow. The former generated certification enum exposure is resolved. | Medium. Tests and views remain coupled to implementation details that could otherwise be hidden behind app-owned request/result models. |
| Services are injected as observable UI environment dependencies | Primary services such as `EncryptionService`, `DecryptionService`, `SigningService`, `KeyManagementService`, `ContactService`, `QRService`, and `SelfTestService` are marked `@Observable`. Views read services from environment, for example [Sources/App/Encrypt/EncryptView.swift:106](../Sources/App/Encrypt/EncryptView.swift#L106), [Sources/App/Contacts/AddContactView.swift:38](../Sources/App/Contacts/AddContactView.swift#L38), and [Sources/App/Settings/SelfTestView.swift:6](../Sources/App/Settings/SelfTestView.swift#L6). | Services act as both business workflow owners and observable UI dependencies. This keeps direct service access natural even on screens that would benefit from ScreenModel-only interaction. | Medium. It blurs service and presentation state ownership and makes it harder to enforce view-thinness consistently. |
| Security workflows surface into Settings ScreenModel | `SettingsScreenModel` stores `AuthenticationManager` and `KeyManagementService` directly in [Sources/App/Settings/SettingsScreenModel.swift:16](../Sources/App/Settings/SettingsScreenModel.swift#L16). It calls `authManager.switchMode(...)` through its default action in [Sources/App/Settings/SettingsScreenModel.swift:66](../Sources/App/Settings/SettingsScreenModel.swift#L66) and creates/uses `LAContext` for local reset authorization in [Sources/App/Settings/SettingsScreenModel.swift:367](../Sources/App/Settings/SettingsScreenModel.swift#L367). | App-facing settings state coordinates authentication mode and local reset authorization directly rather than routing through a narrower service-level workflow. | High. Authentication mode and reset are sensitive boundaries; app-layer orchestration increases review surface. |
| Reset-all workflow lives in App/Settings but owns Security and ProtectedData details | `LocalDataResetService` is under `Sources/App/Settings/` but stores `KeychainManageable`, `ProtectedDataStorageRoot`, `AuthenticationManager`, `ProtectedDataSessionCoordinator`, `AppSessionOrchestrator`, `KeyManagementService`, and `ContactService` in [Sources/App/Settings/LocalDataResetService.swift:21](../Sources/App/Settings/LocalDataResetService.swift#L21). | Local reset is a product workflow, but the implementation directly enumerates and deletes low-level Keychain, ProtectedData, Contacts, defaults, and temporary-artifact surfaces from the App layer. | High. It is intentionally powerful and security-sensitive, but placement makes App code a direct owner of storage/security internals. |
| Protected settings access coordinator owns ProtectedData authorization details | `ProtectedSettingsAccessCoordinator.Dependencies` includes authorization handoff checks, root-key access, domain opening, mutation recovery, and reset closures in [Sources/App/Settings/ProtectedSettingsAccessCoordinator.swift:20](../Sources/App/Settings/ProtectedSettingsAccessCoordinator.swift#L20). It stores and invalidates `LAContext` in [Sources/App/Settings/ProtectedSettingsAccessCoordinator.swift:47](../Sources/App/Settings/ProtectedSettingsAccessCoordinator.swift#L47). | The coordinator is a useful App-facing bridge, but it still models ProtectedData authorization and mutation recovery mechanics in the App layer. | Medium to High. Future ProtectedData policy changes will likely require App-layer changes. |
| AppContainer does more than wiring in post-auth flow | `AppContainer` constructs concrete dependencies, which is expected. Its post-authentication handler also bootstraps first domain state, opens registered ProtectedData domains, opens Contacts, appends migration warnings, loads ordinary settings, updates private-key control state, and invokes recovery checks in [Sources/App/AppContainer.swift:490](../Sources/App/AppContainer.swift#L490). | App composition is the correct place to assemble dependencies, but this closure owns significant sequencing and policy around ProtectedData, Contacts, settings, and private-key recovery. | Medium. Startup and post-unlock behavior is difficult to reason about because policy is embedded in composition code. |
| Tutorial container repeats concrete service/engine wiring | `TutorialSandboxContainer` constructs its own `PgpEngine`, security mocks, `KeyManagementService`, `ContactService`, and PGP services in [Sources/App/Onboarding/TutorialSandboxContainer.swift:48](../Sources/App/Onboarding/TutorialSandboxContainer.swift#L48) and [Sources/App/Onboarding/TutorialSandboxContainer.swift:91](../Sources/App/Onboarding/TutorialSandboxContainer.swift#L91). | The tutorial sandbox legitimately needs isolated composition, but it duplicates knowledge of concrete service construction and direct engine injection. | Low to Medium. It can drift from production wiring unless shared composition boundaries become clearer. |

## Non-Findings And Boundaries

- This audit does not identify a direct UI call to `PgpEngine` in ordinary route
  views. Current generated FFI interaction is contained in composition roots and
  `Sources/Services/FFI`; the active concern is preserving that boundary as new
  OpenPGP work lands.
- `AppContainer` and `TutorialSandboxContainer` are allowed to know concrete
  implementation types as composition roots. The concern is policy breadth and
  duplicated construction knowledge, not the existence of composition code.
- The protected Contacts domain exists and is documented as implemented in
  current-state docs. The remaining audit finding is high coupling in
  protected-domain coordination, not a flat `Contact` runtime projection.
- This audit did not attempt to re-validate cryptographic correctness, AEAD
  hard-fail behavior, zero network access, or release packaging. Those remain
  governed by `SECURITY.md`, `TESTING.md`, and existing tests.

## Validation Notes

The audit was prepared from targeted source inspection and searches focused on:

- generated UniFFI symbols above the service boundary
- generated error/cancellation containment and `PGPErrorMapper` call sites
- direct `PgpEngine` ownership
- SwiftUI and localized presentation policy inside `Sources/Models`
- ProtectedData and Security implementation vocabulary inside `Sources/Models`
- `Contact` / `[Contact]` runtime references and legacy flat Contacts projection types
- direct service calls from views
- Security and ProtectedData types inside App and ScreenModel code

The 2026-05-15 PR2A refresh checked that generated profile, certification,
message-signature, detailed-signature, and User ID selector vocabulary no longer
appears in production Models, ScreenModels, Services, or UI-facing summaries
except inside `Sources/Services/FFI` adapter/mapping files or composition-root
exceptions. It also checked that app-owned Codable enums preserve historical raw
values for schema compatibility. The 2026-05-15 PR2B refresh checked that
production `Sources/App` and `Sources/Models` no longer reference `PgpError`,
and that `PGPErrorMapper` production use is limited to `Sources/Services/FFI`.
The 2026-05-15 PR2C refresh also checked that `Sources/Models` no longer import
SwiftUI or call `String(localized:)` / `String.localizedStringWithFormat`. The
2026-05-15 PR2D refresh checked that `Sources/Models` no longer reference
ProtectedData or Security implementation vocabulary in production code.
The 2026-05-18 PR3A refresh checked that source-audit `[Contact]` exceptions
are limited to `ContactService`, `ContactsCompatibilityMapper`,
`ContactsLegacyMigrationSource`, and `ContactImportMatcher`; signature models and
FFI verification contexts now use `ContactKeyRecord`/summary contracts instead of
flat contact arrays.
The 2026-05-18 PR3B refresh checked that Contact Detail renders
`ContactIdentitySummary` / `ContactKeySummary` state and routes its contact
mutations through `ContactDetailScreenModel`.
The 2026-05-18 PR3C refresh checked that production `[Contact]` exceptions are
limited to explicit migration files, and that production sources contain no
legacy Contacts runtime vocabulary for legacy availability, compatibility open,
or key-replacement import outcomes.
The 2026-05-18 PR3D refresh checked that production `Sources/` have zero
`[Contact]` exceptions and no `ContactRepository`,
`ContactsLegacyMigrationSource`, `ContactsCompatibilityMapper`, or production
`struct Contact` reintroductions.
The Phase 3 close-out pass accepted PR3A through PR3D as complete after
rechecking source-audit guardrails and targeted Contacts tests for empty
protected-domain creation, schema migration, protected recovery, candidate
import, merge and historical signer behavior, recipient search, Contact Detail
ScreenModel mutations, relock cleanup, URL import, and Encrypt tag selection.
The 2026-05-19 PR4A refresh checked key-route ScreenModel ownership for key
generation, private-key import, backup export, expiry modification, key detail,
and selective revocation. It added unit coverage for stale async-result
suppression, import/export cleanup, backup confirmation timing, and a
source-audit rule blocking key-management workflow calls from key route Views.
The 2026-05-19 PR4B refresh checked Contacts route ScreenModel ownership for
QR display, Add Contact QR-photo import handling, Contact Detail mutations,
Contacts search/tag filters, Tag Management, Tag Detail, import confirmation,
and incoming URL import. It added QR Display ScreenModel coverage, refreshed Add
Contact QR-photo loader tests, and added a source-audit rule blocking
contact/QR workflow calls from Contacts route Views.

Because this audit can be updated together with code changes, validation should
follow the touched surfaces. Documentation-only changes do not require Rust or
Xcode test runs unless they touch code, generated files, project files,
entitlements, release metadata, or build settings.
