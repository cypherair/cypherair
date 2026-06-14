# Codex Security Review Closed Findings

This document records reviewed findings that are not part of the active fix queue. Use `SR-CLOSED-*` only for audit and traceability. Active implementation work should use `SR-FIX-*` from `docs/CODEX_SECURITY_REVIEW.md`; when an active `SR-FIX-*` item closes, the former active ID is recorded here for traceability.

The archived CSV exports are retained as raw source exports. This Markdown file is the curated decision record for closed findings.

## Closed Decisions

### SR-CLOSED-01: Release builds trust mutable arm64e compiler prereleases

- Legacy ID: `CA-03`
- Severity: `high`
- Area: `ci-supply-chain`
- Disposition: `closed-false-positive`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/f2e7648c09e08191ad848e57aeee7474)
- Decision: False positive. The arm64e stage1 prerelease channel is first-party release infrastructure for this project, not an untrusted third-party dependency source. Pinning can be reproducibility hardening but is not required to close this finding.
- Relevant paths: `.github/workflows/stable-build-release.yml`, `.github/workflows/xcframework-edge-release.yml`, `scripts/build_apple_arm64e_xcframework.sh`

### SR-CLOSED-02: Candidate gate ignores untracked build inputs

- Legacy ID: `CA-04`
- Severity: `high`
- Area: `release-provenance`
- Disposition: `closed-wont-fix`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/0cb2d605ae5c8191b0842302245431ad)
- Decision: Won't fix. Local maintainer App Store candidate builds are inside the trusted release boundary and do not require byte-for-byte matching against GitHub release XCFramework artifacts.
- Relevant paths: `scripts/validate_app_store_candidate_release.py`, `scripts/tests/test_validate_app_store_candidate_release.py`, `CypherAir.xcodeproj/project.pbxproj`, `.gitignore`, `scripts/generate_source_compliance_info.py`

### SR-CLOSED-03: Reset leaves legacy contact files behind

- Legacy ID: `CA-06`
- Severity: `medium`
- Area: `contacts-reset`
- Disposition: `closed-wont-fix`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/1a2f54d7f6dc8191a7a7bba0fc3e3204)
- Decision: Won't fix. Legacy flat contact files are outside the supported app-state model, and current code does not read, migrate, trust, or reset-clean them.
- Relevant paths: `Sources/Services/ContactService.swift`, `Sources/App/Settings/LocalDataResetService.swift`

### SR-CLOSED-04: PRs can warning-skip hosted Swift unit tests

- Legacy ID: `CA-07`
- Severity: `medium`
- Area: `ci-tests`
- Disposition: `closed-wont-fix`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/e3704fde333081918a2fc4404432a502)
- Decision: Won't fix. Hosted Swift unit tests can warning-skip because GitHub Actions is not the authoritative Swift/Xcode gate. Signing credentials are intentionally kept out of hosted CI; App Store candidates are validated on trusted maintainer Apple hardware.
- Relevant paths: `scripts/ci_xcode_platform_preflight.sh`, `.github/workflows/pr-checks.yml`

### SR-CLOSED-05: Mutable OpenSSL fork branch weakens supply-chain pinning

- Legacy ID: `CA-12`
- Severity: `medium`
- Area: `rust-supply-chain`
- Disposition: `closed-false-positive`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/b05242c664948191b3417612b868068d)
- Decision: False positive. The CypherAir OpenSSL carry chain is first-party maintained, and release builds use locked dependency resolution plus manifest-recorded provenance.
- Relevant paths: `pgp-mobile/Cargo.toml`, `pgp-mobile/Cargo.lock`, `build-xcframework.sh`, `.github/workflows/stable-build-release.yml`, `docs/TDD.md`

### SR-CLOSED-06: High-security app access downgraded to passcode fallback

- Legacy ID: `CA-13`
- Severity: `medium`
- Area: `app-auth`
- Disposition: `closed-false-positive`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/c9c06a1e809c819194966ec9af67eb8c)
- Decision: False positive. The finding targets an old migration window, not a current supported reachable flow. App Access Protection and High Security private-key protection are separate.
- Relevant paths: `Sources/Models/AppConfiguration.swift`, `Sources/App/AppContainer.swift`, `Sources/Security/AuthenticationEvaluable.swift`, `Sources/Security/ProtectedData/ProtectedDataSessionCoordinator.swift`

### SR-CLOSED-07: Authentication shield now uses translucent material

- Legacy ID: `CA-14`
- Severity: `medium`
- Area: `privacy-shield`
- Disposition: `closed-false-positive`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/6d9bbb036edc8191bac8bd5eb13ff506)
- Decision: False positive. As of the 2026-05-31 triage, material blur was an intentional UI design, and manual review found no readable privacy/security leak.
- Relevant paths: `Sources/App/Common/AuthenticationShieldHost.swift`

### SR-CLOSED-08: Unbounded signature file import can exhaust app memory

- Legacy ID: `CA-17`
- Severity: `medium`
- Area: `contact-certification-import`
- Disposition: `closed-false-positive`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/eddd21469998819181bbf2a643064c09)
- Decision: False positive for security scope. Manually selecting an abnormally large local signature file is generic robustness hardening, not a security issue for this workflow.
- Relevant paths: `Sources/App/Contacts/ContactCertificateSignaturesScreenModel.swift`

### SR-CLOSED-09: Vendored OpenSSL source redirected to external git fork

- Legacy ID: `CA-19`
- Severity: `medium`
- Area: `rust-supply-chain`
- Disposition: `closed-false-positive`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/b6673788d658819190bd5e40e16998a7)
- Decision: False positive. `cypherair/openssl-src-rs` and `cypherair/openssl` are first-party carry-chain repositories, not untrusted external dependency sources.
- Relevant paths: `pgp-mobile/Cargo.toml`, `pgp-mobile/Cargo.lock`, `build-xcframework.sh`

### SR-CLOSED-10: Unbounded detailed signature UI enables DoS

- Legacy ID: `CA-20`
- Severity: `medium`
- Area: `decrypt-verify-ui`
- Disposition: `closed-false-positive`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/4b57512bd5ec819194bff3e78091181a)
- Decision: False positive for security scope. This is a local user-initiated availability risk and does not create a user-data security issue.
- Relevant paths: `Sources/App/Common/DetailedSignatureSectionView.swift`, `Sources/App/Sign/VerifyView.swift`, `Sources/App/Decrypt/DecryptView.swift`, `Sources/App/Sign/VerifyScreenModel.swift`, `Sources/App/Decrypt/DecryptScreenModel.swift`, `pgp-mobile/src/signature_details.rs`

### SR-CLOSED-11: Unbounded SKESK fallback enables password-decrypt DoS

- Legacy ID: `CA-21`
- Severity: `medium`
- Area: `rust-password`
- Disposition: `closed-wont-fix`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/5dfacb1e55cc81918f142034127840ff)
- Decision: Won't fix. Password/SKESK support is service-only, outside the current target threat model, and has no planned UI exposure. Repeated fallback can at most cause local availability DoS without plaintext/private-key disclosure or AEAD/MDC bypass.
- Relevant paths: `pgp-mobile/src/password.rs`, `pgp-mobile/src/decrypt.rs`

### SR-CLOSED-12: Imported-key revocations stored without export authentication

- Legacy ID: `CA-45`
- Severity: `medium`
- Area: `key-management-revocation`
- Disposition: `closed-false-positive`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/1554a5c3ae908191bb067599d00dce8e)
- Decision: False positive. Revocation certificates are explicit public-distribution exports. Production key metadata lives in the ProtectedData `key-metadata` domain, while legacy nil-access-control metadata rows are migration sources only.
- Relevant paths: `Sources/Services/KeyManagementService.swift`, `Sources/Security/KeyMetadataStore.swift`, `Sources/Models/PGPKeyIdentity.swift`, `Sources/App/Keys/KeyDetailView.swift`

### SR-CLOSED-13: Unbounded armored text imports can exhaust memory

- Legacy ID: `CA-24`
- Severity: `medium`
- Area: `decrypt-verify-ui`
- Disposition: `closed-false-positive`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/792eaf5ba0488191a3b45e9651c6162c)
- Decision: False positive. Large-file decrypt/verify paths use streaming; oversized local text imports are robustness/UX concerns rather than security boundaries.
- Relevant paths: `Sources/App/Decrypt/DecryptView.swift`, `Sources/App/Sign/VerifyView.swift`, `Sources/App/Common/SecurityScopedFileAccess.swift`

### SR-CLOSED-14: macOS Argon2 guard treats total RAM as available

- Legacy ID: `CA-25`
- Severity: `medium`
- Area: `key-import-memory`
- Disposition: `closed-wont-fix`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/c56fc514b22481918273dc22faae7421)
- Decision: Won't fix. macOS intentionally uses physical memory for the Argon2id guard because the iOS Jetsam available-memory model does not apply on macOS.
- Relevant paths: `Sources/Security/Argon2idMemoryGuard.swift`, `Sources/Services/KeyManagementService.swift`, `pgp-mobile/src/keys.rs`

### SR-CLOSED-15: Enhanced Security entitlements renamed to ignored keys

- Legacy ID: `CA-26`
- Severity: `medium`
- Area: `entitlements`
- Disposition: `closed-false-positive`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/5d51dc7622fc8191b9062c03230f5356)
- Decision: False positive. Current Enhanced Security/MIE configuration is correct: the entitlement keys match current Apple naming, build settings enable Enhanced Security and pointer authentication, and Xcode resolves the expected entitlements files.
- Relevant paths: `CypherAir.entitlements`, `docs/SECURITY.md`, `CypherAir.xcodeproj/project.pbxproj`

### SR-CLOSED-16: Hidden QR key can override pasted contact import

- Legacy ID: `CA-28`
- Severity: `medium`
- Area: `contact-import`
- Disposition: `closed-false-positive`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/fbaae00c695881919aad5d01d8942311)
- Decision: False positive. The QR/Paste timing path is unrealistic, and the confirmation UI shows the actual imported key.
- Relevant paths: `Sources/App/Contacts/AddContactView.swift`

### SR-CLOSED-17: Predictable decrypt temp file enables plaintext and symlink attacks

- Legacy ID: `CA-30`
- Severity: `medium`
- Area: `rust-streaming`
- Disposition: `closed-false-positive`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/536baf654b288191b275f2c4d4b9d32a)
- Decision: False positive. The report is based on a stale predictable `<output>.tmp` model. Current streaming decrypt uses randomized staging, and external destinations are reached only by explicit export after authenticated decrypt succeeds.
- Relevant paths: `pgp-mobile/src/streaming.rs`

### SR-CLOSED-18: Launch auth can show content before blur is enabled

- Legacy ID: `CA-31`
- Severity: `medium`
- Area: `privacy-lifecycle`
- Disposition: `closed-false-positive`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/6e6da113cfc481919d83defdc698e785)
- Decision: False positive. A cold-launch first frame cannot expose user-sensitive ProtectedData before app-session authentication unlocks it.
- Relevant paths: `Sources/App/Common/PrivacyScreenModifier.swift`, `Sources/App/CypherAirApp.swift`

### SR-CLOSED-19: Bad signatures no longer hard-fail verification

- Legacy ID: `CA-34`
- Severity: `medium`
- Area: `rust-verify`
- Disposition: `closed-false-positive`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/f1b869820c4c819195b018e0027298ba)
- Decision: False positive. Standalone signature verification intentionally returns graded results and the UI displays invalid signatures; decrypt payload authentication remains a separate hard-fail invariant.
- Relevant paths: `pgp-mobile/src/verify.rs`, `pgp-mobile/src/decrypt.rs`

### SR-CLOSED-20: Oversized FFI inputs can crash Swift callers

- Legacy ID: `CA-35`
- Severity: `medium`
- Area: `ffi-bindings`
- Disposition: `closed-false-positive`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/105db662caf481918b80f2a457afae2e)
- Decision: False positive. Oversized FFI inputs can at most trigger extreme local crash/availability failure; real large-file workflows use dedicated streaming paths.
- Relevant paths: `bindings/pgp_mobile.swift`, `bindings/pgp_mobileFFI.h`

### SR-CLOSED-21: Malformed protected settings envelope can crash app

- Legacy ID: `CA-36`
- Severity: `low`
- Area: `protected-data`
- Disposition: `closed-wont-fix`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/ebf86edb2698819185b2a21d6a21ed94)
- Decision: Won't fix. The path requires local tampering or corruption of app-owned ProtectedData envelopes; normal flows do not generate it, and the impact is local crash/availability.
- Relevant paths: `Sources/Security/ProtectedData/ProtectedDataDomain.swift`, `Sources/Security/ProtectedData/ProtectedDomainRecoveryCoordinator.swift`

### SR-CLOSED-22: Unvalidated temp metadata can spoof build provenance

- Legacy ID: `CA-37`
- Severity: `low`
- Area: `release-provenance`
- Disposition: `closed-false-positive`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/ecf473bc312481919107ae93638eeca8)
- Decision: False positive. The formal candidate flow regenerates metadata after validation; stale temporary metadata requires bypassing the supported release flow.
- Relevant paths: `CypherAir.xcodeproj/project.pbxproj`, `scripts/generate_source_compliance_info.py`, `scripts/validate_app_store_candidate_release.py`

### SR-CLOSED-23: Certificate signatures can verify with invalid signer keys

- Legacy ID: `CA-46`
- Severity: `low`
- Area: `certificate-signatures`
- Disposition: `closed-wont-fix`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/2e9505ab20b08191b1cb000715279709)
- Decision: Won't fix as a separate finding. The verifier is crypto-only by design; the real signer policy and Contacts trust-semantics concern remains tracked by SR-FIX-05 / CA-09.
- Relevant paths: `Sources/Services/CertificateSignatureService.swift`, `pgp-mobile/src/cert_signature.rs`

### SR-CLOSED-24: Signer selection is reset on every Sign view appearance

- Legacy ID: `CA-47`
- Severity: `low`
- Area: `sign-ui`
- Disposition: `closed-false-positive`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/18b3c7e3ff888191a08df1ce994fded3)
- Decision: False positive. Re-syncing to the default signer on each Sign view appearance is current test-locked design; the UI shows the actual signer and there is no attacker-controlled signer injection.
- Relevant paths: `Sources/App/Sign/SignScreenModel.swift`, `Sources/App/Sign/SignView.swift`

### SR-CLOSED-25: Unbounded SKESK S2K can exhaust memory

- Legacy ID: `CA-39`
- Severity: `low`
- Area: `rust-password`
- Disposition: `closed-wont-fix`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/e7a2686e638c8191876364539797073c)
- Decision: Won't fix. This is the same password/SKESK service-only path as CA-21; S2K/KDF resource exhaustion is outside the current target threat model and can at most cause local availability DoS.
- Relevant paths: `Sources/Services/PasswordMessageService.swift`, `pgp-mobile/src/password.rs`, `Sources/Security/Argon2idMemoryGuard.swift`

### SR-CLOSED-26: Legacy share temp files are no longer cleaned on launch

- Legacy ID: `CA-48`
- Severity: `low`
- Area: `temp-files`
- Disposition: `closed-wont-fix`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/fc696460daa08191acbf2ce184cc359b)
- Decision: Won't fix. As of the 2026-05-31 triage, app code no longer creates the legacy `tmp/share/` path; any historical residue is inside the app sandbox temporary directory with low residual risk.
- Relevant paths: `Sources/App/CypherAirApp.swift`, `Sources/App/AppStartupCoordinator.swift`, `Sources/App/Common/AppTemporaryArtifactStore.swift`

### SR-CLOSED-27: AuthenticationManager target addition breaks builds

- Legacy ID: `CA-43`
- Severity: `informational`
- Area: `build-integration`
- Disposition: `closed-false-positive`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/3c77229cc04881919d0060e2d44f8c3d)
- Decision: False positive. As of the 2026-05-31 triage, the claimed build failure was not reproducible; `AuthenticationManager.swift` is in the app target and macOS build succeeds.
- Relevant paths: `CypherAir.xcodeproj/project.pbxproj`, `Sources/Security/AuthenticationManager.swift`

### SR-CLOSED-28: High Security uses biometryAny, enabling biometric reset bypass

- Legacy ID: `CA-44`
- Severity: `informational`
- Area: `auth-docs`
- Disposition: `closed-fixed`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/754d34973c5c8191acd83ea713c022d9)
- Decision: Already fixed as documentation. The implementation intentionally uses `.biometryAny`; PRD/SECURITY wording now states the precise guarantee: no device-passcode fallback for private-key operations and no biometric-enrollment invalidation guarantee.
- Relevant paths: `docs/SECURITY.md`, `docs/PRD.md`, `docs/TDD.md`, `.claude/rules/security-rules.md`

### SR-CLOSED-29: GH_TOKEN exposed to entire XCFramework build

- Former Review ID: `SR-FIX-02`
- Legacy ID: `CA-02`
- Severity: `high`
- Area: `ci-supply-chain`
- Disposition: `closed-fixed`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/b2db20bd745c8191856cc218daacb19d)
- Decision: Fixed by PR #415. Release/XCFramework builds now keep GitHub credentials out of the broad artifact build environment.
- Resolution: Stage1 toolchain download is handled separately, checkout credential persistence is disabled, and static workflow tests verify build and downloader steps do not receive GitHub tokens.
- Relevant paths: `.github/workflows/pr-checks.yml`, `.github/workflows/stable-build-release.yml`, `.github/workflows/xcframework-edge-release.yml`, `scripts/build_apple_arm64e_xcframework.sh`, `scripts/download_arm64e_stage1_toolchain.sh`

### SR-CLOSED-30: Release workflow runs arbitrary refs with write token

- Former Review ID: `SR-FIX-03`
- Legacy ID: `CA-05`
- Severity: `medium`
- Area: `ci-supply-chain`
- Disposition: `closed-fixed`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/893e12c4d22c8191afba18916328b86d)
- Decision: Fixed by PR #415. Stable release publication is now tag-push only, and manual workflow dispatch runs are limited to dry-run validation.
- Resolution: The publish path revalidates that `HEAD` matches the peeled stable tag commit before official artifact creation and rechecks that the remote stable tag is an SSH-signed annotated tag for the expected artifact commit before attestation and release publication.
- Relevant paths: `.github/workflows/stable-build-release.yml`

### SR-CLOSED-31: Rust audit does not gate release publication

- Former Review ID: `SR-FIX-04`
- Legacy ID: `CA-08`
- Severity: `medium`
- Area: `ci-supply-chain`
- Disposition: `closed-fixed`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/9b57feaa6750819185da3adea4e4b205)
- Decision: Fixed by PR #415. Edge/drill release publication is now gated on the Rust dependency audit.
- Resolution: The workflow separates read-scoped asset generation from the write-scoped publish job, and the publish job depends on both the artifact build and `rust-dependency-audit` before attestation, tag creation, release creation, asset upload, or publication.
- Relevant paths: `.github/workflows/stable-build-release.yml`, `.github/workflows/xcframework-edge-release.yml`, `docs/TESTING.md`, `docs/APP_RELEASE_PROCESS.md`

### SR-CLOSED-32: Stale operation prompt generation can disable privacy blur

- Former Review ID: `SR-FIX-08`
- Legacy ID: `CA-15`
- Severity: `medium`
- Area: `privacy-lifecycle`
- Disposition: `closed-fixed`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/daf3bd3399248191900565067b6785ae)
- Decision: Fixed by PR #411, with closure recorded in PR #413. The stale operation-prompt suppression path was replaced with bounded prompt snapshots and generation-aware lifecycle handling.
- Resolution: Operation prompt tails now require prompt-owned lifecycle evidence, expire after a short settle window, and real background transitions clear prompt state and still hard-blur. A related macOS immediate-grace-period observation remains for separate follow-up and is tracked outside this finding.
- Relevant paths: `Sources/Security/AuthenticationPromptCoordinator.swift`, `Sources/App/Common/PrivacyScreenLifecycleGate.swift`, `Sources/App/Common/PrivacyScreenModifier.swift`, `Sources/Security/ProtectedData/AppSessionOrchestrator.swift`

### SR-CLOSED-33: Unescaped source ref in release verification command

- Former Review ID: `SR-FIX-10`
- Legacy ID: `CA-18`
- Severity: `medium`
- Area: `ci-supply-chain`
- Disposition: `closed-fixed`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/6d4198b21e5c8191a5d7d8339a3d6484)
- Decision: Fixed by PR #415. Drill release verification commands now render the source ref through Python `shlex.quote` before publication.
- Resolution: Copied `gh attestation verify --source-ref` commands are shell-safe. Release metadata generation was also moved to structured JSON output, and static workflow tests assert that raw source-ref interpolation is no longer used.
- Relevant paths: `.github/workflows/xcframework-edge-release.yml`

### SR-CLOSED-34: Production auth can be bypassed via UI-test defaults key

- Former Review ID: `SR-FIX-11`
- Legacy ID: `CA-22`
- Severity: `medium`
- Area: `app-auth`
- Disposition: `closed-fixed`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/85c8b620e92c8191ab484e11a5cf4143)
- Decision: Fixed by PR #414. Production/default `AuthenticationManager` instances now ignore the UI-test authentication bypass unless explicitly constructed with UI-test bypass opt-in.
- Resolution: `AppContainer.makeUITest()` remains opted in for automation, while production app-session and private-key authentication paths no longer treat a mutable defaults key as an auth bypass switch. Curated Markdown and the refreshed raw CSV export both record this as fixed.
- Relevant paths: `Sources/App/AppContainer.swift`, `Sources/Security/AuthenticationManager.swift`, `Sources/App/Common/PrivacyScreenModifier.swift`

### SR-CLOSED-35: Secret key zeroization skipped on KMS helper failures

- Former Review ID: `SR-FIX-13`
- Legacy ID: `CA-27`
- Severity: `medium`
- Area: `key-management-zeroization`
- Disposition: `closed-fixed`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/2a18f490890c8191afc9b8775a8ff2b3)
- Decision: Fixed. Key-operation adapter helpers now zeroize secret certificate `Data` on failure paths after secret material has been produced but before ownership reaches the caller.
- Resolution: `PGPKeyOperationAdapter` keeps success-path cleanup caller-owned, while failure-injection tests assert adapter-local zeroization is invoked for post-secret key generation/import helper failures.
- Relevant paths: `Sources/Services/FFI/PGPKeyOperationAdapter.swift`, `Tests/ServiceTests/PGPKeyOperationAdapterTests.swift`

### SR-CLOSED-36: Signing key not zeroized on no-default encrypt-to-self error

- Former Review ID: `SR-FIX-15`
- Legacy ID: `CA-32`
- Severity: `medium`
- Area: `encryption-zeroization`
- Disposition: `closed-fixed`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/8ef989997a7081919d767f560071a253)
- Decision: Fixed. Encryption now resolves public-only encrypt-to-self inputs before unwrapping an optional signing private key.
- Resolution: Text and streaming encryption share one encrypt-to-self resolver, preserving the existing explicit-fingerprint fallback-to-default behavior. Regression tests cover missing-default encrypt-to-self with signing requested and assert signer private-key unwrap does not occur.
- Relevant paths: `Sources/Services/EncryptionService.swift`, `Tests/ServiceTests/EncryptionServiceTests.swift`

### SR-CLOSED-37: Post-auth warm-up can clear background privacy blur

- Former Review ID: `SR-FIX-09`
- Legacy ID: `CA-16`
- Severity: `medium`
- Area: `privacy-lifecycle`
- Disposition: `closed-fixed`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/e2433b9357a48191b7ea3c939cad1a4d)
- Decision: Fixed. Resume completion now checks whether its captured lifecycle generation is still current before it can clear the privacy blur.
- Resolution: Real resign-active and background transitions invalidate in-flight resume completions and keep the hard blur. A stale post-auth completion no longer arms the transient authentication settle path; when the app has already returned active, the UI schedules a fresh resume/grace check instead of accepting the stale completion directly.
- Relevant paths: `Sources/Security/ProtectedData/AppSessionOrchestrator.swift`, `Sources/App/Common/PrivacyScreenModifier.swift`, `Tests/ServiceTests/ProtectedDataFrameworkTests.swift`

### SR-CLOSED-38: Spoofed duplicate contacts bypass key-update warning

- Former Review ID: `SR-FIX-01`
- Legacy ID: `CA-01`
- Severity: `high`
- Area: `contact-import`
- Disposition: `closed-fixed`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/3db1dd11b0548191993e920e471adfb2)
- Decision: Fixed. Duplicate conflicting contact imports remain separate identities by product policy, but the import confirmation now preserves and displays same-identity/different-fingerprint candidate warnings before the user can verify or import the key.
- Resolution: `ContactService` exposes a non-mutating candidate preview for contact import confirmation, `ContactImportWorkflow` carries that preview into `ImportConfirmationRequest`, and confirmed imports recheck the displayed candidate immediately before mutation. If Contacts state changes while the sheet is open, import fails closed and asks the user to review the key again.
- Relevant paths: `Sources/Services/ContactService.swift`, `Sources/Services/ContactSnapshotMutator.swift`, `Sources/App/Contacts/Import/ContactImportWorkflow.swift`, `Sources/App/Contacts/ImportConfirmView.swift`, `Tests/ServiceTests/AddContactScreenModelTests.swift`, `Tests/ServiceTests/IncomingURLImportCoordinatorTests.swift`

### SR-CLOSED-39: Import confirmation can act on a replaced key request

- Former Review ID: `SR-FIX-12`
- Legacy ID: `CA-23`
- Severity: `medium`
- Area: `contact-import`
- Disposition: `closed-fixed`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/078f49939538819195ae18333d9d130b)
- Decision: Fixed. Import confirmation presentation is now first-request-wins, and sheet actions execute the request displayed to the user rather than dereferencing a later mutable request.
- Resolution: `ImportConfirmationCoordinator.present(_:)` refuses replacement while a request is pending, sheet buttons pass the displayed request into coordinator actions, Add Contact surfaces an already-pending error when custom presentation refuses a request, and URL import keeps the current confirmation while reporting that the user must finish or cancel it first.
- Relevant paths: `Sources/App/Contacts/ImportConfirmationCoordinator.swift`, `Sources/App/Contacts/AddContactScreenModel.swift`, `Sources/App/Contacts/AddContactView.swift`, `Sources/App/Contacts/Import/IncomingURLImportCoordinator.swift`, `Sources/App/Onboarding/TutorialSessionStore.swift`, `Tests/ServiceTests/AddContactScreenModelTests.swift`, `Tests/ServiceTests/IncomingURLImportCoordinatorTests.swift`

### SR-CLOSED-40: Local reset fails open when authentication is unavailable

- Former Review ID: `SR-FIX-07`
- Legacy ID: `CA-11`
- Severity: `medium`
- Area: `local-reset-auth`
- Disposition: `closed-fixed`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/be6dc440a494819194638fde5dcd7663)
- Decision: Fixed. Reset All Local Data now requires a successful app-session authentication result before destructive cleanup begins.
- Resolution: `SettingsScreenModel` routes reset confirmation through an injectable app-session authentication action and treats unavailable authentication, failed authentication, cancellation, and non-authenticated results as reset-blocking errors. `LocalDataResetService` remains the internal cleanup primitive and is called only after the Settings flow receives the authenticated result.
- Relevant paths: `Sources/App/Settings/SettingsScreenModel.swift`, `Sources/App/Settings/LocalDataResetService.swift`, `Tests/ServiceTests/SettingsScreenModelTests.swift`

### SR-CLOSED-41: Concurrent tutorial contacts open can fail sandbox setup

- Former Review ID: `SR-FIX-19`
- Legacy ID: `CA-41`
- Severity: `informational`
- Area: `tutorial-contacts`
- Disposition: `closed-fixed`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/703d8b5d0ad48191abf6a936394d174e)
- Decision: Fixed. Tutorial module opens are now serialized by `TutorialSessionStore`, so repeated module launches cannot start concurrent contacts-domain opens against the same disposable tutorial sandbox.
- Resolution: Module open state uses a token-guarded in-flight marker, reset and finish cleanup clear that state, and tutorial launch controls are disabled while an open is running. Production Contacts and ProtectedData open paths are unchanged.
- Relevant paths: `Sources/App/Onboarding/TutorialSessionStore.swift`, `Sources/App/Onboarding/TutorialView.swift`, `Sources/App/Onboarding/Tutorial/TutorialShellTabsView.swift`, `Tests/ServiceTests/TutorialSessionStoreTests.swift`

### SR-CLOSED-42: TOCTOU can delete active protected-data root secret

- Former Review ID: `SR-FIX-06`
- Legacy ID: `CA-10`
- Severity: `medium`
- Area: `protected-data`
- Disposition: `closed-fixed`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/9fd5a847678881918e0eea9cbdfc2e77)
- Decision: Fixed. First-domain root-secret cleanup no longer trusts an empty-registry snapshot captured before domain creation begins.
- Resolution: Orphan cleanup now runs from the first-domain create transaction only after the registry has persisted the matching `.createDomain(..., .journaled)` mutation. The cleaner deletes only for that exact journaled first-domain state and returns `notNeeded` for committed membership, unrelated pending mutations, or other shared-resource states.
- Relevant paths: `Sources/Security/ProtectedData/ProtectedDataFirstDomainSharedRightCleaner.swift`, `Sources/Security/ProtectedData/ProtectedDataRegistryStore.swift`, `Sources/Security/ProtectedData/PrivateKeyControlStore.swift`, `Sources/Security/ProtectedData/ProtectedSettingsStore.swift`, `Tests/ServiceTests/ProtectedDataFrameworkTests.swift`, `Tests/ServiceTests/LocalDataResetServiceTests.swift`

### SR-CLOSED-43: Decrypted file can persist after cancelled/abandoned decrypt

- Former Review ID: `SR-FIX-14`
- Legacy ID: `CA-29`
- Severity: `medium`
- Area: `decrypt-file-output`
- Disposition: `closed-fixed`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/a2a7f41bec048191b18443eaa38268e6)
- Decision: Fixed. Decrypt route disappearance now cancels and invalidates in-flight operations before clearing route state, so a late successful file decrypt cannot adopt plaintext output after the route is abandoned.
- Resolution: `DecryptScreenModel.handleDisappear()` enters the same cancel/invalidate lifecycle used by content-clear handling, and file decrypt keeps its pending-output cleanup guard until adoption after cancellation checks. Regression coverage suspends a file decrypt, disappears the route, then lets the operation return successfully and verifies the output is removed and not published.
- Relevant paths: `Sources/App/Decrypt/DecryptScreenModel.swift`, `Tests/ServiceTests/DecryptScreenModelTests.swift`

### SR-CLOSED-44: Decrypt view can show stale signature for wrong content

- Former Review ID: `SR-FIX-16`
- Legacy ID: `CA-33`
- Severity: `medium`
- Area: `decrypt-verify-ui`
- Disposition: `closed-fixed`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/ffff6cd467088191ab32b29040dd40ab)
- Decision: Fixed. Decrypt text and file outputs now own separate detailed signature verification state, and the view renders only the verification for the currently visible result.
- Resolution: `DecryptScreenModel` now represents text decrypt as an atomic plaintext-plus-verification result and file decrypt as an atomic temporary-output-plus-verification result. File result replacement and clearing preserve temporary-output cleanup ownership. Regression tests cover mode switching, per-mode result preservation, file export from the file-owned result, and text/file invalidation isolation.
- Relevant paths: `Sources/App/Decrypt/DecryptScreenModel.swift`, `Sources/App/Decrypt/DecryptView.swift`, `Tests/ServiceTests/DecryptScreenModelTests.swift`

### SR-CLOSED-45: Text input section is recreated on every edit

- Former Review ID: `SR-FIX-20`
- Legacy ID: `CA-42`
- Severity: `informational`
- Area: `decrypt-verify-ui`
- Disposition: `closed-fixed`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/3f03eebb98448191b26dbb3af9dcafa0)
- Decision: Fixed. Ordinary Decrypt and Verify text edits now clear stale parse/result state without changing the text input section identity.
- Resolution: Decrypt and Verify screen models separate result invalidation from explicit section refresh. Import, reset, and completion workflows can still refresh the section, while normal text edits preserve focus-friendly section identity. Regression tests assert ordinary ciphertext and signed-message edits leave `textInputSectionEpoch` unchanged.
- Relevant paths: `Sources/App/Decrypt/DecryptScreenModel.swift`, `Sources/App/Sign/VerifyScreenModel.swift`, `Tests/ServiceTests/DecryptScreenModelTests.swift`, `Tests/ServiceTests/VerifyScreenModelTests.swift`

### SR-CLOSED-46: Prompt settle window can bypass grace=0 re-auth

- Legacy ID: `none`
- Severity: `medium`
- Area: `privacy-lifecycle`
- Disposition: `closed-fixed`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/dd04b6c16bc48191acb683536c2fb633)
- Decision: Auto-closed by the security scanner (no longer detected) and imported from the 2026-06-14 archived export. Detected 2026-06-05: a coalesced prompt/resign cycle within a 30s settle window could consume a real return as the prompt's paired activation, suppressing grace=0 content-clear / relock / re-authentication. Recorded as fixed pending the maintainer's post-review curation.
- Relevant paths: `Sources/App/Common/PrivacyScreenLifecycleGate.swift`, `Sources/App/Common/PrivacyScreenModifier.swift`, `Sources/Security/AuthenticationPromptCoordinator.swift`

### SR-CLOSED-47: Stale resume authentication can unlock after backgrounding

- Legacy ID: `none`
- Severity: `medium`
- Area: `privacy-lifecycle`
- Disposition: `closed-fixed`
- Source: [finding](https://chatgpt.com/codex/cloud/security/archives/de7b1bdfb5b88191ad0fd84580d82d1a)
- Decision: Auto-closed by the security scanner (no longer detected) and imported from the 2026-06-14 archived export. Detected 2026-06-05: an in-flight successful resume that completed after a background transition could clear the blur from the pre-background authentication instead of forcing a fresh resume check under an expired grace period. Recorded as fixed pending the maintainer's post-review curation.
- Relevant paths: `Sources/Security/ProtectedData/AppSessionOrchestrator.swift`, `Sources/App/Common/PrivacyScreenModifier.swift`
