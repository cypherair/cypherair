# Testing

## 1. Lanes

**The Swift unit and FFI lane runs on macOS.** A simulator build runs the sandbox composition in place of the production one, because the simulator has no Secure Enclave and a context there cannot carry an application password, and it accepts the missing file-protection readback the simulator's volume gives; nothing a simulator run passes says anything about the production composition or about file protection.

**CI runs no `xcodebuild test` at all.** The local macOS unit lane is the source of truth for Swift validation, in every case. Hosted runners carry no CypherAir signing material by policy — signed app builds stay local and on Xcode Cloud — and a hosted-image mismatch skips the affected Apple platform probe rather than failing; **a skipped probe never stands in for release validation.**

**The vault package's tests are their own lane**: `swift test --package-path Packages/CypherVault` runs them; the unit plan does not. They run on the package's sandbox composition — the software enclave, rows in memory, no prompt — behind a recording wrapper that keeps every access policy it is handed, and never reach LocalAuthentication.

**Service tests run over a real sandbox vault, never a mock of it.** `TestHelpers.makeSandbox()` opens the same composition under a known passphrase in a temporary directory; `reopen()` locks and unlocks it through that passphrase, which is how a test proves something survived to disk. The UI-test container is the same composition: under `UITEST_REQUIRE_MANUAL_AUTH=1` the app boots locked and the test types `UITEST_VAULT_PASSPHRASE`, and nothing prompts.

**The device lane needs a real Secure Enclave.** An Apple Silicon Mac runs the whole lane locally; SE-capable iPhones and iPads work too; the simulator cannot.

**The Rust and XCFramework CI jobs deliberately use no Cargo cache action:** a restored `target/` can mix compiler generations and break proc-macro builds.

## 2. What a test must earn

A test exists only if its name states the contract it guards and a later change could break that contract silently. If the regression it would catch cannot be named, it is not written. Four kinds meet that bar:

- **Known-answer vectors** for the sealing layer, so drift in a derivation label or in authenticated data is caught.
- **Adversarial tests:** flip each public field of an envelope and expect failure, open a blob as the wrong payload kind, damage or remove one domain file and expect the integrity-failure state, never defaults.
- **Invariant tests** over the sandbox composition: no enclave key is created without the application-password option except ML-KEM, every session accessor throws once relocked, and custody approvals are taken inside the operation-prompt window.
- **Device tests** on real hardware: the application-password probes, plus one unlock and one private operation end to end.

Not written: tests of initializers and accessors, tests that assert a mock was called, tests that mirror an implementation's branches, error-string snapshots.

## 3. Traps and red lines

- **Every `XCTestCase` class under `Tests/DeviceSecurityTests/` that declares test methods must be listed in the unit plan's `skippedTests`**, or it runs in the unit lane and stops the run at a biometric prompt. The rule is scoped to that directory, not to a `Device*` name; `scripts/check_device_test_skip_list.py` enforces it in CI, but a local run bites first.
- **The application-password probes are two classes with different needs.** `DeviceApplicationPasswordProbeTests` uses password-only access control and runs unattended in the device lane; `DeviceApplicationPasswordBiometricProbeTests` combines the biometric constraint and needs exactly one Touch ID or Face ID approval, so it is run with a person present. Their printed reports are the evidence behind the platform facts in [SECURITY.md](SECURITY.md); a change in what they observe re-opens the design decision that rests on it.
- **Device tests never write under the app's own Keychain services** (`com.cypherair.vault.*`); the probes tag their rows with their own names, so a run leaves the real vault untouched.
- **Build phases read only what they declare, and a declared parent directory is not recursive access.** Adding a test fixture means adding it to `Tests/FixtureResources.xcfilelist` and its `.outputs` companion. Local validation must never depend on `ENABLE_USER_SCRIPT_SANDBOXING=NO`.
- **Tutorial or UI-test launch-gating changes** additionally need the Mac UI plan plus Release and `AppStore Candidate Release` macOS build probes — the proof that the `UITEST_*` launch overrides stay Debug-only.
- **Every crypto operation** needs a round-trip test per family it supports, a targeted tamper test proving hard-fail with no partial output, and format assertions wherever the format rule applies.

## 4. Cross-tool interoperability

GnuPG interop applies to Portable Legacy (software v4) and Device-Bound Legacy (v4). **v6 output — Modern, Modern · High, and Device-Bound Modern — is expected to be rejected by GnuPG**, and that rejection is asserted rather than assumed. **The post-quantum families make no GnuPG claim at all**: GnuPG follows LibrePGP's different post-quantum wire format ([CUSTODY.md](CUSTODY.md)). `sq` (sequoia-sq) is the cross-implementation evidence for the RFC 9580/9980 families.

Fixtures are tool-generated certificates, messages, and signatures committed as test data with the tested tool versions recorded beside them; live lanes drive the real binary, and `gpg` runs on macOS only. Regenerate fixtures when a Sequoia update changes emitted or accepted wire formats, when algorithm selection changes, or when the GnuPG major version changes; for wire-neutral Sequoia patch releases, validate the frozen fixtures and the live lanes instead.

Under `CYPHERAIR_REQUIRE_GPG=1` / `CYPHERAIR_REQUIRE_SQ=1`, how the CI interop job runs, a missing binary fails the lane instead of skipping. One exception: the post-quantum live sq tests also gate on a capability probe, because an sq built on pre-2.4 sequoia-openpgp cannot read engine ML-DSA certificates; **those tests skip loudly even under the require flag** and self-activate once the installed sq can import an engine post-quantum key.

**A format trap.** sq advertises the SEIPDv2 feature even on its default v4 profile, so every sq suite negotiates SEIPDv2. That is sq's behavior, not a format-selection defect; the v4-only SEIPDv1 floor is asserted by mixing an engine Portable Legacy key into the recipient set.

## 5. MIE validation

MIE validation needs hardware with memory tagging (A19 / A19 Pro class) and the Xcode memory-tagging diagnostic; no device test exercises it, and the build probes only prove the slices link. **The pass criterion is out of band:** after a run on such hardware, Console.app and the crash logs must contain no `EXC_GUARD` / `GUARD_EXC_MTE_SYNC_FAULT` entry for the app.
