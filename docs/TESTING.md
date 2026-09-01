# Testing

*Lanes, plans, and the cross-tool interop policy — the parts of validation the suites and the project cannot state themselves. The files under `pgp-mobile/tests/` and `Tests/` are the source of truth for what is covered. The Rust↔Xcode artifact contract and the sync command: [BUILD.md](BUILD.md).*

## 1. Lanes

**The Swift unit and FFI lane runs on macOS only.** The iOS Simulator compiles it, but the unit-test host app dies at launch: the ProtectedData storage root requires the volume to report file-protection support and re-reads the `.complete` attribute it just wrote, failing closed when either check fails, which is what the simulator's volume does.

**CI runs no `xcodebuild test` at all.** The local macOS unit lane is the source of truth for Swift validation, in every case. Hosted runners carry no CypherAir signing material by policy — signed app builds stay local and on Xcode Cloud — and a hosted-image mismatch skips the affected Apple platform probe rather than failing; **a skipped probe never stands in for release validation.**

**The device lane needs a real Secure Enclave.** An Apple Silicon Mac runs the whole lane locally; SE-capable iPhones and iPads work too; the simulator cannot. The MIE subset additionally needs memory-tagging hardware (§4).

**The Rust and XCFramework CI jobs deliberately use no Cargo cache action:** a restored `target/` can mix compiler generations and break proc-macro builds.

## 2. Traps and red lines

- **Every `XCTestCase` class under `Tests/DeviceSecurityTests/` that declares test methods must be listed in the unit plan's `skippedTests`**, or it runs in the unit lane and stops the run at a biometric prompt. The rule is scoped to that directory, not to a `Device*` name; `scripts/check_device_test_skip_list.py` enforces it in CI, but a local run bites first.
- **`CypherAir-DangerousDeviceTests` is destructive.** Its Reset All Local Data cleanup proof deletes every app-owned Secure Enclave custody handle for the bundle, not only the handles it created. Run it against a disposable install or device state, never a real one.
- **ProtectedData device tests use test-only shared-right identifiers, never the production one, and never call `removeAllRightsWithCompletion()`.**
- **Build phases read only what they declare, and a declared parent directory is not recursive access.** Adding a test fixture means adding it to `Tests/FixtureResources.xcfilelist` and its `.outputs` companion. Local validation must never depend on `ENABLE_USER_SCRIPT_SANDBOXING=NO`.
- **Tutorial or UI-test launch-gating changes** additionally need the Mac UI plan plus Release and `AppStore Candidate Release` macOS build probes — the proof that the `UITEST_*` launch overrides stay Debug-only.
- **Every crypto operation** needs a round-trip test per family it supports, a targeted tamper test proving hard-fail with no partial output, and format assertions wherever the format rule applies.

## 3. Cross-tool interoperability

GnuPG interop applies to Portable Legacy (software v4) and Device-Bound Legacy (v4). **v6 output — Modern, Modern · High, and Device-Bound Modern — is expected to be rejected by GnuPG**, and that rejection is asserted rather than assumed. **The post-quantum families make no GnuPG claim at all**: GnuPG follows LibrePGP's different post-quantum wire format ([CUSTODY.md](CUSTODY.md)). `sq` (sequoia-sq) is the cross-implementation evidence for the RFC 9580/9980 families.

Fixtures are tool-generated certificates, messages, and signatures committed as test data with the tested tool versions recorded beside them; live lanes drive the real binary, and `gpg` runs on macOS only. Regenerate fixtures when a Sequoia update changes emitted or accepted wire formats, when algorithm selection changes, or when the GnuPG major version changes; for wire-neutral Sequoia patch releases, validate the frozen fixtures and the live lanes instead.

Under `CYPHERAIR_REQUIRE_GPG=1` / `CYPHERAIR_REQUIRE_SQ=1`, how the CI interop job runs, a missing binary fails the lane instead of skipping. One exception: the post-quantum live sq tests also gate on a capability probe, because an sq built on pre-2.4 sequoia-openpgp cannot read engine ML-DSA certificates; **those tests skip loudly even under the require flag** and self-activate once the installed sq can import an engine post-quantum key.

**A format trap.** sq advertises the SEIPDv2 feature even on its default v4 profile, so every sq suite negotiates SEIPDv2. That is sq's behavior, not a format-selection defect; the v4-only SEIPDv1 floor is asserted by mixing an engine Portable Legacy key into the recipient set.

## 4. MIE validation

Run on hardware with Hardware Memory Tagging (A19 / A19 Pro class) with the Xcode memory-tagging diagnostic enabled. The MIE tests also pass on hardware without tagging — they simply prove nothing about MIE there. **The pass criterion no test can assert is the out-of-band one:** after the run, Console.app and the crash logs must contain no `EXC_GUARD` / `GUARD_EXC_MTE_SYNC_FAULT` entry for the app.
