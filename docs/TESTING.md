# Testing

*Lanes, plans, and the cross-tool interop policy — the parts of validation a reader cannot recover from the suites themselves. The files under `pgp-mobile/tests/` and `Tests/` are the source of truth for what is covered; this document keeps no prose copy of them. The Rust↔Xcode artifact contract, the sync command, and stale-artifact troubleshooting: [BUILD.md](BUILD.md) §6.*

## 1. Lanes

Four lanes, distinguished by what they can run on.

**Rust** — no Apple dependency; exercises the `pgp-mobile` engine directly.

```bash
cargo +stable test --manifest-path pgp-mobile/Cargo.toml
```

The default run skips tests marked `#[ignore = "slow"]`; the blocking lanes add those two targets by name:

```bash
cargo +stable test --manifest-path pgp-mobile/Cargo.toml --test portable_modern_high_slow_tests -- --ignored
cargo +stable test --manifest-path pgp-mobile/Cargo.toml --test large_payload_tests -- --ignored
```

**Dependency audit** — whenever `pgp-mobile/Cargo.lock` changes, and before release validation:

```bash
cargo +stable install cargo-audit --version 0.22.2 --locked
cargo +stable audit --file pgp-mobile/Cargo.lock --deny warnings
```

**Swift unit + FFI** — the iOS Simulator cannot host this lane; macOS is where it runs. The Simulator compiles, but the unit-test host app dies at launch: the ProtectedData storage root requires the volume to report file-protection support *and* re-reads the `.complete` attribute it just wrote, failing closed when either check fails — which is what the simulator's volume does.

**Device** — needs a real Secure Enclave. An Apple Silicon Mac runs the whole lane locally (the Mac host has one); SE-capable iPhones and iPads work too; the simulator cannot. Biometric steps use Touch ID or the system authentication prompt. The MIE subset additionally needs memory-tagging hardware (§6).

**Environment-gated skips.** A test whose environment is unavailable — no Secure Enclave, no enrolled biometrics, no external binary, an app window that never becomes frontmost — **skips explicitly rather than weakening an assertion**, and re-running is the normal path. The interop lanes turn that skip back into a failure on demand (§5).

Commands for the Apple lanes: §2.3.

## 2. Test plans

Five plans. Every invocation names one with `-testPlan`, so scope is never implicit.

- **CypherAir-UnitTests** — the Swift unit and FFI lane; the `CypherAir` scheme's default plan.
- **CypherAir-DeviceTests** — the device lane, selected classes only. Non-destructive.
- **CypherAir-DangerousDeviceTests** — manual and destructive. Its Reset All Local Data cleanup proof **deletes every app-owned Secure Enclave custody handle for the bundle**, not only the handles it created. Run it against a disposable install or device state, never a real one.
- **CypherAir-InteropEvidenceTests** — the manual macOS-only real-SE↔GnuPG evidence harness; needs real Secure Enclave hardware, biometric approval, and a local `gpg`. Evidence rules: [CUSTODY.md](CUSTODY.md) §9.
- **CypherAir-MacUITests** — macOS UI smoke coverage: routes, settings, tutorial launch and lifecycle, and the lock shield.

There is no visionOS test plan; native visionOS validation is the build probe in §2.3.

**The unit plan's `skippedTests` list is fail-open by construction.** Every `XCTestCase`-deriving class under `Tests/DeviceSecurityTests/` that declares test methods must be listed there, or it runs in the unit lane and stops the run at a biometric prompt. The rule is scoped to that directory, not to a `Device*` name. `scripts/check_device_test_skip_list.py` inverts the default in PR and nightly CI and fails with the missing class names; a base class that declares no test methods of its own is exempt until it declares one.

The test target is named `CypherAirTests` — `-only-testing:` takes the target name, not the scheme name.

Tutorial or UI-test launch-gating changes additionally need the Mac UI plan plus Release and `AppStore Candidate Release` macOS build probes — the proof that the `UITEST_*` launch overrides stay Debug-only.

ProtectedData device tests use test-only shared-right identifiers, never the production one, and never call `removeAllRightsWithCompletion()`.

### 2.1 CI lanes

**PR Checks** (pull requests) and **Nightly Full Validation** (scheduled, plus manual dispatch) run the same job set and are the blocking release-readiness signal. **XCFramework Edge Release** rebuilds, probes, and publishes an edge prerelease on every push to `main`; **Stable Release Attestation** runs on `release.published` ([BUILD.md](BUILD.md) §2); the dependency-freshness report is manual-only and never fails.

- Rust and XCFramework jobs deliberately use **no Cargo cache action**: a restored `target/` can mix compiler generations and break proc-macro builds. Clean, slower builds are the accepted trade.
- Localization catalog health is **reported, never gated** (`scripts/report_localization_catalog.py`, `continue-on-error`). Read the Step Summary when touching `Sources/Resources/*.xcstrings`.

### 2.2 Hosted-runner limits

Hosted macOS images can lag the deployment target, or ship an Xcode before its matching platform runtimes: the pinned Xcode version and the SDK/runtime expectation are therefore pinned *separately* in `scripts/ci_xcode_platform_preflight.sh`, so an IDE-only Xcode update stays expressible. An image mismatch warns and skips the affected Apple platform probe rather than degrading the XCFramework packaging signal, while a project-configuration or missing-destination failure still fails the workflow. **A skipped probe never stands in for release validation.** Hosted runners also carry no CypherAir signing material by policy — signed app builds stay local and on Xcode Cloud. And CI runs no `xcodebuild test` at all: **the local macOS unit lane is the source of truth for Swift validation**, in every case.

### 2.3 Local validation

```bash
# Swift unit + FFI lane
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS,arch=arm64e'

# Device lane — an Apple Silicon Mac, or a physical iPhone/iPad
xcodebuild test -scheme CypherAir -testPlan CypherAir-DeviceTests \
    -destination 'platform=macOS,arch=arm64e'

# macOS UI smoke coverage
xcodebuild test -scheme CypherAir -testPlan CypherAir-MacUITests \
    -destination 'platform=macOS'

# Native visionOS build probe (linkage + availability, not a test substitute)
xcodebuild build -scheme CypherAir -destination 'generic/platform=visionOS'

# The Python gates, which CI runs in named groups
python3 -m unittest discover -s scripts/tests

# Text hygiene (rustfmt is a local courtesy, not a CI gate)
python3 scripts/check_text_hygiene.py
```

**Script sandboxing.** User-script sandboxing is enabled for the app and test targets, and local validation must never depend on `ENABLE_USER_SCRIPT_SANDBOXING=NO`. A Run Script phase must declare every file it reads in `inputPaths`/`inputFileListPaths` and every product it writes in `outputPaths`/`outputFileListPaths` — **a declared parent directory is not recursive access.** That is why adding a test fixture means updating the fixture xcfilelists (`Tests/FixtureResources.xcfilelist` and its `.outputs` companion) rather than naming their directory.

## 3. Family coverage

Crypto tests cover every family a change touches. The five portable families are what the Rust suites parameterize over; the device-bound families get equivalent coverage through the custody unit suites (mocks plus software P-256 keys) and the device lane. Per-family algorithms, key versions, and message formats are canon in code.

Password/SKESK round-trips are recipient-key-independent and are covered per message format rather than per family. **Their tamper tests use targeted payload and tag-area mutations, not arbitrary bit flips** — a random flip usually fails for the wrong reason.

## 4. Writing tests

- **Assert behavior, not source text.** No source-scanning XCTest assertions: architecture conformance is review's job, not a test's.
- **Every crypto operation** needs a round-trip test per family it supports, a targeted tamper test proving hard-fail with no partial output, and format assertions wherever the format rule applies (SEIPDv1/v2 selection, the AES-256 floor).

## 5. Cross-tool interoperability

**The policy.** GnuPG interop applies to Portable Legacy (software v4) and Device-Bound Legacy (v4). **v6 output — Modern, Modern · High, and Device-Bound Modern — is expected to be rejected by GnuPG**, and that rejection is asserted rather than assumed. **The post-quantum families make no GnuPG claim at all**: GnuPG follows LibrePGP's different post-quantum wire format ([CUSTODY.md](CUSTODY.md) §8). `sq` (sequoia-sq) is the cross-implementation evidence for the RFC 9580/9980 families; the device-bound families share those wire formats, and their custody halves are covered by the custody suites and the device lane.

**Two mechanisms per tool.** Fixtures are tool-generated certificates, messages, and signatures committed as test data, with the tested tool versions recorded beside them — deterministic and CI-safe. Live lanes drive the real binary; `gpg` runs on macOS only. Regenerate fixtures when a Sequoia update changes emitted or accepted wire formats, when algorithm selection changes, or when the GnuPG major version changes. For wire-neutral Sequoia patch releases, validate the frozen fixtures and the live lanes instead of rotating randomized test material.

**The require flags fail; they do not skip.** The interop helpers skip when the binary is missing, but under `CYPHERAIR_REQUIRE_GPG=1` / `CYPHERAIR_REQUIRE_SQ=1` — how the CI interop job runs them — a missing binary fails the lane instead. One deliberate exception: the post-quantum live sq tests gate additionally on a capability probe, because an sq built on pre-2.4 sequoia-openpgp predates the final RFC 9980 wire format and cannot read engine ML-DSA certificates. **Those tests skip loudly even under `CYPHERAIR_REQUIRE_SQ=1`** — the flag requires sq's presence, not its newest version — and self-activate once the installed sq can import an engine post-quantum key. The committed fixtures carry cross-implementation post-quantum coverage meanwhile.

**A format trap.** sq advertises the SEIPDv2 feature even on its default v4 profile, so every sq suite negotiates SEIPDv2. That is sq's behavior, not a format-selection defect; the v4-only SEIPDv1 floor is asserted by mixing an engine Portable Legacy key into the recipient set (the format rule in [PRODUCT.md](PRODUCT.md) §5).

## 6. MIE validation

Run on hardware with Hardware Memory Tagging (A19 / A19 Pro class) with the Xcode memory-tagging diagnostic enabled. The MIE tests also pass on hardware without tagging — they simply prove nothing about MIE there.

**The pass criterion no test can assert is the out-of-band one:** after the run, Console.app and the crash logs must contain no `EXC_GUARD` / `GUARD_EXC_MTE_SYNC_FAULT` entry for the app.
