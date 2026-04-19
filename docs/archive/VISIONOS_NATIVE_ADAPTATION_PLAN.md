> Status: Archived planning snapshot.
> Snapshot date: 2026-04-18.
> Archival reason: Native visionOS support is now shipped, so this plan no longer describes the current product or build state.
> Successor current-state docs: [README](../../README.md) · [PRD](../PRD.md) · [TDD](../TDD.md) · [TESTING](../TESTING.md)
> Current code and active documentation outrank this archived planning snapshot.

# CypherAir Native visionOS Adaptation Plan

> Purpose: Define the engineering plan for a native visionOS adaptation of CypherAir.
> Audience: Engineering, product, and security reviewers.
> Status: Planning/design note, not an implementation PRD.
> Baseline date: April 18, 2026.

## 1. Executive Decision

CypherAir should pursue a **native visionOS v1** for Apple Vision Pro as a **window-first security tool**, not as a spatial or immersive experience.

This is the recommended first release path for three reasons:

1. Apple’s visionOS guidance recommends **windows** for familiar, UI-centric interfaces, while volumes and immersive spaces are better reserved for experiences that benefit from depth, 3D content, or environmental integration.
2. CypherAir already uses SwiftUI for the app shell and already has a platform-adaptive navigation structure that aligns well with visionOS window behavior.
3. A window-first release minimizes risk to the app’s security-critical layers, especially Secure Enclave wrapping, LocalAuthentication flows, the two-phase decryption boundary, and the Rust/UniFFI cryptographic pipeline.

For v1, CypherAir should target **native parity and platform correctness**, not spatial differentiation.

## 2. Current Repository Readiness

### 2.1 What is already in place

The repository is partially prepared for visionOS at the project level:

- [`CypherAir.xcodeproj/project.pbxproj`](../../CypherAir.xcodeproj/project.pbxproj) already declares:
  - `SUPPORTED_PLATFORMS = "iphoneos iphonesimulator macosx xros xrsimulator"`
  - `TARGETED_DEVICE_FAMILY = "1,2,7"`
  - `XROS_DEPLOYMENT_TARGET = 26.4`
- `xcodebuild -scheme CypherAir -showdestinations` exposes both:
  - `Any visionOS Device`
  - `Apple Vision Pro` simulator destinations

The app is also structurally well-positioned for a window-based adaptation:

- [`Sources/App/CypherAirApp.swift`](../../Sources/App/CypherAirApp.swift) already uses the SwiftUI app lifecycle and platform branching between iOS and macOS.
- [`Sources/App/ContentView.swift`](../../Sources/App/ContentView.swift) and related shell files already separate iOS-style and macOS-style presentation logic.
- [`Sources/App/Shell/SharedIOSTabShellView.swift`](../../Sources/App/Shell/SharedIOSTabShellView.swift) uses `.tabViewStyle(.sidebarAdaptable)`, which Apple documents as:
  - showing an **ornament** on visionOS; and
  - showing a **sidebar** for secondary tabs inside a `TabSection`.

This means CypherAir’s existing tab-based information architecture is already compatible with a native visionOS window model.

### 2.2 Current build probe

The current non-mutating build probe for visionOS is:

```bash
xcodebuild -scheme CypherAir \
    -destination 'generic/platform=visionOS' \
    build CODE_SIGNING_ALLOWED=NO
```

As of April 18, 2026, the probe confirms that the project is **not yet natively visionOS-complete**.

### 2.3 Observed current blockers

The current visionOS readiness gap is not a top-level architecture failure. As of **April 18, 2026**, the generic visionOS build probe and targeted visionOS SDK availability checks show a set of concrete platform-compatibility blockers that must be resolved before the app can compile cleanly for native visionOS.

Observed blockers:

- [`Sources/App/HomeView.swift`](../../Sources/App/HomeView.swift)
  - `.buttonStyle(.glass)` is unavailable on visionOS.
- [`Sources/App/Common/CypherMultilineTextInput.swift`](../../Sources/App/Common/CypherMultilineTextInput.swift)
  - `conversationContext` is unavailable on visionOS.
  - `inputAssistantItem.leadingBarButtonGroups` is unavailable on visionOS.
  - `inputAssistantItem.trailingBarButtonGroups` is unavailable on visionOS.
- [`Sources/App/Contacts/AddContactView.swift`](../../Sources/App/Contacts/AddContactView.swift)
  - `.scrollDismissesKeyboard(.interactively)` is unavailable on visionOS.

The `scrollDismissesKeyboard` issue is a **class of issue**, not a single-file issue. The same modifier currently appears in multiple input-heavy screens, including:

- [`Sources/App/Decrypt/DecryptView.swift`](../../Sources/App/Decrypt/DecryptView.swift)
- [`Sources/App/Encrypt/EncryptView.swift`](../../Sources/App/Encrypt/EncryptView.swift)
- [`Sources/App/Sign/SignView.swift`](../../Sources/App/Sign/SignView.swift)
- [`Sources/App/Sign/VerifyView.swift`](../../Sources/App/Sign/VerifyView.swift)
- [`Sources/App/Keys/BackupKeyView.swift`](../../Sources/App/Keys/BackupKeyView.swift)
- [`Sources/App/Keys/ImportKeyView.swift`](../../Sources/App/Keys/ImportKeyView.swift)
- [`Sources/App/Keys/KeyGenerationView.swift`](../../Sources/App/Keys/KeyGenerationView.swift)

The current first compile-stopping failure in the generic `visionOS` build probe is the `.glass` button style usage in [`HomeView.swift`](../../Sources/App/HomeView.swift). The text-input and keyboard-assistant issues above remain in scope because targeted `visionOS` SDK availability checks confirm that those symbols are explicitly unavailable on native visionOS.

The plan intentionally does **not** treat alternate app icon asset warnings as a current blocker. That warning had been observed earlier in planning, but it was **not reproduced** in the latest local build probe and therefore should not be treated as a current gating issue without a fresh reproducible log.

## 3. Platform Strategy

CypherAir should formalize a **three-way platform strategy**:

- `iOS`
- `visionOS`
- `macOS`

The current codebase largely branches between iOS and macOS. That is a good starting point, but it is not sufficient for a native visionOS adaptation because many UIKit APIs are shared between iOS and visionOS while still differing in availability and behavior.

### 3.1 Platform branching rule

visionOS should not remain hidden behind `canImport(UIKit)` checks alone, but native adaptation work also should not default to platform forking when Apple’s standard adaptive mechanisms are sufficient.

The implementation strategy for future work should explicitly prefer:

- adaptive layout and environment-driven behavior;
- availability and capability checks;
- compile-time platform branching only when a symbol is unavailable on visionOS or the interaction model is meaningfully different.

For example, future code should prefer environment and availability patterns first, and reserve explicit platform branches for cases like:

```swift
#if os(visionOS)
// Native visionOS-only path for unavailable or materially different APIs.
#elseif os(iOS)
// iOS-specific path when the same symbol or interaction is not shared.
#endif
```

Use `canImport(UIKit)` only where a UIKit-wide abstraction is genuinely shared across both iOS and visionOS.

### 3.2 Scene model for v1

CypherAir v1 on visionOS should target a **single-instance main window** rather than a multi-instance window group.

The intended v1 target is a standard application window with `Window` semantics, not a `WindowGroup` that permits multiple independently instantiated primary windows. This is a product and security decision, not only a presentation preference: CypherAir’s privacy screen, reauthentication state, and sensitive in-memory workflow assumptions are simpler and safer when the native visionOS product exposes one primary window.

Current repository state and target state are different here:

- today, the non-macOS app path still uses `WindowGroup`;
- native visionOS v1 should treat that as an implementation gap to close, not as the desired end state;
- multi-window support is out of scope for v1 because it would require explicit design for privacy-screen coordination, authentication-state consistency, and window restoration semantics before it could be considered safe and coherent.

For the initial release, the app should not introduce new scene types beyond what is needed for a single standard application window. In particular, v1 should not depend on:

- `ImmersiveSpace`
- `Volume`
- RealityKit scene composition
- custom 3D navigation structures

This keeps the adaptation aligned with the app’s current security-tool workflow and reduces the number of platform variables introduced during initial validation.

## 4. UI and Interaction Adaptation

### 4.1 Navigation and shell

CypherAir should keep its existing tab-based information architecture for visionOS v1.

This means:

- reuse the current SwiftUI shell structure;
- continue to organize the app around Home, Keys, Contacts, Settings, and tool flows;
- let visionOS present tab bars and toolbars as native ornaments rather than inventing a custom spatial shell.

Because the current iOS shell already uses `.sidebarAdaptable`, the likely v1 direction is to reuse that architecture and validate it under visionOS rather than replace it.

### 4.2 Input system adaptation

Text input is the first known UI adaptation area.

The implementation work implied by this document should include:

- replacing or guarding iOS-only text assistant APIs in [`CypherMultilineTextInput.swift`](../../Sources/App/Common/CypherMultilineTextInput.swift);
- removing or conditionally disabling `.scrollDismissesKeyboard(.interactively)` on visionOS;
- validating secure long-form text entry, paste, import, export, and machine-text workflows under visionOS interaction patterns.

The document should treat the unavailable input assistant APIs as a signal that **iPad-style keyboard accessory behavior must not be assumed on visionOS**.

### 4.3 Settings and platform capability handling

All privacy and security settings should remain part of the visionOS product surface unless a platform capability is unavailable.

Specific guidance for v1:

- keep the existing privacy, authentication, and key-management settings model;
- treat alternate app icon selection as a **native visionOS v1 non-goal**;
- explicitly distinguish between two runtime models:
  - compatible iPhone/iPad apps running on visionOS can still use `setAlternateIconName`;
  - apps built natively with the visionOS SDK do **not** support alternate icons, and calling `setAlternateIconName` has no effect;
- do not expose the alternate app icon setting in the native visionOS UI;
- treat static app icon asset configuration as a separate launch-readiness concern, not as a runtime substitute for alternate icon switching;
- document that native visionOS has **no runtime substitute** for alternate app icon switching in v1.

## 5. Security and Authentication Position

visionOS v1 should **not** change CypherAir’s existing security model.

The following security behaviors remain unchanged:

- Secure Enclave wrapping and unwrapping flow
- Keychain access-control model
- LocalAuthentication-based gating
- the two-phase decryption boundary
- zero-network behavior
- no plaintext or private-key logging

### 5.1 Why the current model should carry forward

Apple’s Local Authentication and Secure Enclave documentation indicates that visionOS remains aligned with the same core model used across Apple’s secure platforms:

- `LAContext` remains the API surface for evaluating authentication policies and access control;
- Local Authentication continues to broker biometric and passcode-style policies through the Secure Enclave;
- `SecureEnclave.isAvailable` remains the runtime capability check for hardware-backed Secure Enclave access.

For CypherAir, this supports a compatibility-driven visionOS adaptation rather than a redesign of the authentication model.

### 5.2 Sensitive boundary reminder

Any future implementation work touching the following paths remains a sensitive-boundary change and should be explicitly reviewed:

- [`Sources/Security/`](../../Sources/Security)
- [`Sources/Services/DecryptionService.swift`](../../Sources/Services/DecryptionService.swift)
- [`pgp-mobile/src/`](../../pgp-mobile/src)

The expectation for visionOS adaptation work is that changes in these areas, if needed at all, should be compatibility-driven rather than behavior-changing.

## 6. Rust / UniFFI / Build Pipeline Gap

This is a first-class gap, not an appendix item.

### 6.1 Current state

The current Rust/UniFFI pipeline is not yet visionOS-native:

- Local Rust builds have now validated that `pgp-mobile` can compile for both:
  - `aarch64-apple-visionos`
  - `aarch64-apple-visionos-sim`
  when `openssl-src` is patched with visionOS support.
- The patched `openssl-src-rs` work has been upstreamed as:
  - [`alexcrichton/openssl-src-rs#283`](https://github.com/alexcrichton/openssl-src-rs/pull/283)
  - branch source: `cypherair/openssl-src-rs:visionos-openssl-src-upstream-prep`
  - exact tested revision: `0c7e9b5e0c4c4644de34dd3ee86f2a2ef87daa61`
- That upstream PR also fixes the existing architecture-specific iOS simulator OpenSSL configure target mappings for:
  - `x86_64-apple-ios`
  - `aarch64-apple-ios-sim`
- [`build-xcframework.sh`](../../build-xcframework.sh) builds only:
  - `aarch64-apple-ios`
  - `aarch64-apple-ios-sim`
  - `aarch64-apple-darwin`
- [`CypherAir.xcodeproj/project.pbxproj`](../../CypherAir.xcodeproj/project.pbxproj) links Rust static archives only for:
  - `iphoneos`
  - `iphonesimulator`
  - `macosx`
- Local toolchain inspection shows that `rustc --print target-list` already includes:
  - `aarch64-apple-visionos`
  - `aarch64-apple-visionos-sim`

This changes the planning posture: the unresolved gap is no longer "whether vendored OpenSSL can be made to build for visionOS at all", but rather "how to formalize that support in CypherAir's own build, linking, and Swift app layers".

### 6.2 Planning conclusion

The v1 planning conclusion is:

- **no UniFFI surface redesign is required** for visionOS v1;
- the build pipeline must be extended to produce and link visionOS Rust artifacts before CypherAir can be considered a native visionOS target;
- this is an engineering enablement task, not a product-level redesign.
- CypherAir main should not commit a machine-local `path` patch for `openssl-src`.
- If upstream support is still pending when implementation starts, a temporary implementation branch may pin `openssl-src` to the CypherAir fork with `git` + exact `rev` for reproducibility.

The current recommended temporary source for that implementation-branch-only override is:

- fork: [`cypherair/openssl-src-rs`](https://github.com/cypherair/openssl-src-rs)
- branch: `visionos-openssl-src-upstream-prep`
- exact tested revision: `0c7e9b5e0c4c4644de34dd3ee86f2a2ef87daa61`
- upstream PR: [`alexcrichton/openssl-src-rs#283`](https://github.com/alexcrichton/openssl-src-rs/pull/283)

A recommended temporary Cargo override for a future implementation branch is:

```toml
[patch.crates-io]
openssl-src = { git = "https://github.com/cypherair/openssl-src-rs", rev = "0c7e9b5e0c4c4644de34dd3ee86f2a2ef87daa61" }
```

In practical terms, a clean native visionOS adaptation requires both:

1. Swift/App-layer platform fixes; and
2. Rust artifact production and Xcode linker wiring for visionOS.

Only solving the Swift compile issues would leave the native visionOS story incomplete.

## 7. Testing and Acceptance Criteria

visionOS readiness should be evaluated in three tiers.

### 7.1 Compile tier

Goal:

- a generic visionOS build compiles successfully;
- the app links against visionOS Rust artifacts;
- the project produces a valid native visionOS app binary.

Primary check:

```bash
xcodebuild -scheme CypherAir \
    -destination 'generic/platform=visionOS' \
    build CODE_SIGNING_ALLOWED=NO
```

### 7.2 Simulator tier

Goal:

- validate native window behavior on the Apple Vision Pro simulator;
- validate navigation, text input, clipboard/paste flows, file import/export, and basic encrypt/decrypt/sign/verify UI paths;
- confirm that the adapted shell and input model behave correctly under visionOS.

Simulator validation should include:

- top-level navigation and tab/ornament behavior;
- text import and secure text entry;
- file import/export presentation flows;
- non-device-specific service flows that do not depend on real biometric hardware.

### 7.3 Device tier

Goal:

- validate the security-critical runtime behavior that cannot be fully proven in simulator.

Device validation should include:

- biometric prompts on Apple Vision Pro;
- Secure Enclave-backed key operations;
- foreground/background privacy blur behavior;
- reauthentication on resume;
- High Security mode behavior and related failure handling.

### 7.4 Baseline validation that remains required

visionOS work must not replace the existing repo validation baseline.

At minimum, the following remain required after meaningful changes:

```bash
cargo test --manifest-path pgp-mobile/Cargo.toml

xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS'
```

Final security signoff for visionOS must treat simulator-only validation as insufficient because biometric and Secure Enclave behavior remains device-only.

## 8. Architectural Commitments

The visionOS v1 plan does **not** include changes to CypherAir’s public cryptographic or product contracts.

Explicit commitments:

- no change to message-format selection behavior;
- no change to CypherAir’s public crypto behavior;
- no UniFFI API redesign for visionOS v1;
- no planned behavior changes to Secure Enclave wrapping, authentication-mode semantics, or the two-phase decryption model.

visionOS v1 is primarily a **platform adaptation** of:

- the App layer;
- the build and linking pipeline; and
- the validation matrix.

If any implementation work later touches [`Sources/Security`](../../Sources/Security) or [`pgp-mobile/src`](../../pgp-mobile/src), it should be treated as compatibility work unless a separate design decision explicitly approves a behavior change.

## 9. Non-Goals

The following are explicitly out of scope for visionOS v1:

- `ImmersiveSpace`
- `Volume`
- RealityKit content
- camera-dependent acquisition flows
- QR-camera acquisition flows
- spatial collaboration features
- platform differentiation based on 3D content

These exclusions are intentional. The v1 target is a secure, native, window-based product, not a showcase for spatial computing features.

## 10. Future Enhancements

After the native window version is stable, CypherAir can consider selective post-v1 enhancements such as:

- deeper ornament customization where it improves tool workflows;
- visionOS-specific window customization and state restoration refinement;
- scene persistence improvements;
- carefully scoped platform polish that improves comfort or productivity without changing the security model.

These are follow-on opportunities, not prerequisites for the first native release.

## 11. External References

Apple platform and design guidance:

- [Bringing your existing apps to visionOS](https://developer.apple.com/documentation/visionos/bringing-your-app-to-visionos)
- [Determining whether to bring your app to visionOS](https://developer.apple.com/documentation/visionos/determining-whether-to-bring-your-app-to-visionos)
- [Windows](https://developer.apple.com/design/human-interface-guidelines/windows)
- [WindowGroup](https://developer.apple.com/documentation/swiftui/windowgroup)
- [Window](https://developer.apple.com/documentation/swiftui/window)
- [Ornaments](https://developer.apple.com/design/human-interface-guidelines/ornaments)
- [TabViewStyle.sidebarAdaptable](https://developer.apple.com/documentation/swiftui/tabviewstyle/sidebaradaptable)
- [TabView](https://developer.apple.com/documentation/swiftui/tabview)
- [setAlternateIconName(_:completionHandler:)](https://developer.apple.com/documentation/uikit/uiapplication/setalternateiconname%28_%3Acompletionhandler%3A%29)
- [Local Authentication](https://developer.apple.com/documentation/localauthentication/)
- [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
- [SecureEnclave](https://developer.apple.com/documentation/cryptokit/secureenclave)
- [Enabling enhanced security for your app](https://developer.apple.com/documentation/Xcode/enabling-enhanced-security-for-your-app)

Distribution and submission guidance:

- [App Store Connect release notes](https://developer.apple.com/help/app-store-connect/release-notes/)

Important dated note for planning:

- Apple’s App Store Connect release notes for **September 9, 2025** state that apps built with the **Enhanced Security capability** or Enhanced Security extensions on **visionOS** can be uploaded for the App Store and for internal and external testing through TestFlight. This matters for CypherAir because the project treats Enhanced Security as a non-negotiable security requirement rather than an optional polish item.
