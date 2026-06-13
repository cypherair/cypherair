import SwiftUI

/// Runtime gate for the macOS 27 / MIE v2 text-field teardown crash mitigation
/// (Apple framework bug **FB23066215**, tracked in issue #499).
///
/// On macOS 27 (arm64e, MIE v2 / Hardware Memory Tagging) a focused SwiftUI
/// `TextField`/`SecureField`/`TextEditor` faults in libobjc `weak_clear_no_lock` when its
/// backing `NSTextField` deallocates (`EXC_ARM_MTE_TAGCHECK_FAIL`). On-device A/B testing
/// proved this is intrinsic to `NSTextField` deallocation — independent of `@FocusState`,
/// of field ownership, and of first-responder timing — and that the only effective client
/// mitigation is to never deallocate the field: pool and reuse it for the process lifetime
/// (`weak_clear_no_lock` runs only inside `dealloc`). See the pooled inputs in
/// `CypherTextInputs.swift` / `CypherMultilineTextInput.swift`. Remove the whole mitigation
/// once Apple ships a fix.
///
/// Runtime check (NOT `#available`) because CI builds against the 26.5 SDK, which has no
/// macOS-27 availability symbol. NO-OP on macOS 26.x, iOS, visionOS.
enum MIEWeakTeardownMitigation {
    static let isActive: Bool = {
        #if os(macOS)
        return ProcessInfo.processInfo.isOperatingSystemAtLeast(
            .init(majorVersion: 27, minorVersion: 0, patchVersion: 0)
        )
        #else
        return false
        #endif
    }()
}

extension View {
    @ViewBuilder
    func scrollDismissesKeyboardInteractivelyIfAvailable() -> some View {
        #if os(iOS)
        self.scrollDismissesKeyboard(.interactively)
        #else
        self
        #endif
    }
}
