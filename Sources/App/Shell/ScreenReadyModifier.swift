import SwiftUI

public extension View {
    /// Publishes a "this screen finished loading" marker for the macOS UI-test
    /// lane to wait on.
    ///
    /// The marker is a real accessibility element — that is the only reason
    /// XCUITest can find it, and the reason VoiceOver would otherwise reach and
    /// speak an identifier that means nothing to a reader. Hiding it from
    /// assistive technology hides it from XCUITest too, so it is compiled out
    /// instead. Nothing is lost: the UI tests drive the app through `UITEST_*`
    /// launch overrides, which `AppLaunchConfiguration` honours only in DEBUG.
    func screenReady(_ identifier: String) -> some View {
        #if DEBUG
        overlay(alignment: .topLeading) {
            Text(identifier)
                .font(.system(size: 1))
                .foregroundStyle(.clear)
                .accessibilityIdentifier(identifier)
                .allowsHitTesting(false)
        }
        #else
        self
        #endif
    }
}
