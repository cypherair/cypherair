import SwiftUI

extension ToolbarItemPlacement {
    /// Where a sheet's one prominent Done goes: pinned to the trailing end of
    /// the top bar on iOS and visionOS, so it never moves into the overflow
    /// menu, and the confirmation slot on macOS, which has no pinned placement.
    static var sheetDone: ToolbarItemPlacement {
        #if os(macOS)
        .confirmationAction
        #else
        .topBarPinnedTrailing
        #endif
    }
}

extension View {
    /// Keeps the navigation title on screen while the content scrolls. Beside
    /// a vertical bar iOS otherwise minimises the navigation bar on scroll,
    /// which takes the title away and leaves the screen unnamed. Applies to the
    /// content of each navigation stack, so a sheet's stack needs its own.
    func navigationTitleStaysVisible() -> some View {
        #if os(iOS)
        toolbarMinimizationBehavior(.never, for: .navigationBar)
        #else
        self
        #endif
    }
}
