import SwiftUI

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
