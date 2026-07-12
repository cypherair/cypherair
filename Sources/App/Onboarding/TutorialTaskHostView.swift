import SwiftUI

struct TutorialTaskHostView<Content: View>: View {
    @ViewBuilder let content: () -> Content

    init(
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.content = content
    }

    var body: some View {
        content()
    }
}
