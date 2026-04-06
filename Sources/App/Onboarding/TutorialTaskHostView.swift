import SwiftUI

struct TutorialTaskHostView<Content: View>: View {
    let module: TutorialModuleID
    let showsCompletionFeedback: Bool
    @ViewBuilder let content: () -> Content

    init(
        module: TutorialModuleID,
        showsCompletionFeedback: Bool = true,
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.module = module
        self.showsCompletionFeedback = showsCompletionFeedback
        self.content = content
    }

    var body: some View {
        content()
    }
}
