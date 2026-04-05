import SwiftUI

struct TutorialTaskHostView<Content: View>: View {
    let task: TutorialTaskID
    let showsCompletionFeedback: Bool
    @ViewBuilder let content: () -> Content

    init(
        task: TutorialTaskID,
        showsCompletionFeedback: Bool = true,
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.task = task
        self.showsCompletionFeedback = showsCompletionFeedback
        self.content = content
    }

    var body: some View {
        content()
    }
}
