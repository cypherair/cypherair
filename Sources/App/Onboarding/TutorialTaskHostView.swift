import SwiftUI

struct TutorialTaskHostView<Content: View>: View {
    @Environment(TutorialSessionStore.self) private var tutorialStore

    let task: TutorialTaskID
    @ViewBuilder let content: () -> Content

    var body: some View {
        content()
            .safeAreaInset(edge: .bottom) {
                if tutorialStore.isCompleted(task),
                   tutorialStore.session.activeTask == task {
                    completionCard
                }
            }
    }

    private var completionCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(task.title)
                .font(.headline)
            Text(String(localized: "guidedTutorial.task.complete", defaultValue: "Task complete. Return to the tutorial to continue."))
                .font(.subheadline)
                .foregroundStyle(.secondary)

            Button(String(localized: "guidedTutorial.return", defaultValue: "Return to Tutorial")) {
                tutorialStore.dismissShell()
            }
            .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }
}
