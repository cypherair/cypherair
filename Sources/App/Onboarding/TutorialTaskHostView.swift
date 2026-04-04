import SwiftUI

struct TutorialTaskHostView<Content: View>: View {
    @Environment(TutorialSessionStore.self) private var tutorialStore
    @Environment(\.horizontalSizeClass) private var sizeClass

    let task: TutorialTaskID
    let showsCompletionFeedback: Bool
    @ViewBuilder let content: () -> Content
    @State private var showCompactSuccessBanner = false

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
            .overlay(alignment: .top) {
                if showsCompletionFeedback,
                   sizeClass == .compact,
                   showCompactSuccessBanner,
                   tutorialStore.activeModal == nil {
                    compactSuccessBanner
                        .padding(.horizontal, 16)
                        .padding(.top, 12)
                }
            }
            .overlay(alignment: .bottom) {
                if showsCompletionFeedback,
                   isTaskCompleted,
                   sizeClass != .compact,
                   tutorialStore.activeModal == nil {
                    completionCard
                        .padding(.horizontal, 16)
                        .padding(.bottom, 12)
                }
            }
            .onAppear {
                showCompactSuccessBanner = false
            }
            .onChange(of: isTaskCompleted) { oldValue, newValue in
                if sizeClass == .compact,
                   !oldValue,
                   newValue {
                    showCompactSuccessBanner = true
                }
            }
    }

    private var isTaskCompleted: Bool {
        tutorialStore.isCompleted(task) &&
            tutorialStore.session.activeTask == task
    }

    private var isFinalTask: Bool {
        task == TutorialTaskID.allCases.last
    }

    private var completionMessage: String {
        if isFinalTask {
            return String(localized: "guidedTutorial.task.complete.final", defaultValue: "Tutorial complete. Finish to see your next steps.")
        }
        return String(localized: "guidedTutorial.task.complete", defaultValue: "Task complete. Return to the tutorial to continue.")
    }

    private var primaryButtonTitle: String {
        if isFinalTask {
            return String(localized: "guidedTutorial.finish", defaultValue: "Finish Tutorial")
        }
        return String(localized: "guidedTutorial.return", defaultValue: "Return to Tutorial")
    }

    private var compactSuccessBanner: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(task.title)
                .font(.headline)

            Text(completionMessage)
                .font(.subheadline)
                .foregroundStyle(.secondary)

            HStack(spacing: 10) {
                Button(primaryButtonTitle) {
                    tutorialStore.dismissShell()
                }
                .buttonStyle(.borderedProminent)

                Button(String(localized: "guidedTutorial.keepExploring", defaultValue: "Keep Exploring")) {
                    showCompactSuccessBanner = false
                }
                .buttonStyle(.bordered)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(.regularMaterial)
    }

    private var completionCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(task.title)
                .font(.headline)
            Text(completionMessage)
                .font(.subheadline)
                .foregroundStyle(.secondary)

            Button(primaryButtonTitle) {
                tutorialStore.dismissShell()
            }
            .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
    }
}
