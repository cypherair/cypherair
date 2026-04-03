import SwiftUI

struct TutorialTaskHostView<Content: View>: View {
    @Environment(TutorialSessionStore.self) private var tutorialStore
    @Environment(\.horizontalSizeClass) private var sizeClass

    let task: TutorialTaskID
    @ViewBuilder let content: () -> Content
    @State private var showCompactSuccessBanner = false

    var body: some View {
        content()
            .safeAreaInset(edge: .top) {
                if sizeClass == .compact,
                   showCompactSuccessBanner {
                    compactSuccessBanner
                }
            }
            .safeAreaInset(edge: .bottom) {
                if isTaskCompleted,
                   sizeClass != .compact {
                    completionCard
                        .padding(.horizontal, 16)
                        .padding(.vertical, 12)
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

    private var compactSuccessBanner: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(task.title)
                .font(.headline)

            Text(String(localized: "guidedTutorial.task.complete", defaultValue: "Task complete. Return to the tutorial to continue."))
                .font(.subheadline)
                .foregroundStyle(.secondary)

            HStack(spacing: 10) {
                Button(String(localized: "guidedTutorial.return", defaultValue: "Return to Tutorial")) {
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
    }
}
