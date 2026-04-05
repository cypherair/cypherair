import SwiftUI

@MainActor
private struct TutorialSandboxChromeModifier: ViewModifier {
    @Environment(TutorialSessionStore.self) private var tutorialStore
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass

    let tab: AppShellTab
    let sizeClass: UserInterfaceSizeClass?

    func body(content: Content) -> some View {
        content
            .safeAreaInset(edge: .top, spacing: 0) {
                #if os(macOS)
                if isActiveSandboxTab {
                    macOSTopChrome
                }
                #endif
            }
            .safeAreaInset(edge: .bottom, spacing: 0) {
                if let promptTask = visibleCompletionPromptTask,
                   tutorialStore.activeModal == nil {
                    completionPrompt(for: promptTask)
                        .padding(.horizontal, 16)
                        .padding(.bottom, 12)
                }
            }
            .overlay {
                if isActiveSandboxTab {
                    TutorialSpotlightOverlay(target: currentGuidance?.target)
                }
            }
    }

    private var isActiveSandboxTab: Bool {
        tutorialStore.session.activeTask != nil && tab == tutorialStore.selectedTab
    }

    private var currentGuidance: TutorialGuidance? {
        guard isActiveSandboxTab else { return nil }
        guard tutorialStore.activeModal == nil else { return nil }
        guard let activeTask = tutorialStore.session.activeTask else { return nil }
        guard !tutorialStore.isCompleted(activeTask) else { return nil }

        return TutorialGuidanceResolver().guidance(
            session: tutorialStore.session,
            navigation: tutorialStore.navigation,
            sizeClass: sizeClass,
            selectedTab: tab
        )
    }

    private var visibleCompletionPromptTask: TutorialTaskID? {
        guard isActiveSandboxTab else { return nil }
        guard let promptTask = tutorialStore.pendingCompletionPromptTask else { return nil }
        guard tutorialStore.session.activeTask == promptTask else { return nil }
        return promptTask
    }

    #if os(macOS)
    private var macOSTopChrome: some View {
        HStack {
            Button {
                tutorialStore.returnToOverview()
            } label: {
                Label(
                    String(localized: "guidedTutorial.return", defaultValue: "Return to Tutorial"),
                    systemImage: "chevron.left"
                )
                .font(.subheadline.weight(.semibold))
                .lineLimit(1)
                .minimumScaleFactor(0.85)
            }
            .buttonStyle(.plain)

            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(.bar)
    }
    #endif

    @ViewBuilder
    private func completionPrompt(for task: TutorialTaskID) -> some View {
        if horizontalSizeClass == .compact {
            compactCompletionPrompt(for: task)
        } else {
            regularCompletionPrompt(for: task)
        }
    }

    private func compactCompletionPrompt(for task: TutorialTaskID) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(task.title)
                .font(.headline)

            Text(completionMessage(for: task))
                .font(.subheadline)
                .foregroundStyle(.secondary)

            HStack(spacing: 10) {
                Button(primaryPromptButtonTitle(for: task)) {
                    tutorialStore.handlePrimaryCompletionPromptAction()
                }
                .buttonStyle(.borderedProminent)

                Button(String(localized: "guidedTutorial.keepExploring", defaultValue: "Keep Exploring")) {
                    tutorialStore.dismissCompletionPrompt()
                }
                .buttonStyle(.bordered)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .tutorialBannerChrome()
    }

    private func regularCompletionPrompt(for task: TutorialTaskID) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(task.title)
                .font(.headline)

            Text(completionMessage(for: task))
                .font(.subheadline)
                .foregroundStyle(.secondary)

            HStack(spacing: 10) {
                Button(primaryPromptButtonTitle(for: task)) {
                    tutorialStore.handlePrimaryCompletionPromptAction()
                }
                .buttonStyle(.borderedProminent)

                Button(String(localized: "guidedTutorial.keepExploring", defaultValue: "Keep Exploring")) {
                    tutorialStore.dismissCompletionPrompt()
                }
                .buttonStyle(.bordered)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .tutorialCardChrome(.overlay)
    }

    private func primaryPromptButtonTitle(for task: TutorialTaskID) -> String {
        if task == TutorialTaskID.allCases.last {
            return String(localized: "guidedTutorial.finish", defaultValue: "Finish Tutorial")
        }
        return String(localized: "guidedTutorial.return", defaultValue: "Return to Tutorial")
    }

    private func completionMessage(for task: TutorialTaskID) -> String {
        if task == TutorialTaskID.allCases.last {
            return String(localized: "guidedTutorial.task.complete.final", defaultValue: "Tutorial complete. Finish to see your next steps.")
        }
        return String(localized: "guidedTutorial.task.complete", defaultValue: "Task complete. Return to the tutorial to continue.")
    }
}

extension View {
    func tutorialSandboxChrome(
        tab: AppShellTab,
        sizeClass: UserInterfaceSizeClass?
    ) -> some View {
        modifier(TutorialSandboxChromeModifier(tab: tab, sizeClass: sizeClass))
    }
}
