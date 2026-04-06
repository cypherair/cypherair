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
                if let promptModule = visibleCompletionPromptModule,
                   tutorialStore.activeModal == nil {
                    completionPrompt(for: promptModule)
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
        tutorialStore.currentModule != nil && tab == tutorialStore.selectedTab
    }

    private var currentGuidance: TutorialGuidancePayload? {
        guard isActiveSandboxTab else { return nil }
        guard tutorialStore.activeModal == nil else { return nil }
        guard let activeModule = tutorialStore.currentModule else { return nil }
        guard !tutorialStore.isCompleted(activeModule) else { return nil }

        return TutorialGuidanceResolver().guidance(
            session: tutorialStore.session,
            navigation: tutorialStore.navigation,
            sizeClass: sizeClass,
            selectedTab: tab
        )
    }

    private var visibleCompletionPromptModule: TutorialModuleID? {
        guard isActiveSandboxTab else { return nil }
        guard let promptModule = tutorialStore.pendingCompletionPromptModule else { return nil }
        guard tutorialStore.currentModule == promptModule else { return nil }
        return promptModule
    }

    #if os(macOS)
    private var macOSTopChrome: some View {
        HStack {
            Button {
                tutorialStore.returnToOverview()
            } label: {
                Label(
                    String(localized: "guidedTutorial.returnToOverview", defaultValue: "Return to Tutorial Overview"),
                    systemImage: "chevron.left.circle.fill"
                )
                .font(.subheadline.weight(.semibold))
            }
            .buttonStyle(.bordered)
            .tint(.orange)

            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(.bar)
    }
    #endif

    @ViewBuilder
    private func completionPrompt(for module: TutorialModuleID) -> some View {
        if horizontalSizeClass == .compact {
            compactCompletionPrompt(for: module)
        } else {
            regularCompletionPrompt(for: module)
        }
    }

    private func compactCompletionPrompt(for module: TutorialModuleID) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(module.title)
                .font(.headline)

            Text(completionMessage(for: module))
                .font(.subheadline)
                .foregroundStyle(.secondary)

            HStack(spacing: 10) {
                Button(primaryPromptButtonTitle(for: module)) {
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

    private func regularCompletionPrompt(for module: TutorialModuleID) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(module.title)
                .font(.headline)

            Text(completionMessage(for: module))
                .font(.subheadline)
                .foregroundStyle(.secondary)

            HStack(spacing: 10) {
                Button(primaryPromptButtonTitle(for: module)) {
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

    private func primaryPromptButtonTitle(for module: TutorialModuleID) -> String {
        if module == .enableHighSecurity {
            return String(localized: "guidedTutorial.reviewCompletion", defaultValue: "Review Completion")
        }
        return String(localized: "guidedTutorial.returnToOverview", defaultValue: "Return to Tutorial Overview")
    }

    private func completionMessage(for module: TutorialModuleID) -> String {
        if module == .enableHighSecurity {
            return String(localized: "guidedTutorial.task.complete.final", defaultValue: "All modules are complete. Review the completion summary before you finish the tutorial.")
        }
        return String(localized: "guidedTutorial.task.complete", defaultValue: "Task complete. Return to the tutorial overview to continue.")
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
