import SwiftUI

enum TutorialPresentationContext {
    case onboardingFirstRun
    case inApp
}

struct TutorialView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(AppConfiguration.self) private var config
    @Environment(TutorialSessionStore.self) private var tutorialStore

    let presentationContext: TutorialPresentationContext
    let onTutorialFinished: (@MainActor () -> Void)?

    init(
        presentationContext: TutorialPresentationContext = .inApp,
        onTutorialFinished: (@MainActor () -> Void)? = nil
    ) {
        self.presentationContext = presentationContext
        self.onTutorialFinished = onTutorialFinished
    }

    @ViewBuilder
    var body: some View {
        #if canImport(UIKit)
        rootContent
            .fullScreenCover(
                isPresented: Binding(
                    get: { tutorialStore.session.isShellPresented },
                    set: { if !$0 { tutorialStore.dismissShell() } }
                )
            ) {
                TutorialMirrorShellView()
                    .environment(tutorialStore)
            }
        #else
        rootContent
            .sheet(
                isPresented: Binding(
                    get: { tutorialStore.session.isShellPresented },
                    set: { if !$0 { tutorialStore.dismissShell() } }
                )
            ) {
                TutorialMirrorShellView()
                    .environment(tutorialStore)
                    .frame(minWidth: 880, minHeight: 640)
            }
        #endif
    }

    @ViewBuilder
    private var rootContent: some View {
        if tutorialStore.isShowingCompletionView {
            completionView
        } else {
            tutorialHome
        }
    }

    private var tutorialHome: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    heroCard

                    ForEach(TutorialPhaseID.allCases) { phase in
                        phaseCard(phase)
                    }
                }
                .padding()
            }
            .navigationTitle(String(localized: "guidedTutorial.title", defaultValue: "Guided Tutorial"))
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(String(localized: "common.done", defaultValue: "Done")) {
                        dismissTutorial()
                    }
                }
            }
            .task {
                tutorialStore.ensureSession()
                tutorialStore.configurePersistence(appConfiguration: config)
            }
        }
    }

    private var heroCard: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label(
                String(localized: "guidedTutorial.sandbox.badge", defaultValue: "Sandbox"),
                systemImage: "testtube.2"
            )
            .font(.headline)
            .foregroundStyle(.orange)

            Text(String(localized: "guidedTutorial.hero.title", defaultValue: "Learn CypherAir in a real sandbox"))
                .font(.title2.weight(.semibold))

            Text(String(localized: "guidedTutorial.hero.body", defaultValue: "This guided tutorial uses the real app UI with isolated sandbox data. Your real keys, contacts, settings, exports, and files are never touched."))
                .foregroundStyle(.secondary)

            ProgressView(value: tutorialStore.session.progressValue)

            HStack(spacing: 12) {
                if let primaryActionTitle {
                    Button(primaryActionTitle) {
                        Task {
                            await handlePrimaryHeroAction()
                        }
                    }
                    .buttonStyle(.borderedProminent)
                }

                Button(String(localized: "guidedTutorial.reset", defaultValue: "Reset Tutorial")) {
                    tutorialStore.resetTutorial()
                }
                .buttonStyle(.bordered)
            }
        }
        .padding(20)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
    }

    private var completionView: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    VStack(alignment: .leading, spacing: 16) {
                        Label(
                            String(localized: "guidedTutorial.completion.badge", defaultValue: "Tutorial Complete"),
                            systemImage: "checkmark.seal.fill"
                        )
                        .font(.headline)
                        .foregroundStyle(.green)

                        Text(String(localized: "guidedTutorial.completion.title", defaultValue: "You're ready to start using CypherAir"))
                            .font(.title2.weight(.semibold))

                        Text(String(localized: "guidedTutorial.completion.body", defaultValue: "You completed the Guided Tutorial in a safe sandbox. The real app is ready for your own keys and messages, and none of the tutorial data was saved into your real workspace."))
                            .foregroundStyle(.secondary)

                        Button(completionPrimaryActionTitle) {
                            finishTutorial()
                        }
                        .buttonStyle(.borderedProminent)
                    }
                    .padding(20)
                    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 24, style: .continuous))

                    VStack(alignment: .leading, spacing: 14) {
                        Text(String(localized: "guidedTutorial.completion.next.header", defaultValue: "Next Steps"))
                            .font(.headline)

                        Label(
                            String(localized: "guidedTutorial.completion.next.realKey", defaultValue: "Create your real encryption key from the Keys tab when you're ready."),
                            systemImage: "key.horizontal"
                        )
                        .foregroundStyle(.secondary)

                        Label(
                            String(localized: "guidedTutorial.completion.next.replay", defaultValue: "You can replay the Guided Tutorial any time from Settings."),
                            systemImage: "arrow.clockwise"
                        )
                        .foregroundStyle(.secondary)
                    }
                    .padding(20)
                    .background(.background.secondary, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
                }
                .padding()
            }
            .navigationTitle(String(localized: "guidedTutorial.title", defaultValue: "Guided Tutorial"))
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(String(localized: "common.done", defaultValue: "Done")) {
                        dismissTutorial()
                    }
                }
            }
        }
    }

    private func phaseCard(_ phase: TutorialPhaseID) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(phase.title)
                .font(.headline)

            ForEach(phase.tasks) { task in
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(task.title)
                            .font(.subheadline.weight(.medium))
                        Text(taskStatusDescription(task))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }

                    Spacer()

                    if tutorialStore.isCompleted(task) {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                    } else if canOpen(task) {
                        Button(String(localized: "guidedTutorial.openTask", defaultValue: "Open")) {
                            Task {
                                await tutorialStore.openTask(task)
                            }
                        }
                        .buttonStyle(.bordered)
                    } else {
                        Image(systemName: "lock.fill")
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.vertical, 4)
            }
        }
        .padding(20)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }

    private func canOpen(_ task: TutorialTaskID) -> Bool {
        if tutorialStore.isCompleted(task) {
            return true
        }

        guard let index = TutorialTaskID.allCases.firstIndex(of: task) else { return false }
        if index == 0 {
            return true
        }
        let previousTasks = TutorialTaskID.allCases.prefix(index)
        return previousTasks.allSatisfy { tutorialStore.isCompleted($0) }
    }

    private func taskStatusDescription(_ task: TutorialTaskID) -> String {
        if tutorialStore.isCompleted(task) {
            return String(localized: "guidedTutorial.status.complete", defaultValue: "Completed in this sandbox session")
        }
        if canOpen(task) {
            return String(localized: "guidedTutorial.status.ready", defaultValue: "Ready to start")
        }
        return String(localized: "guidedTutorial.status.locked", defaultValue: "Complete earlier steps first")
    }

    private var primaryActionTitle: String? {
        if tutorialStore.session.completedCount > 0,
           tutorialStore.nextTask != nil {
            return String(localized: "guidedTutorial.continue", defaultValue: "Continue")
        }

        switch config.guidedTutorialCompletionState {
        case .neverCompleted:
            return tutorialStore.nextTask == nil ? nil : String(localized: "guidedTutorial.start", defaultValue: "Start Guided Tutorial")
        case .completedCurrentVersion:
            return String(localized: "guidedTutorial.replay", defaultValue: "Replay Guided Tutorial")
        case .completedPreviousVersion:
            return String(localized: "guidedTutorial.updated.start", defaultValue: "Start Updated Guided Tutorial")
        }
    }

    private var completionPrimaryActionTitle: String {
        switch presentationContext {
        case .onboardingFirstRun:
            String(localized: "guidedTutorial.complete.enterApp", defaultValue: "Start Using CypherAir")
        case .inApp:
            String(localized: "common.done", defaultValue: "Done")
        }
    }

    private func handlePrimaryHeroAction() async {
        if tutorialStore.session.completedCount > 0,
           let nextTask = tutorialStore.nextTask {
            let task = nextTask == .understandSandbox ? TutorialTaskID.generateAliceKey : nextTask
            await tutorialStore.openTask(task)
            return
        }

        switch config.guidedTutorialCompletionState {
        case .neverCompleted:
            await tutorialStore.openTask(.understandSandbox)
        case .completedCurrentVersion, .completedPreviousVersion:
            tutorialStore.resetTutorial()
            await tutorialStore.openTask(.understandSandbox)
        }
    }

    private func finishTutorial() {
        tutorialStore.dismissCompletionView()

        if presentationContext == .onboardingFirstRun {
            config.hasCompletedOnboarding = true
        }

        if let onTutorialFinished {
            onTutorialFinished()
        } else {
            dismiss()
        }
    }

    private func dismissTutorial() {
        tutorialStore.dismissCompletionView()
        dismiss()
    }
}
