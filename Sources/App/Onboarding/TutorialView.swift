import SwiftUI

struct TutorialView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.iosPresentationController) private var iosPresentationController
    @Environment(\.macPresentationController) private var macPresentationController
    @Environment(AppConfiguration.self) private var config
    @Environment(TutorialSessionStore.self) private var tutorialStore

    let presentationContext: TutorialPresentationContext
    let initialModule: TutorialModuleID?
    let onTutorialFinished: (@MainActor () -> Void)?
    @State private var hasPreparedPresentation = false

    init(
        presentationContext: TutorialPresentationContext = .inApp,
        initialModule: TutorialModuleID? = nil,
        onTutorialFinished: (@MainActor () -> Void)? = nil
    ) {
        self.presentationContext = presentationContext
        self.initialModule = initialModule
        self.onTutorialFinished = onTutorialFinished
    }

    @ViewBuilder
    var body: some View {
        rootContent
            .screenReady(TutorialAutomationContract.rootReadyMarker)
            .sheet(item: activeModalBinding) { modal in
                modalView(for: modal)
            }
            .onAppear {
                tutorialStore.setTutorialPresentationActive(true)
            }
            .onDisappear {
                tutorialStore.setTutorialPresentationActive(false)
            }
            .task {
                guard !hasPreparedPresentation else { return }
                hasPreparedPresentation = true
                tutorialStore.configurePersistence(appConfiguration: config)
                tutorialStore.prepareForPresentation(launchOrigin: presentationContext)
                #if DEBUG
                if await tutorialStore.prepareUITestContactDetailSurfaceIfRequested() {
                    return
                }
                #endif
                if let initialModule {
                    await tutorialStore.openModule(initialModule)
                }
            }
    }

    @ViewBuilder
    private var rootContent: some View {
        switch tutorialStore.hostSurface {
        case .hub:
            tutorialHub
        case .sandboxAcknowledgement:
            TutorialSandboxAcknowledgementView()
        case .workspace:
            TutorialMirrorShellView()
                .environment(tutorialStore)
        case .completion:
            completionView
        }
    }

    private var tutorialHub: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    promiseCard
                    moduleMapCard
                }
                .padding()
            }
            .navigationTitle(String(localized: "guidedTutorial.title", defaultValue: "Guided Tutorial"))
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(String(localized: "common.close", defaultValue: "Close")) {
                        closeTutorial()
                    }
                }
            }
            .screenReady(TutorialAutomationContract.hubReadyMarker)
        }
    }

    private var promiseCard: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label(
                String(localized: "guidedTutorial.sandbox.badge", defaultValue: "Tutorial Sandbox"),
                systemImage: "testtube.2"
            )
            .font(.headline)
            .foregroundStyle(.orange)

            Text(String(localized: "guidedTutorial.hero.title", defaultValue: "Learn CypherAir in a real sandbox"))
                .font(.title2.weight(.semibold))

            Text(String(localized: "guidedTutorial.promise", defaultValue: "This tutorial uses isolated tutorial data in a tutorial workspace. It does not read or write your real keys, contacts, settings, files, exports, or other real workspace content."))
                .foregroundStyle(.secondary)

            HStack(spacing: 16) {
                Label(String(localized: "guidedTutorial.time", defaultValue: "4–7 min"), systemImage: "clock")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)

                Label(String(localized: "guidedTutorial.modulesCount", defaultValue: "7 modules"), systemImage: "list.number")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            ProgressView(value: tutorialStore.session.progressValue)

            HStack(spacing: 12) {
                if let primaryActionTitle {
                    Button(primaryActionTitle) {
                        Task {
                            await handlePrimaryHeroAction()
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier("tutorial.primaryAction")
                }

                if tutorialStore.session.hasStartedSession {
                    Button(String(localized: "guidedTutorial.reset", defaultValue: "Reset Tutorial")) {
                        tutorialStore.resetTutorial()
                    }
                    .buttonStyle(.bordered)
                }
            }
        }
        .padding(20)
        .tutorialCardChrome(.hero)
    }

    private var moduleMapCard: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(String(localized: "guidedTutorial.modules", defaultValue: "Tutorial Modules"))
                .font(.headline)

            ForEach(TutorialModuleID.allCases) { module in
                moduleRow(module)
            }
        }
        .padding(20)
        .tutorialCardChrome(.standard)
    }

    private func moduleRow(_ module: TutorialModuleID) -> some View {
        HStack(alignment: .top, spacing: 12) {
            statusIcon(for: module)
                .padding(.top, 2)

            VStack(alignment: .leading, spacing: 4) {
                Text(module.title)
                    .font(.subheadline.weight(.semibold))

                Text(module.detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)

                if let location = module.realAppLocation {
                    Text(location)
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(.secondary)
                }
            }

            Spacer()

            if tutorialStore.canOpen(module) {
                Button(tutorialStore.isCompleted(module) ? String(localized: "guidedTutorial.review", defaultValue: "Review") : String(localized: "guidedTutorial.openTask", defaultValue: "Open")) {
                    Task {
                        await tutorialStore.openModule(module)
                    }
                }
                .buttonStyle(.bordered)
                .accessibilityIdentifier(module.launchControlIdentifier)
            }
        }
        .padding(.vertical, 4)
    }

    private func statusIcon(for module: TutorialModuleID) -> some View {
        Group {
            if tutorialStore.isCompleted(module) {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.green)
            } else if tutorialStore.canOpen(module) {
                Image(systemName: "circle")
                    .foregroundStyle(.secondary)
            } else {
                Image(systemName: "lock.fill")
                    .foregroundStyle(.secondary)
            }
        }
        .frame(width: 20)
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
                    .tutorialCardChrome(.hero)

                    VStack(alignment: .leading, spacing: 14) {
                        Text(String(localized: "guidedTutorial.completion.next.header", defaultValue: "Next Step"))
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
                    .tutorialCardChrome(.standard)
                }
                .padding()
            }
            .navigationTitle(String(localized: "guidedTutorial.title", defaultValue: "Guided Tutorial"))
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(String(localized: "common.close", defaultValue: "Close")) {
                        closeTutorial()
                    }
                }
            }
            .screenReady(TutorialAutomationContract.completionReadyMarker)
        }
    }

    private var primaryActionTitle: String? {
        switch tutorialStore.lifecycleState {
        case .stepsCompleted:
            return String(localized: "guidedTutorial.reviewCompletion", defaultValue: "Review Completion")
        case .inProgress:
            return tutorialStore.nextModule == nil
                ? String(localized: "guidedTutorial.reviewCompletion", defaultValue: "Review Completion")
                : String(localized: "guidedTutorial.continue", defaultValue: "Continue Tutorial")
        case .notStarted, .finished:
            switch config.guidedTutorialCompletionState {
            case .neverCompleted:
                return String(localized: "guidedTutorial.start", defaultValue: "Start Guided Tutorial")
            case .completedCurrentVersion:
                return String(localized: "guidedTutorial.replay", defaultValue: "Replay Guided Tutorial")
            case .completedPreviousVersion:
                return String(localized: "guidedTutorial.updated.start", defaultValue: "Start Updated Guided Tutorial")
            }
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
        switch tutorialStore.lifecycleState {
        case .stepsCompleted:
            tutorialStore.showCompletionView()
        case .inProgress:
            if let nextModule = tutorialStore.nextModule {
                await tutorialStore.openModule(nextModule)
            } else {
                tutorialStore.showCompletionView()
            }
        case .notStarted, .finished:
            if config.guidedTutorialCompletionState != .neverCompleted {
                tutorialStore.resetTutorial()
                tutorialStore.prepareForPresentation(launchOrigin: presentationContext)
            }
            await tutorialStore.openModule(.sandbox)
        }
    }

    private func finishTutorial() {
        tutorialStore.markFinishedTutorial()
        tutorialStore.finishAndCleanupTutorial()
        dismissTutorial()
    }

    private func closeTutorial() {
        if tutorialStore.requiresLeaveConfirmation {
            tutorialStore.presentLeaveConfirmation {
                dismissTutorial()
            }
            return
        }

        tutorialStore.returnToOverview()
        dismissTutorial()
    }

    private func dismissTutorial() {
        if let iosPresentationController {
            iosPresentationController.dismiss()
        } else if let macPresentationController {
            macPresentationController.dismiss()
        } else if let onTutorialFinished {
            onTutorialFinished()
        } else {
            dismiss()
        }
    }

    private var activeModalBinding: Binding<TutorialModal?> {
        Binding(
            get: { tutorialStore.activeModal },
            set: { if $0 == nil { tutorialStore.dismissModal() } }
        )
    }

    @ViewBuilder
    private func modalView(for modal: TutorialModal) -> some View {
        switch modal {
        case .importConfirmation(let request):
            ImportConfirmView(
                keyInfo: request.keyInfo,
                detectedProfile: request.profile,
                onImportVerified: {
                    let action = request.onImportVerified
                    tutorialStore.dismissModal()
                    action()
                },
                onImportUnverified: request.allowsUnverifiedImport ? {
                    let action = request.onImportUnverified
                    tutorialStore.dismissModal()
                    action()
                } : nil,
                onCancel: {
                    let action = request.onCancel
                    tutorialStore.dismissModal()
                    action()
                }
            )
        case .authModeConfirmation(let request):
            NavigationStack {
                TutorialAuthModeConfirmationView(request: request)
            }
            #if os(macOS)
            .frame(minWidth: 500, idealWidth: 540, minHeight: 360, idealHeight: 420)
            #endif
            #if canImport(UIKit)
            .presentationDetents([.medium, .large])
            #endif
        case .leaveConfirmation(let request):
            NavigationStack {
                TutorialLeaveConfirmationView(request: request)
            }
            #if os(macOS)
            .frame(minWidth: 480, idealWidth: 520, minHeight: 260, idealHeight: 320)
            #endif
            #if canImport(UIKit)
            .presentationDetents([.medium])
            #endif
        }
    }
}
