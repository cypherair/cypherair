import SwiftUI

enum TutorialPresentationContext {
    case onboardingFirstRun
    case inApp
}

struct TutorialView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.iosPresentationController) private var iosPresentationController
    @Environment(AppConfiguration.self) private var config
    #if os(macOS)
    @Environment(TutorialPresentationCoordinator.self) private var tutorialPresentationCoordinator
    #endif

    let presentationContext: TutorialPresentationContext
    let initialTask: TutorialTaskID?
    let onTutorialFinished: (@MainActor () -> Void)?

    @State private var lifecycleModel: TutorialLifecycleModel
    @State private var hasPreparedPresentation = false

    @State private var identityName = "Alice Demo"
    @State private var identityEmail = "alice@demo.invalid"
    @State private var encryptDraft = String(
        localized: "tutorial.encrypt.prefill",
        defaultValue: "Hi Bob, this is a safe tutorial message from Alice."
    )
    @State private var backupPassphrase = "demo-backup-passphrase"
    @State private var backupPassphraseConfirmation = "demo-backup-passphrase"

    init(
        presentationContext: TutorialPresentationContext = .inApp,
        initialTask: TutorialTaskID? = nil,
        onTutorialFinished: (@MainActor () -> Void)? = nil
    ) {
        self.presentationContext = presentationContext
        self.initialTask = initialTask
        self.onTutorialFinished = onTutorialFinished
        _lifecycleModel = State(
            initialValue: TutorialLifecycleModel(
                launchOrigin: presentationContext == .onboardingFirstRun ? .onboardingFirstRun : .inApp
            )
        )
    }

    var body: some View {
        NavigationStack {
            Group {
                switch lifecycleModel.surface {
                case .hub:
                    tutorialHub
                case .workspace(let module):
                    tutorialWorkspace(module: module)
                case .completion(let kind):
                    tutorialCompletion(kind: kind)
                }
            }
            .navigationTitle(String(localized: "guidedTutorial.title", defaultValue: "Guided Tutorial"))
            #if canImport(UIKit)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(closeButtonTitle) {
                        handleCloseTapped()
                    }
                    .accessibilityIdentifier(TutorialAutomationContract.Identifier.closeButton)
                    .tutorialAnchor(.tutorialCloseButton)
                }
                #if os(macOS)
                if case .workspace = lifecycleModel.surface {
                    ToolbarItem(placement: .automatic) {
                        Button(lifecycleModel.isGuidanceRailVisible ? String(localized: "tutorial.guidance.hide", defaultValue: "Hide Guidance") : String(localized: "tutorial.guidance.show", defaultValue: "Show Guidance")) {
                            lifecycleModel.isGuidanceRailVisible.toggle()
                        }
                    }
                }
                #endif
            }
        }
        .sheet(item: activeModal) { modal in
            switch modal {
            case .leaveConfirmation:
                TutorialLeaveConfirmationSheet(
                    onContinue: {
                        lifecycleModel.dismissLeaveConfirmation()
                    },
                    onLeave: {
                        lifecycleModel.resetCurrentTutorialSession()
                        exitTutorial(finished: false)
                    }
                )
            case .authContinuation(let continuation):
                TutorialAuthExplanationSheet(
                    module: lifecycleModel.activeModule,
                    guidance: lifecycleModel.currentGuidance?.modalGuidance,
                    confirmTitle: continuation == .enableHighSecurity
                        ? String(localized: "tutorial.highSecurity.confirm", defaultValue: "Enable Tutorial High Security")
                        : String(localized: "tutorial.decrypt.confirm", defaultValue: "Continue to Decrypt"),
                    onConfirm: {
                        Task {
                            await lifecycleModel.confirmAuthContinuation()
                        }
                    },
                    onCancel: {
                        lifecycleModel.cancelAuthContinuation()
                    }
                )
            }
        }
        .task {
            guard !hasPreparedPresentation else { return }
            hasPreparedPresentation = true
            lifecycleModel.configure(appConfiguration: config)
            if let initialModule = initialModule {
                await openInitialModule(initialModule)
            }
        }
        .onChange(of: lifecycleModel.activeSession?.id.rawValue) { _, _ in
            resetDraftsForNewSession()
        }
    }

    private var activeModal: Binding<TutorialActiveModal?> {
        Binding(
            get: {
                if lifecycleModel.isLeaveConfirmationPresented {
                    return .leaveConfirmation
                }
                if let continuation = lifecycleModel.pendingAuthContinuation {
                    return .authContinuation(continuation)
                }
                return nil
            },
            set: { newValue in
                if newValue == nil {
                    if lifecycleModel.isLeaveConfirmationPresented {
                        lifecycleModel.dismissLeaveConfirmation()
                    }
                }
            }
        )
    }

    private var initialModule: TutorialModuleID? {
        guard let initialTask else { return nil }

        switch initialTask {
        case .understandSandbox:
            return TutorialModuleID.sandbox
        case .generateAliceKey:
            return TutorialModuleID.demoIdentity
        case .importBobKey:
            return TutorialModuleID.demoContact
        case .composeAndEncryptMessage:
            return TutorialModuleID.encryptMessage
        case .parseRecipients, .decryptMessage:
            return TutorialModuleID.decryptAndVerify
        case .exportBackup:
            return TutorialModuleID.backupKey
        case .enableHighSecurity:
            return TutorialModuleID.enableHighSecurity
        }
    }

    private var closeButtonTitle: String {
        switch presentationContext {
        case .onboardingFirstRun:
            String(localized: "tutorial.close", defaultValue: "Close")
        case .inApp:
            String(localized: "common.done", defaultValue: "Done")
        }
    }

    private var hubPrimaryActionTitle: String {
        if lifecycleModel.hasCompletedCurrentCoreTutorial {
            return String(localized: "tutorial.hub.replayCore", defaultValue: "Replay Core Tutorial")
        }
        if lifecycleModel.activeSession?.layer == .core,
           lifecycleModel.nextCoreModule != nil {
            return String(localized: "guidedTutorial.continue", defaultValue: "Continue")
        }
        return String(localized: "tutorial.hub.start", defaultValue: "Start Tutorial")
    }

    private var finishPrimaryActionTitle: String {
        switch presentationContext {
        case .onboardingFirstRun:
            String(localized: "guidedTutorial.complete.enterApp", defaultValue: "Start Using CypherAir")
        case .inApp:
            String(localized: "common.done", defaultValue: "Done")
        }
    }

    private var tutorialHub: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                hubSummaryCard
                coreModulesCard
                if lifecycleModel.canShowAdvancedModules {
                    advancedModulesCard
                }
            }
            .padding()
        }
        .screenReady(TutorialAutomationContract.Ready.hub)
    }

    private var hubSummaryCard: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label(
                String(localized: "guidedTutorial.sandbox.badge", defaultValue: "Sandbox"),
                systemImage: "testtube.2"
            )
            .font(.headline)
            .foregroundStyle(.orange)

            Text(String(localized: "tutorial.hub.title", defaultValue: "Learn CypherAir in an isolated tutorial workspace"))
                .font(.title2.weight(.semibold))

            Text(String(localized: "tutorial.hub.promise", defaultValue: "This tutorial uses demo data in an isolated workspace. It does not read or write your real keys, contacts, settings, files, exports, or other workspace content."))
                .foregroundStyle(.secondary)

            HStack {
                Label(String(localized: "tutorial.hub.time", defaultValue: "3 to 5 minutes"), systemImage: "clock")
                    .foregroundStyle(.secondary)
                Spacer()
                Text("\(lifecycleModel.hasCompletedCurrentCoreTutorial ? TutorialModuleID.coreModules.count : lifecycleModel.coreCompletedModules.count)/\(TutorialModuleID.coreModules.count)")
                    .font(.headline.monospacedDigit())
            }

            ProgressView(
                value: lifecycleModel.hasCompletedCurrentCoreTutorial
                    ? Double(TutorialModuleID.coreModules.count)
                    : Double(lifecycleModel.coreCompletedModules.count),
                total: Double(TutorialModuleID.coreModules.count)
            )

            HStack(spacing: 12) {
                Button(hubPrimaryActionTitle) {
                    Task {
                        await handleHubPrimaryAction()
                    }
                }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier(TutorialAutomationContract.Identifier.hubPrimaryAction)
                .tutorialAnchor(.tutorialPrimaryAction)

                if lifecycleModel.hasCompletedCurrentCoreTutorial {
                    Button(String(localized: "tutorial.hub.finish", defaultValue: "Close")) {
                        exitTutorial(finished: false)
                    }
                    .buttonStyle(.bordered)
                }
            }
        }
        .padding(20)
        .tutorialCardChrome(.hero)
    }

    private var coreModulesCard: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(String(localized: "tutorial.core.header", defaultValue: "Core Tutorial"))
                .font(.headline)

            ForEach(TutorialModuleID.coreModules) { module in
                moduleRow(module)
            }
        }
        .padding(20)
        .tutorialCardChrome(.standard)
    }

    private var advancedModulesCard: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(String(localized: "tutorial.advanced.header", defaultValue: "Advanced Modules"))
                .font(.headline)

            ForEach(TutorialModuleID.advancedModules) { module in
                moduleRow(module)
            }
        }
        .padding(20)
        .tutorialCardChrome(.standard)
    }

    private func moduleRow(_ module: TutorialModuleID) -> some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text(module.title)
                    .font(.subheadline.weight(.semibold))
                Text(module.summary)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Text(module.realAppLocationLabel)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
            }

            Spacer()

            if lifecycleModel.isModuleCompleted(module) {
                Label(String(localized: "tutorial.status.complete", defaultValue: "Completed"), systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
            } else if lifecycleModel.isModuleUnlocked(module) {
                Button(module.layer == .core && lifecycleModel.hasCompletedCurrentCoreTutorial ? String(localized: "guidedTutorial.replay", defaultValue: "Replay") : String(localized: "guidedTutorial.openTask", defaultValue: "Open")) {
                    Task {
                        await lifecycleModel.openModule(module)
                    }
                }
                .buttonStyle(.bordered)
                .accessibilityIdentifier(TutorialAutomationContract.Identifier.hubModuleButtonPrefix + module.rawValue)
            } else {
                Label(String(localized: "tutorial.status.locked", defaultValue: "Locked"), systemImage: "lock.fill")
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func tutorialWorkspace(module: TutorialModuleID) -> some View {
        Group {
            #if os(macOS)
            macWorkspace(module: module)
            #else
            workspaceColumns(module: module, showsNavigator: false)
            #endif
        }
        .screenReady(readyMarker(for: module))
    }

    #if os(macOS)
    private func macWorkspace(module: TutorialModuleID) -> some View {
        HStack(spacing: 0) {
            moduleNavigator
                .frame(width: 240)
                .background(.background.secondary)

            Divider()

            workspaceColumns(module: module, showsNavigator: true)
        }
    }
    #endif

    private func workspaceColumns(module: TutorialModuleID, showsNavigator: Bool) -> some View {
        GeometryReader { proxy in
            let useRail = shouldUseGuidanceRail(width: proxy.size.width)

            ZStack {
                if useRail {
                    HStack(alignment: .top, spacing: 20) {
                        workspaceContent(module: module)
                            .frame(maxWidth: .infinity, alignment: .leading)

                        if lifecycleModel.isGuidanceRailVisible {
                            guidanceRail(for: module)
                                .frame(width: guidanceRailWidth)
                        }
                    }
                    .padding()
                } else {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 20) {
                            workspaceContextCard(for: module)
                            workspaceContent(module: module)
                        }
                        .padding()
                    }
                }
            }
            .overlay {
                TutorialSpotlightOverlay(target: lifecycleModel.currentGuidance?.target)
            }
        }
    }

    private var moduleNavigator: some View {
        List {
            Section(String(localized: "tutorial.navigator.core", defaultValue: "Core")) {
                ForEach(TutorialModuleID.coreModules) { module in
                    Button {
                        Task {
                            await lifecycleModel.openModule(module)
                        }
                    } label: {
                        HStack {
                            Text(module.title)
                            Spacer()
                            if lifecycleModel.isModuleCompleted(module) {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundStyle(.green)
                            }
                        }
                    }
                    .buttonStyle(.plain)
                    .disabled(!lifecycleModel.isModuleUnlocked(module))
                }
            }

            Section(String(localized: "tutorial.navigator.advanced", defaultValue: "Advanced")) {
                ForEach(TutorialModuleID.advancedModules) { module in
                    Button {
                        Task {
                            await lifecycleModel.openModule(module)
                        }
                    } label: {
                        HStack {
                            Text(module.title)
                            Spacer()
                            if lifecycleModel.isModuleCompleted(module) {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundStyle(.green)
                            }
                        }
                    }
                    .buttonStyle(.plain)
                    .disabled(!lifecycleModel.isModuleUnlocked(module))
                }
            }
        }
        .listStyle(.sidebar)
    }

    private func guidanceRail(for module: TutorialModuleID) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text(String(localized: "tutorial.guidance.header", defaultValue: "Guidance"))
                    .font(.headline)
                Spacer()
                #if os(macOS)
                Button(String(localized: "tutorial.guidance.hide", defaultValue: "Hide")) {
                    lifecycleModel.isGuidanceRailVisible = false
                }
                .buttonStyle(.plain)
                #endif
            }

            workspaceContextCard(for: module)

            if let guidance = lifecycleModel.currentGuidance {
                VStack(alignment: .leading, spacing: 10) {
                    Text(guidance.detail)
                        .foregroundStyle(.secondary)
                    Text(module.mappingNote)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding(18)
        .tutorialCardChrome(.standard)
    }

    private func workspaceContextCard(for module: TutorialModuleID) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label(module.realAppLocationLabel, systemImage: "location.north.line.fill")
                    .font(.headline)
                    .foregroundStyle(.secondary)
                Spacer()
                Button(String(localized: "guidedTutorial.return", defaultValue: "Return to Tutorial")) {
                    lifecycleModel.returnToHub()
                }
                .buttonStyle(.borderless)
                .accessibilityIdentifier(TutorialAutomationContract.Identifier.returnButton)
                .tutorialAnchor(.tutorialReturnButton)
            }

            Text(module.title)
                .font(.title3.weight(.semibold))

            Text(module.summary)
                .foregroundStyle(.secondary)

            if !lifecycleModel.isGuidanceRailVisible && shouldOfferGuidanceRestore {
                Button(String(localized: "tutorial.guidance.restore", defaultValue: "Show Guidance")) {
                    lifecycleModel.isGuidanceRailVisible = true
                }
                .buttonStyle(.bordered)
                .accessibilityIdentifier(TutorialAutomationContract.Identifier.guidanceRestore)
                .tutorialAnchor(.tutorialGuidanceRestoreButton)
            }
        }
        .padding(18)
        .tutorialCardChrome(.standard)
    }

    @ViewBuilder
    private func workspaceContent(module: TutorialModuleID) -> some View {
        switch module {
        case .sandbox:
            sandboxModuleView
        case .demoIdentity:
            demoIdentityModuleView
        case .demoContact:
            demoContactModuleView
        case .encryptMessage:
            encryptModuleView
        case .decryptAndVerify:
            decryptModuleView
        case .backupKey:
            backupModuleView
        case .enableHighSecurity:
            highSecurityModuleView
        }
    }

    private var sandboxModuleView: some View {
        VStack(alignment: .leading, spacing: 18) {
            tutorialFactList(title: String(localized: "tutorial.sandbox.points", defaultValue: "What stays separate"), items: [
                String(localized: "tutorial.sandbox.fact.one", defaultValue: "No real keys or contacts are read or changed."),
                String(localized: "tutorial.sandbox.fact.two", defaultValue: "No real files, exports, share sheets, or photo imports appear here."),
                String(localized: "tutorial.sandbox.fact.three", defaultValue: "The real app still asks you to create your own real key later.")
            ])

            Button(String(localized: "tutorial.sandbox.start", defaultValue: "Start Tutorial")) {
                lifecycleModel.acknowledgeSandbox()
                lifecycleModel.returnToHub()
            }
            .buttonStyle(.borderedProminent)
            .accessibilityIdentifier(TutorialAutomationContract.Identifier.primaryAction)
            .tutorialAnchor(.tutorialPrimaryAction)
        }
        .padding(20)
        .tutorialCardChrome(.standard)
    }

    private var demoIdentityModuleView: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text(String(localized: "tutorial.identity.copy", defaultValue: "A key represents your identity. This module creates a demo identity only for the tutorial."))
                .foregroundStyle(.secondary)

            if let identity = lifecycleModel.activeSession?.artifacts.aliceIdentity {
                moduleSuccessCard(
                    title: String(localized: "tutorial.identity.success", defaultValue: "Demo identity created"),
                    body: identity.userId ?? identity.fingerprint,
                    note: TutorialModuleID.demoIdentity.mappingNote
                )
            } else {
                VStack(alignment: .leading, spacing: 14) {
                    TextField(String(localized: "tutorial.identity.name", defaultValue: "Name"), text: $identityName)
                        .textFieldStyle(.roundedBorder)
                    TextField(String(localized: "tutorial.identity.email", defaultValue: "Email"), text: $identityEmail)
                        .textFieldStyle(.roundedBorder)
                    Text(String(localized: "tutorial.identity.profile", defaultValue: "Tutorial profile: Universal"))
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Button(String(localized: "tutorial.identity.generate", defaultValue: "Create Demo Identity")) {
                        Task {
                            await lifecycleModel.createDemoIdentity(name: identityName, email: identityEmail)
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(identityName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    .accessibilityIdentifier(TutorialAutomationContract.Identifier.primaryAction)
                    .tutorialAnchor(.tutorialPrimaryAction)
                }
            }
        }
        .padding(20)
        .tutorialCardChrome(.standard)
    }

    private var demoContactModuleView: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text(String(localized: "tutorial.contact.copy", defaultValue: "Contacts store recipient public keys. This module uses tutorial-provided sample content instead of a real importer."))
                .foregroundStyle(.secondary)

            if let contact = lifecycleModel.activeSession?.artifacts.bobContact {
                moduleSuccessCard(
                    title: String(localized: "tutorial.contact.success", defaultValue: "Demo contact added"),
                    body: contact.userId ?? contact.fingerprint,
                    note: TutorialModuleID.demoContact.mappingNote
                )
            } else {
                if let sample = lifecycleModel.activeSession?.artifacts.bobArmoredPublicKey {
                    GroupBox(String(localized: "tutorial.contact.sample", defaultValue: "Sample Key Content")) {
                        Text(sample)
                            .font(.footnote.monospaced())
                            .textSelection(.enabled)
                            .lineLimit(6)
                    }
                }

                Button(String(localized: "tutorial.contact.add", defaultValue: "Add Demo Contact")) {
                    do {
                        try lifecycleModel.addDemoContact()
                    } catch {
                        lifecycleModel.errorMessage = error.localizedDescription
                    }
                }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier(TutorialAutomationContract.Identifier.primaryAction)
                .tutorialAnchor(.tutorialPrimaryAction)
            }
        }
        .padding(20)
        .tutorialCardChrome(.standard)
    }

    private var encryptModuleView: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text(String(localized: "tutorial.encrypt.copy", defaultValue: "Encryption creates protected output for a chosen recipient. The tutorial keeps that output local to this sandbox."))
                .foregroundStyle(.secondary)

            if let contact = lifecycleModel.activeSession?.artifacts.bobContact {
                Label(contact.displayName, systemImage: "person.crop.circle.badge.checkmark")
                    .foregroundStyle(.secondary)
            }

            if let ciphertext = lifecycleModel.activeSession?.artifacts.encryptedMessage {
                moduleSuccessCard(
                    title: String(localized: "tutorial.encrypt.success", defaultValue: "Demo message encrypted"),
                    body: ciphertext,
                    note: String(localized: "tutorial.encrypt.note", defaultValue: "This output stays inside the tutorial. Copy, share, and export are intentionally unavailable here.")
                )
            } else {
                TextEditor(text: $encryptDraft)
                    .frame(minHeight: 180)
                    .overlay(
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .strokeBorder(.quaternary)
                    )
                Button(String(localized: "tutorial.encrypt.action", defaultValue: "Encrypt Demo Message")) {
                    Task {
                        await lifecycleModel.encryptDemoMessage(encryptDraft)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(encryptDraft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                .accessibilityIdentifier(TutorialAutomationContract.Identifier.primaryAction)
                .tutorialAnchor(.tutorialPrimaryAction)
            }
        }
        .padding(20)
        .tutorialCardChrome(.standard)
    }

    private var decryptModuleView: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text(String(localized: "tutorial.decrypt.copy", defaultValue: "Decrypting first identifies the matching key, then unlocks the message. The real app would ask for device authentication at that point."))
                .foregroundStyle(.secondary)

            if let parseResult = lifecycleModel.activeSession?.artifacts.parseResult,
               let matchedKey = parseResult.matchedKey {
                GroupBox(String(localized: "tutorial.decrypt.match", defaultValue: "Matched Recipient")) {
                    Text(matchedKey.userId ?? matchedKey.fingerprint)
                        .font(.callout)
                }
            }

            if let plaintext = lifecycleModel.activeSession?.artifacts.decryptedMessage {
                VStack(alignment: .leading, spacing: 14) {
                    moduleSuccessCard(
                        title: String(localized: "tutorial.decrypt.success", defaultValue: "Demo message decrypted"),
                        body: plaintext,
                        note: TutorialModuleID.decryptAndVerify.mappingNote
                    )
                    if let verification = lifecycleModel.activeSession?.artifacts.decryptedVerification {
                        Label(verification.statusDescription, systemImage: verification.symbolName)
                            .foregroundStyle(verification.statusColor)
                    }
                }
            } else if lifecycleModel.activeSession?.artifacts.parseResult == nil {
                Button(String(localized: "tutorial.decrypt.inspect", defaultValue: "Inspect Recipients")) {
                    Task {
                        await lifecycleModel.inspectRecipients()
                    }
                }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier(TutorialAutomationContract.Identifier.primaryAction)
                .tutorialAnchor(.tutorialPrimaryAction)
            } else {
                Button(String(localized: "tutorial.decrypt.continue", defaultValue: "Continue to Decrypt")) {
                    lifecycleModel.beginDecryptContinuation()
                }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier(TutorialAutomationContract.Identifier.primaryAction)
                .tutorialAnchor(.tutorialPrimaryAction)
            }
        }
        .padding(20)
        .tutorialCardChrome(.standard)
    }

    private var backupModuleView: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text(String(localized: "tutorial.backup.copy", defaultValue: "Backups protect a private key with a passphrase. This module shows a tutorial-only preview instead of a real exported file."))
                .foregroundStyle(.secondary)

            if let preview = lifecycleModel.activeSession?.artifacts.backupArmoredKey {
                moduleSuccessCard(
                    title: String(localized: "tutorial.backup.success", defaultValue: "Tutorial backup created"),
                    body: preview,
                    note: TutorialModuleID.backupKey.mappingNote
                )
            } else {
                SecureField(String(localized: "tutorial.backup.passphrase", defaultValue: "Backup Passphrase"), text: $backupPassphrase)
                    .textFieldStyle(.roundedBorder)
                SecureField(String(localized: "tutorial.backup.confirm", defaultValue: "Confirm Passphrase"), text: $backupPassphraseConfirmation)
                    .textFieldStyle(.roundedBorder)
                Button(String(localized: "tutorial.backup.action", defaultValue: "Create Tutorial Backup")) {
                    Task {
                        await lifecycleModel.createTutorialBackup(passphrase: backupPassphrase)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(backupPassphrase.isEmpty || backupPassphrase != backupPassphraseConfirmation)
                .accessibilityIdentifier(TutorialAutomationContract.Identifier.primaryAction)
                .tutorialAnchor(.tutorialPrimaryAction)
            }
        }
        .padding(20)
        .tutorialCardChrome(.standard)
    }

    private var highSecurityModuleView: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text(String(localized: "tutorial.highSecurity.copy", defaultValue: "High Security removes passcode fallback in the real app. This module changes tutorial-only state after a tutorial-owned confirmation step."))
                .foregroundStyle(.secondary)

            Label(
                lifecycleModel.activeSession?.artifacts.authMode == .highSecurity
                    ? String(localized: "tutorial.highSecurity.state.enabled", defaultValue: "Tutorial mode: High Security")
                    : String(localized: "tutorial.highSecurity.state.standard", defaultValue: "Tutorial mode: Standard"),
                systemImage: "lock.shield"
            )
            .foregroundStyle(.secondary)

            if lifecycleModel.activeSession?.artifacts.authMode == .highSecurity {
                moduleSuccessCard(
                    title: String(localized: "tutorial.highSecurity.success", defaultValue: "Tutorial High Security enabled"),
                    body: String(localized: "tutorial.highSecurity.enabled", defaultValue: "This tutorial session now reflects the stricter auth mode."),
                    note: TutorialModuleID.enableHighSecurity.mappingNote
                )
            } else {
                Button(String(localized: "tutorial.highSecurity.review", defaultValue: "Review High Security Warning")) {
                    lifecycleModel.beginHighSecurityContinuation()
                }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier(TutorialAutomationContract.Identifier.primaryAction)
                .tutorialAnchor(.tutorialPrimaryAction)
            }
        }
        .padding(20)
        .tutorialCardChrome(.standard)
    }

    private func tutorialCompletion(kind: TutorialCompletionKind) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                switch kind {
                case .core:
                    coreCompletionCard
                case .module(let module):
                    advancedCompletionCard(module: module)
                }
            }
            .padding()
        }
        .screenReady(kind == .core ? TutorialAutomationContract.Ready.coreCompletion : TutorialAutomationContract.Ready.moduleCompletion)
    }

    private var coreCompletionCard: some View {
        VStack(alignment: .leading, spacing: 18) {
            Color.clear
                .frame(width: 1, height: 1)
                .accessibilityIdentifier(TutorialAutomationContract.Ready.coreCompletion)

            Label(
                String(localized: "guidedTutorial.completion.badge", defaultValue: "Tutorial Complete"),
                systemImage: "checkmark.seal.fill"
            )
            .font(.headline)
            .foregroundStyle(.green)

            Text(String(localized: "tutorial.completion.core.title", defaultValue: "You finished the core tutorial"))
                .font(.title2.weight(.semibold))

            Text(String(localized: "tutorial.completion.core.body", defaultValue: "Your real workspace is still untouched. The next real step is to create your own key in the Keys area when you are ready."))
                .foregroundStyle(.secondary)

            tutorialFactList(title: String(localized: "tutorial.completion.next", defaultValue: "Next"), items: [
                String(localized: "tutorial.completion.realKey", defaultValue: "Create your real key in the real app."),
                String(localized: "tutorial.completion.advanced", defaultValue: "Optional advanced modules are available if you want more practice.")
            ])

            HStack(spacing: 12) {
                Button(finishPrimaryActionTitle) {
                    lifecycleModel.completeCoreFinish(stayInTutorial: false)
                    if presentationContext == .onboardingFirstRun {
                        config.hasCompletedOnboarding = true
                    }
                    exitTutorial(finished: true)
                }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier(TutorialAutomationContract.Identifier.finishButton)
                .tutorialAnchor(.tutorialFinishButton)

                Button(String(localized: "tutorial.completion.exploreAdvanced", defaultValue: "Explore Advanced Skills")) {
                    lifecycleModel.completeCoreFinish(stayInTutorial: true)
                }
                .buttonStyle(.bordered)
                .accessibilityIdentifier(TutorialAutomationContract.Identifier.exploreAdvancedButton)
            }
        }
        .padding(20)
        .tutorialCardChrome(.hero)
    }

    private func advancedCompletionCard(module: TutorialModuleID) -> some View {
        VStack(alignment: .leading, spacing: 18) {
            Color.clear
                .frame(width: 1, height: 1)
                .accessibilityIdentifier(TutorialAutomationContract.Ready.moduleCompletion)

            Label(
                String(localized: "tutorial.completion.module.badge", defaultValue: "Module Complete"),
                systemImage: "checkmark.circle.fill"
            )
            .font(.headline)
            .foregroundStyle(.green)

            Text(module.title)
                .font(.title2.weight(.semibold))

            Text(module.mappingNote)
                .foregroundStyle(.secondary)

            HStack(spacing: 12) {
                Button(String(localized: "common.done", defaultValue: "Done")) {
                    lifecycleModel.finishAdvancedModule()
                    exitTutorial(finished: false)
                }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier(TutorialAutomationContract.Identifier.finishButton)
                .tutorialAnchor(.tutorialFinishButton)

                Button(String(localized: "tutorial.returnToHub", defaultValue: "Return to Hub")) {
                    lifecycleModel.finishAdvancedModule()
                }
                .buttonStyle(.bordered)
            }
        }
        .padding(20)
        .tutorialCardChrome(.hero)
    }

    private func moduleSuccessCard(title: String, body: String, note: String) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(title, systemImage: "checkmark.circle.fill")
                .font(.headline)
                .foregroundStyle(.green)
            Text(body)
                .font(.body)
                .textSelection(.enabled)
            Text(note)
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .padding(16)
        .tutorialCardChrome(.standard)
    }

    private func tutorialFactList(title: String, items: [String]) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title)
                .font(.headline)
            ForEach(items, id: \.self) { item in
                Label(item, systemImage: "checkmark")
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func handleHubPrimaryAction() async {
        if lifecycleModel.hasCompletedCurrentCoreTutorial {
            await lifecycleModel.startCoreTutorial()
            return
        }
        if let nextCoreModule = lifecycleModel.nextCoreModule,
           lifecycleModel.activeSession?.layer == .core {
            await lifecycleModel.openModule(nextCoreModule)
        } else {
            await lifecycleModel.startCoreTutorial()
        }
    }

    private func handleCloseTapped() {
        if lifecycleModel.activeSession != nil {
            lifecycleModel.requestLeaveTutorial()
        } else {
            exitTutorial(finished: false)
        }
    }

    private func openInitialModule(_ module: TutorialModuleID) async {
        switch module.layer {
        case .core:
            await lifecycleModel.startCoreTutorial()
            if module != .sandbox {
                await lifecycleModel.openModule(module)
            }
        case .advanced:
            if lifecycleModel.hasCompletedCurrentCoreTutorial {
                await lifecycleModel.openModule(module)
            }
        }
    }

    private func readyMarker(for module: TutorialModuleID) -> String {
        switch module {
        case .sandbox:
            TutorialAutomationContract.Ready.sandbox
        case .demoIdentity:
            TutorialAutomationContract.Ready.demoIdentity
        case .demoContact:
            TutorialAutomationContract.Ready.demoContact
        case .encryptMessage:
            TutorialAutomationContract.Ready.encrypt
        case .decryptAndVerify:
            TutorialAutomationContract.Ready.decrypt
        case .backupKey:
            TutorialAutomationContract.Ready.backup
        case .enableHighSecurity:
            TutorialAutomationContract.Ready.highSecurity
        }
    }

    private var guidanceRailWidth: CGFloat {
        #if os(macOS)
        320
        #else
        300
        #endif
    }

    private func shouldUseGuidanceRail(width: CGFloat) -> Bool {
        #if os(macOS)
        true
        #else
        width >= 700
        #endif
    }

    private var shouldOfferGuidanceRestore: Bool {
        #if os(macOS)
        true
        #else
        false
        #endif
    }

    private func resetDraftsForNewSession() {
        identityName = "Alice Demo"
        identityEmail = "alice@demo.invalid"
        encryptDraft = String(
            localized: "tutorial.encrypt.prefill",
            defaultValue: "Hi Bob, this is a safe tutorial message from Alice."
        )
        backupPassphrase = "demo-backup-passphrase"
        backupPassphraseConfirmation = "demo-backup-passphrase"
    }

    private func exitTutorial(finished: Bool) {
        if finished && presentationContext == .onboardingFirstRun {
            config.hasCompletedOnboarding = true
        }

        #if os(macOS)
        if tutorialPresentationCoordinator.activeMacTutorialRequest != nil {
            tutorialPresentationCoordinator.dismissMacTutorial()
            if !finished, presentationContext == .onboardingFirstRun {
                tutorialPresentationCoordinator.queueMacPresentation(.onboarding(initialPage: 2))
            }
        } else if let onTutorialFinished {
            onTutorialFinished()
        } else {
            dismiss()
        }
        #else
        switch presentationContext {
        case .onboardingFirstRun:
            iosPresentationController?.dismiss()
            if !finished {
                Task { @MainActor in
                    try? await Task.sleep(for: .milliseconds(150))
                    iosPresentationController?.present(.onboarding(initialPage: 2, context: .firstRun))
                }
            }
        case .inApp:
            if let onTutorialFinished {
                onTutorialFinished()
            } else {
                iosPresentationController?.dismiss()
                dismiss()
            }
        }
        #endif
    }
}

private enum TutorialActiveModal: Identifiable {
    case leaveConfirmation
    case authContinuation(TutorialLifecycleModel.AuthContinuation)

    var id: String {
        switch self {
        case .leaveConfirmation:
            "leave"
        case .authContinuation(let continuation):
            switch continuation {
            case .decryptMessage:
                "auth-decrypt"
            case .enableHighSecurity:
                "auth-high-security"
            }
        }
    }
}

private struct TutorialLeaveConfirmationSheet: View {
    let onContinue: () -> Void
    let onLeave: () -> Void

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 18) {
                Text(String(localized: "tutorial.leave.title", defaultValue: "Leave Tutorial?"))
                    .font(.title3.weight(.semibold))
                Text(String(localized: "tutorial.leave.body", defaultValue: "Leaving now closes the current tutorial session and discards its demo-only progress."))
                    .foregroundStyle(.secondary)
                HStack(spacing: 12) {
                    Button(String(localized: "tutorial.leave.continue", defaultValue: "Continue Tutorial")) {
                        dismiss()
                        onContinue()
                    }
                    .buttonStyle(.bordered)
                    .accessibilityIdentifier(TutorialAutomationContract.Identifier.leaveContinue)

                    Button(String(localized: "tutorial.leave.confirm", defaultValue: "Leave Tutorial"), role: .destructive) {
                        dismiss()
                        onLeave()
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier(TutorialAutomationContract.Identifier.leaveConfirm)
                }
            }
            .padding()
            .screenReady(TutorialAutomationContract.Ready.leaveConfirmation)
            .navigationTitle(String(localized: "guidedTutorial.title", defaultValue: "Guided Tutorial"))
            #if canImport(UIKit)
            .navigationBarTitleDisplayMode(.inline)
            #endif
        }
        .interactiveDismissDisabled()
    }
}

private struct TutorialAuthExplanationSheet: View {
    let module: TutorialModuleID?
    let guidance: TutorialModalGuidance?
    let confirmTitle: String
    let onConfirm: () -> Void
    let onCancel: () -> Void

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 18) {
                Text(module?.title ?? String(localized: "guidedTutorial.title", defaultValue: "Guided Tutorial"))
                    .font(.title3.weight(.semibold))

                if let guidance {
                    tutorialModalRow(
                        title: String(localized: "tutorial.modal.why", defaultValue: "Why This Modal Exists"),
                        body: guidance.whyThisExists
                    )
                    tutorialModalRow(
                        title: String(localized: "tutorial.modal.action", defaultValue: "What You Should Do"),
                        body: guidance.expectedAction
                    )
                    tutorialModalRow(
                        title: String(localized: "tutorial.modal.next", defaultValue: "What Happens Next"),
                        body: guidance.nextStep
                    )
                }

                HStack(spacing: 12) {
                    Button(String(localized: "common.cancel", defaultValue: "Cancel")) {
                        dismiss()
                        onCancel()
                    }
                    .buttonStyle(.bordered)
                    .accessibilityIdentifier(TutorialAutomationContract.Identifier.modalCancel)

                    Button(confirmTitle) {
                        dismiss()
                        onConfirm()
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier(TutorialAutomationContract.Identifier.modalConfirm)
                    .tutorialAnchor(.tutorialModalConfirmButton)
                }
            }
            .padding()
            .screenReady(TutorialAutomationContract.Ready.authModal)
            .navigationTitle(String(localized: "guidedTutorial.title", defaultValue: "Guided Tutorial"))
            #if canImport(UIKit)
            .navigationBarTitleDisplayMode(.inline)
            #endif
        }
    }

    private func tutorialModalRow(title: String, body: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.headline)
            Text(body)
                .foregroundStyle(.secondary)
        }
    }
}
