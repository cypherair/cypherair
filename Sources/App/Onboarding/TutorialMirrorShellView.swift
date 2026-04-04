import SwiftUI

@MainActor
struct TutorialMirrorShellView: View {
    @Environment(TutorialSessionStore.self) private var tutorialStore
    @Environment(\.horizontalSizeClass) private var sizeClass

    var body: some View {
        if let container = tutorialStore.container {
            TutorialShellTabsView(
                selectedTab: selectedTabBinding,
                routePath: routePathBinding,
                sizeClass: sizeClass
            )
            .environment(tutorialStore)
            .environment(container.config)
            .environment(container.keyManagement)
            .environment(container.contactService)
            .environment(container.encryptionService)
            .environment(container.decryptionService)
            .environment(container.signingService)
            .environment(container.qrService)
            .environment(container.selfTestService)
            .environment(container.authManager)
            .onAppear {
                tutorialStore.noteVisibleSurface(
                    tab: tutorialStore.selectedTab,
                    route: tutorialStore.routePath.last
                )
            }
            .sheet(item: activeModalBinding) { modal in
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
                case .postGenerationPrompt(let identity):
                    AppRouteHost(resolver: routeResolver(for: tutorialStore.selectedTab)) {
                        PostGenerationPromptView(identity: identity)
                    }
                case .authModeConfirmation(let request):
                    NavigationStack {
                        TutorialAuthModeConfirmationView(request: request)
                    }
                    #if canImport(UIKit)
                    .presentationDetents([.medium, .large])
                    #endif
                }
            }
        } else {
            ContentUnavailableView {
                Label(
                    String(localized: "guidedTutorial.title", defaultValue: "Guided Tutorial"),
                    systemImage: "testtube.2"
                )
            } description: {
                Text(tutorialStore.errorMessage ?? String(localized: "guidedTutorial.error.defaults", defaultValue: "Could not prepare the sandbox tutorial environment."))
            } actions: {
                Button(String(localized: "common.done", defaultValue: "Done")) {
                    tutorialStore.dismissShell()
                }
            }
        }
    }

    private var selectedTabBinding: Binding<AppShellTab> {
        Binding(
            get: { tutorialStore.selectedTab },
            set: { tutorialStore.selectTab($0) }
        )
    }

    private var routePathBinding: Binding<[AppRoute]> {
        Binding(
            get: { tutorialStore.routePath },
            set: { tutorialStore.setRoutePath($0) }
        )
    }

    private var activeModalBinding: Binding<TutorialModal?> {
        Binding(
            get: { tutorialStore.activeModal },
            set: { if $0 == nil { tutorialStore.dismissModal() } }
        )
    }

    private func routeResolver(for selectedTab: AppShellTab) -> AppRouteDestinationResolver {
        AppRouteDestinationResolver { route in
            AnyView(
                TutorialRouteDestinationView(
                    route: route,
                    selectedTab: selectedTab,
                    sizeClass: sizeClass
                )
            )
        }
    }
}

@MainActor
private struct TutorialShellTabsView: View {
    @Environment(TutorialSessionStore.self) private var tutorialStore

    @Binding var selectedTab: AppShellTab
    @Binding var routePath: [AppRoute]
    let sizeClass: UserInterfaceSizeClass?

    var body: some View {
        if sizeClass == .compact {
            AnyView(compactLayout)
        } else {
            AnyView(regularLayout)
        }
    }

    private var currentGuidance: TutorialGuidance? {
        if tutorialStore.activeModal != nil {
            return nil
        }
        if let activeTask = tutorialStore.session.activeTask,
           tutorialStore.isCompleted(activeTask) {
            return nil
        }

        return tutorialStore.guidance(
            sizeClass: sizeClass,
            selectedTab: selectedTab
        )
    }

    private var compactLayout: some View {
        VStack(spacing: 0) {
            compactTabBar
            Divider()
            compactReturnBar
            Divider()
            if let currentGuidance {
                compactGuidanceBanner(currentGuidance)
                Divider()
            }
            tabRoot(for: selectedTab)
        }
        .overlay {
            TutorialSpotlightOverlay(target: currentGuidance?.target)
        }
    }

    private var regularLayout: some View {
        HStack(spacing: 0) {
            sidebar
            Divider()
            tabRoot(for: selectedTab)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .overlay {
            TutorialSpotlightOverlay(target: currentGuidance?.target)
        }
        .safeAreaInset(edge: .trailing) {
            if let currentGuidance {
                guidanceCard(currentGuidance)
            }
        }
    }

    private var compactTabBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 10) {
                compactTabButton(.home)
                compactTabButton(.keys)
                compactTabButton(.contacts)
                compactTabButton(.settings)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
        }
        .background(.bar)
    }

    private var sidebar: some View {
        #if os(macOS)
        List(selection: $selectedTab) {
            Section {
                sidebarLink(.home)
                sidebarLink(.keys)
                sidebarLink(.contacts)
                sidebarLink(.settings)
            }

            Section(String(localized: "tab.section.tools", defaultValue: "Tools")) {
                sidebarLink(.encrypt)
                sidebarLink(.decrypt)
            }
        }
        .frame(minWidth: 220, idealWidth: 240, maxWidth: 260)
        #else
        List {
            Section {
                sidebarLink(.home)
                sidebarLink(.keys)
                sidebarLink(.contacts)
                sidebarLink(.settings)
            }

            Section(String(localized: "tab.section.tools", defaultValue: "Tools")) {
                sidebarLink(.encrypt)
                sidebarLink(.decrypt)
            }
        }
        .frame(minWidth: 220, idealWidth: 240, maxWidth: 260)
        #endif
    }

    private func compactTabButton(_ tab: AppShellTab) -> some View {
        Group {
            if selectedTab == tab {
                Button {
                    selectedTab = tab
                } label: {
                    Label(
                        AppShellComposition.title(for: tab),
                        systemImage: AppShellComposition.systemImage(for: tab)
                    )
                    .lineLimit(1)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                }
                .buttonStyle(.borderedProminent)
            } else {
                Button {
                    selectedTab = tab
                } label: {
                    Label(
                        AppShellComposition.title(for: tab),
                        systemImage: AppShellComposition.systemImage(for: tab)
                    )
                    .lineLimit(1)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                }
                .buttonStyle(.bordered)
            }
        }
    }

    private func sidebarLink(_ tab: AppShellTab) -> some View {
        Button {
            selectedTab = tab
        } label: {
            Label(
                AppShellComposition.title(for: tab),
                systemImage: AppShellComposition.systemImage(for: tab)
            )
        }
        .buttonStyle(.plain)
        .tag(tab)
    }

    private var routeResolver: AppRouteDestinationResolver {
        AppRouteDestinationResolver { route in
            AnyView(TutorialRouteDestinationView(route: route, selectedTab: selectedTab, sizeClass: sizeClass))
        }
    }

    private func tabRoot(for tab: AppShellTab) -> AnyView {
        switch (tutorialStore.session.activeTask, tab) {
        case (.composeAndEncryptMessage?, .encrypt) where sizeClass != .compact:
            return AnyView(
                AppRouteHost(resolver: routeResolver, path: $routePath) {
                    TutorialSurfaceView(tab: tab, route: nil) {
                        TutorialTaskHostView(task: .composeAndEncryptMessage) {
                            EncryptView(configuration: tutorialStore.encryptConfiguration())
                        }
                    }
                }
            )
        case (.parseRecipients?, .decrypt) where sizeClass != .compact:
            return AnyView(
                AppRouteHost(resolver: routeResolver, path: $routePath) {
                    TutorialSurfaceView(tab: tab, route: nil) {
                        TutorialTaskHostView(task: .parseRecipients) {
                            DecryptView(configuration: tutorialStore.decryptConfiguration(for: .parseRecipients))
                        }
                    }
                }
            )
        case (.decryptMessage?, .decrypt) where sizeClass != .compact:
            return AnyView(
                AppRouteHost(resolver: routeResolver, path: $routePath) {
                    TutorialSurfaceView(tab: tab, route: nil) {
                        TutorialTaskHostView(task: .decryptMessage) {
                            DecryptView(configuration: tutorialStore.decryptConfiguration(for: .decryptMessage))
                        }
                    }
                }
            )
        case (.enableHighSecurity?, .settings):
            return AnyView(
                AppRouteHost(resolver: routeResolver, path: $routePath) {
                    TutorialSurfaceView(tab: tab, route: nil) {
                        TutorialSettingsTaskView()
                    }
                }
            )
        default:
            return defaultRoot(for: tab)
        }
    }

    private func defaultRoot(for tab: AppShellTab) -> AnyView {
        switch tab {
        case .home:
            return AnyView(
                TutorialSurfaceView(tab: tab, route: nil) {
                    AppRouteHost(resolver: routeResolver, path: $routePath) {
                        HomeView()
                    }
                }
            )
        case .keys:
            return AnyView(
                TutorialSurfaceView(tab: tab, route: nil) {
                    AppRouteHost(resolver: routeResolver, path: $routePath) {
                        MyKeysView()
                    }
                }
            )
        case .contacts:
            return AnyView(
                TutorialSurfaceView(tab: tab, route: nil) {
                    AppRouteHost(resolver: routeResolver, path: $routePath) {
                        ContactsView()
                    }
                }
            )
        case .settings:
            return AnyView(
                TutorialSurfaceView(tab: tab, route: nil) {
                    AppRouteHost(resolver: routeResolver, path: $routePath) {
                        SettingsView()
                    }
                }
            )
        case .encrypt:
            return AnyView(
                TutorialSurfaceView(tab: tab, route: nil) {
                    AppRouteHost(resolver: routeResolver, path: $routePath) {
                        EncryptView()
                    }
                }
            )
        case .decrypt:
            return AnyView(
                TutorialSurfaceView(tab: tab, route: nil) {
                    AppRouteHost(resolver: routeResolver, path: $routePath) {
                        DecryptView()
                    }
                }
            )
        case .sign:
            return AnyView(
                TutorialSurfaceView(tab: tab, route: nil) {
                    AppRouteHost(resolver: routeResolver, path: $routePath) {
                        SignView()
                    }
                }
            )
        case .verify:
            return AnyView(
                TutorialSurfaceView(tab: tab, route: nil) {
                    AppRouteHost(resolver: routeResolver, path: $routePath) {
                        VerifyView()
                    }
                }
            )
        }
    }

    private func guidanceCard(_ guidance: TutorialGuidance) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label(
                    String(localized: "guidedTutorial.sandbox.badge", defaultValue: "Sandbox"),
                    systemImage: "testtube.2"
                )
                .font(.caption.weight(.semibold))
                .foregroundStyle(.orange)

                Spacer()

                Button(String(localized: "guidedTutorial.return", defaultValue: "Return to Tutorial")) {
                    tutorialStore.dismissShell()
                }
                .buttonStyle(.bordered)
            }

            Text(guidance.title)
                .font(.headline)
            Text(guidance.body)
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: sizeClass == .compact ? .infinity : 280, alignment: .leading)
        .padding(16)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private func compactGuidanceBanner(_ guidance: TutorialGuidance) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(
                String(localized: "guidedTutorial.sandbox.badge", defaultValue: "Sandbox"),
                systemImage: "testtube.2"
            )
            .font(.caption2.weight(.semibold))
            .foregroundStyle(.orange)

            Text(guidance.title)
                .font(.subheadline.weight(.semibold))

            Text(guidance.body)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(.regularMaterial)
    }

    private var compactReturnBar: some View {
        HStack {
            Button {
                tutorialStore.dismissShell()
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
}

@MainActor
private struct TutorialRouteDestinationView: View {
    @Environment(TutorialSessionStore.self) private var tutorialStore

    let route: AppRoute
    let selectedTab: AppShellTab
    let sizeClass: UserInterfaceSizeClass?

    var body: some View {
        destination
    }

    private var destination: AnyView {
        switch route {
        case .keyGeneration:
            AnyView(
                TutorialSurfaceView(tab: selectedTab, route: route) {
                    if tutorialStore.session.activeTask == .generateAliceKey {
                        TutorialTaskHostView(task: .generateAliceKey) {
                            KeyGenerationView(configuration: tutorialStore.keyGenerationConfiguration())
                        }
                    } else {
                        KeyGenerationView()
                    }
                }
            )
        case .addContact:
            AnyView(
                TutorialSurfaceView(tab: selectedTab, route: route) {
                    if tutorialStore.session.activeTask == .importBobKey {
                        TutorialTaskHostView(task: .importBobKey) {
                            AddContactView(configuration: tutorialStore.addContactConfiguration())
                        }
                    } else {
                        AddContactView()
                    }
                }
            )
        case .encrypt:
            AnyView(
                TutorialSurfaceView(tab: selectedTab, route: route) {
                    if tutorialStore.session.activeTask == .composeAndEncryptMessage {
                        TutorialTaskHostView(task: .composeAndEncryptMessage) {
                            EncryptView(configuration: tutorialStore.encryptConfiguration())
                        }
                    } else {
                        EncryptView()
                    }
                }
            )
        case .decrypt:
            AnyView(
                TutorialSurfaceView(tab: selectedTab, route: route) {
                    if tutorialStore.session.activeTask == .parseRecipients {
                        TutorialTaskHostView(task: .parseRecipients) {
                            DecryptView(configuration: tutorialStore.decryptConfiguration(for: .parseRecipients))
                        }
                    } else if tutorialStore.session.activeTask == .decryptMessage {
                        TutorialTaskHostView(task: .decryptMessage) {
                            DecryptView(configuration: tutorialStore.decryptConfiguration(for: .decryptMessage))
                        }
                    } else {
                        DecryptView()
                    }
                }
            )
        case .backupKey(let fingerprint):
            AnyView(
                TutorialSurfaceView(tab: selectedTab, route: route) {
                    if tutorialStore.session.activeTask == .exportBackup {
                        TutorialTaskHostView(task: .exportBackup) {
                            BackupKeyView(
                                fingerprint: fingerprint,
                                configuration: tutorialStore.backupConfiguration()
                            )
                        }
                    } else {
                        BackupKeyView(fingerprint: fingerprint)
                    }
                }
            )
        case .keyDetail(let fingerprint):
            AnyView(TutorialSurfaceView(tab: selectedTab, route: route) { KeyDetailView(fingerprint: fingerprint) })
        case .contactDetail(let fingerprint):
            AnyView(TutorialSurfaceView(tab: selectedTab, route: route) { ContactDetailView(fingerprint: fingerprint) })
        case .qrDisplay(let publicKeyData, let displayName):
            AnyView(TutorialSurfaceView(tab: selectedTab, route: route) { QRDisplayView(publicKeyData: publicKeyData, displayName: displayName) })
        case .qrPhotoImport:
            AnyView(TutorialSurfaceView(tab: selectedTab, route: route) { QRPhotoImportView() })
        case .importKey:
            AnyView(TutorialSurfaceView(tab: selectedTab, route: route) { ImportKeyView() })
        case .sign:
            AnyView(TutorialSurfaceView(tab: selectedTab, route: route) { SignView() })
        case .verify:
            AnyView(TutorialSurfaceView(tab: selectedTab, route: route) { VerifyView() })
        case .selfTest:
            AnyView(TutorialSurfaceView(tab: selectedTab, route: route) { SelfTestView() })
        case .about:
            AnyView(TutorialSurfaceView(tab: selectedTab, route: route) { AboutView() })
        case .license:
            AnyView(TutorialSurfaceView(tab: selectedTab, route: route) { LicenseListView() })
        case .appIcon:
            AnyView(
                TutorialSurfaceView(tab: selectedTab, route: route) {
                    #if canImport(UIKit)
                    AppIconPickerView()
                    #else
                    Text(String(localized: "common.comingSoon", defaultValue: "Coming soon"))
                    #endif
                }
            )
        case .themePicker:
            AnyView(TutorialSurfaceView(tab: selectedTab, route: route) { ThemePickerView() })
        }
    }
}

@MainActor
private struct TutorialSurfaceView<Content: View>: View {
    @Environment(TutorialSessionStore.self) private var tutorialStore

    let tab: AppShellTab
    let route: AppRoute?
    @ViewBuilder let content: () -> Content

    var body: some View {
        content()
            .onAppear {
                tutorialStore.noteVisibleSurface(tab: tab, route: route)
            }
    }
}

@MainActor
private struct TutorialSettingsTaskView: View {
    @Environment(TutorialSessionStore.self) private var tutorialStore
    @Environment(AppConfiguration.self) private var config

    var body: some View {
        TutorialTaskHostView(task: .enableHighSecurity) {
            SettingsView(configuration: tutorialStore.settingsConfiguration())
                .onChange(of: config.authMode) { _, newMode in
                    if newMode == .highSecurity {
                        tutorialStore.noteHighSecurityEnabled(newMode)
                    }
                }
        }
    }
}

@MainActor
private struct TutorialAuthModeConfirmationView: View {
    @Environment(TutorialSessionStore.self) private var tutorialStore

    let request: AuthModeChangeConfirmationRequest
    @State private var riskAcknowledged = false

    var body: some View {
        Form {
            Section {
                Text(request.message)
                    .font(.callout)
            }

            if request.requiresRiskAcknowledgement {
                Section {
                    Toggle(isOn: $riskAcknowledged) {
                        Text(String(localized: "settings.mode.riskAck", defaultValue: "I understand that if biometrics become unavailable, I will lose access to my private keys"))
                            .font(.callout)
                    }
                }
            }

            Section {
                Button(String(localized: "settings.mode.confirm", defaultValue: "Switch Mode"), role: .destructive) {
                    tutorialStore.dismissModal()
                    request.onConfirm()
                }
                .disabled(request.requiresRiskAcknowledgement && !riskAcknowledged)
                .frame(maxWidth: .infinity)
            }
        }
        .navigationTitle(request.title)
        #if canImport(UIKit)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button(String(localized: "common.cancel", defaultValue: "Cancel")) {
                    tutorialStore.dismissModal()
                    request.onCancel()
                }
            }
        }
    }
}
