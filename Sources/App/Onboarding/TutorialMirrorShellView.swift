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
        #if os(macOS)
        AnyView(macOSLayout)
        #else
        if sizeClass == .compact {
            AnyView(compactLayout)
        } else {
            AnyView(regularLayout)
        }
        #endif
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

    #if os(macOS)
    private var macOSLayout: some View {
        NavigationSplitView {
            sidebar
        } detail: {
            tabRoot(for: selectedTab)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .inspector(isPresented: inspectorBinding) {
            if let currentGuidance {
                guidanceInspector(currentGuidance)
                    .inspectorColumnWidth(min: 260, ideal: 300, max: 360)
            }
        }
    }
    #endif

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
                sidebarSelectionRow(.home)
                sidebarSelectionRow(.keys)
                sidebarSelectionRow(.contacts)
                sidebarSelectionRow(.settings)
            }

            Section(String(localized: "tab.section.tools", defaultValue: "Tools")) {
                sidebarSelectionRow(.encrypt)
                sidebarSelectionRow(.decrypt)
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

    #if os(macOS)
    private func sidebarSelectionRow(_ tab: AppShellTab) -> some View {
        Label(
            AppShellComposition.title(for: tab),
            systemImage: AppShellComposition.systemImage(for: tab)
        )
        .tag(tab)
        .accessibilityIdentifier("tutorial.sidebar.\(tab.rawValue)")
    }
    #endif

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
        .tutorialCardChrome(.overlay)
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    #if os(macOS)
    private var inspectorBinding: Binding<Bool> {
        Binding(
            get: { tutorialStore.isInspectorPresented && currentGuidance != nil },
            set: { tutorialStore.setInspectorPresented($0) }
        )
    }

    private func guidanceInspector(_ guidance: TutorialGuidance) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(
                String(localized: "guidedTutorial.sandbox.badge", defaultValue: "Sandbox"),
                systemImage: "testtube.2"
            )
            .font(.caption.weight(.semibold))
            .foregroundStyle(.orange)

            Text(guidance.title)
                .font(.headline)

            Text(guidance.body)
                .font(.callout)
                .foregroundStyle(.secondary)

            Spacer(minLength: 0)
        }
        .padding(20)
    }
    #endif

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
        .tutorialBannerChrome()
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
        case .postGenerationPrompt(let identity):
            AnyView(
                TutorialSurfaceView(tab: selectedTab, route: route) {
                    PostGenerationPromptView(identity: identity)
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
