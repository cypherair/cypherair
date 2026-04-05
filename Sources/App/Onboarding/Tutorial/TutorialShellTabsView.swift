import SwiftUI

@MainActor
struct TutorialShellTabsView: View {
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

        return TutorialGuidanceResolver().guidance(
            session: tutorialStore.session,
            navigation: tutorialStore.navigation,
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
        let factory = tutorialStore.configurationFactory

        switch (tutorialStore.session.activeTask, tab) {
        case (.composeAndEncryptMessage?, .encrypt) where sizeClass != .compact:
            return AnyView(
                AppRouteHost(resolver: routeResolver, path: $routePath) {
                    TutorialSurfaceView(tab: tab, route: nil) {
                        TutorialTaskHostView(task: .composeAndEncryptMessage) {
                            EncryptView(configuration: factory.encryptConfiguration())
                        }
                    }
                }
            )
        case (.parseRecipients?, .decrypt) where sizeClass != .compact:
            return AnyView(
                AppRouteHost(resolver: routeResolver, path: $routePath) {
                    TutorialSurfaceView(tab: tab, route: nil) {
                        TutorialTaskHostView(task: .parseRecipients) {
                            DecryptView(configuration: factory.decryptConfiguration(for: .parseRecipients))
                        }
                    }
                }
            )
        case (.decryptMessage?, .decrypt) where sizeClass != .compact:
            return AnyView(
                AppRouteHost(resolver: routeResolver, path: $routePath) {
                    TutorialSurfaceView(tab: tab, route: nil) {
                        TutorialTaskHostView(task: .decryptMessage) {
                            DecryptView(configuration: factory.decryptConfiguration(for: .decryptMessage))
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
