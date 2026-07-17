import SwiftUI

/// Root view with TabView for main navigation.
/// Liquid Glass: TabView auto-adopts floating glass capsule — no manual styling needed.
struct ContentView: View {
    @State private var selectedTab: AppShellTab = .home

    var body: some View {
        SharedIOSTabShellView(
            selectedTab: $selectedTab,
            definitions: AppShellComposition.definitions(resolver: .production)
        )
    }
}

#if os(macOS)
struct MacAppShellView: View {
    @Environment(ProtectedOrdinarySettingsCoordinator.self) private var protectedOrdinarySettings

    let navigationState: MacShellNavigationState
    let opensAuthModeConfirmation: Bool

    var body: some View {
        @Bindable var navigationState = navigationState

        NavigationSplitView(
            columnVisibility: $navigationState.columnVisibility,
            preferredCompactColumn: $navigationState.preferredCompactColumn
        ) {
            List(selection: $navigationState.selectedTab) {
                Section {
                    sidebarRow(.home)
                    sidebarRow(.keys)
                    sidebarRow(.contacts)
                    sidebarRow(.settings)
                }

                Section(String(localized: "tab.section.tools", defaultValue: "Tools")) {
                    sidebarRow(.encrypt)
                    sidebarRow(.decrypt)
                    sidebarRow(.sign)
                    sidebarRow(.verify)
                }
            }
            .navigationTitle(AppProductIdentity.localizedDisplayName)
        } detail: {
            detailContent(for: navigationState.selectedTab)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .screenReady("main.ready")
        .macPresentationHost($navigationState.activePresentation)
        .task {
            presentOnboardingIfNeeded()
            presentLaunchAuthModeConfirmationIfNeeded()
        }
        .onChange(of: protectedOrdinarySettings.state) { _, _ in
            presentOnboardingIfNeeded()
        }
    }

    private func presentOnboardingIfNeeded() {
        guard protectedOrdinarySettings.hasCompletedOnboarding == false,
              navigationState.activePresentation == nil else {
            return
        }
        navigationState.activePresentation = .onboarding(initialPage: 0)
    }

    // UITest-only: auto-present the auth-mode confirmation in the main window when launched
    // with UITEST_OPEN_AUTHMODE_CONFIRMATION.
    private func presentLaunchAuthModeConfirmationIfNeeded() {
        guard opensAuthModeConfirmation,
              navigationState.activePresentation == nil else {
            return
        }
        navigationState.selectedTab = .settings
        navigationState.activePresentation = .authModeConfirmation(
            SettingsAuthModeRequestBuilder.makeLaunchPreviewRequest()
        )
    }

    private func sidebarRow(_ tab: AppShellTab) -> some View {
        Label(
            AppShellComposition.title(for: tab),
            systemImage: AppShellComposition.systemImage(for: tab)
        )
        .tag(tab)
        .accessibilityIdentifier("sidebar.\(tab.rawValue)")
    }

    @ViewBuilder
    private func detailContent(for tab: AppShellTab) -> some View {
        // Per-tab identity (.id below) gives each sidebar tab its own
        // NavigationStack instance, and the binding ignores writes made once
        // the tab is no longer selected — the outgoing stack clears its path
        // during teardown, which would otherwise erase the stored per-tab
        // navigation on every switch.
        AppRouteHost(
            resolver: macRouteResolver(for: tab),
            path: Binding(
                get: { navigationState.path(for: tab) },
                set: { newPath in
                    guard navigationState.selectedTab == tab else { return }
                    navigationState.setPath(newPath, for: tab)
                }
            )
        ) {
            switch tab {
            case .home:
                HomeView()
            case .keys:
                MyKeysView()
            case .contacts:
                ContactsView()
            case .settings:
                MainWindowSettingsRootView()
            case .encrypt:
                EncryptView()
            case .decrypt:
                DecryptView()
            case .sign:
                SignView()
            case .verify:
                VerifyView()
            }
        }
        .id(tab)
    }

    private func macRouteResolver(for tab: AppShellTab) -> AppRouteDestinationResolver {
        AppRouteDestinationResolver { route in
            switch route {
            case .keyGeneration:
                AnyView(
                    KeyGenerationView(
                        configuration: KeyGenerationView.Configuration(
                            postGenerationBehavior: .externalPrompt,
                            onPostGenerationPromptRequested: { identity in
                                navigationState.push(.postGenerationPrompt(identity: identity), for: tab)
                            }
                        )
                    )
                )
            default:
                AnyView(AppRouteDestinationView(route: route))
            }
        }
    }
}
#endif
