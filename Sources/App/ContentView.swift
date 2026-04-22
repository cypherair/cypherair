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
    @Environment(AppConfiguration.self) private var config

    let tutorialLaunchRelay: MacTutorialLaunchRelay
    let tutorialHostAvailability: MacTutorialHostAvailability

    @State private var navigationState = MacShellNavigationState()

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
            .navigationTitle(String(localized: "app.name", defaultValue: "CypherAir"))
        } detail: {
            detailContent(for: navigationState.selectedTab)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .screenReady("main.ready")
        .macPresentationHost(
            $navigationState.activePresentation,
            hostMode: .mainWindow,
            tutorialLaunchRelay: tutorialLaunchRelay,
            tutorialHostAvailability: tutorialHostAvailability
        )
        .task {
            if !config.hasCompletedOnboarding,
               navigationState.activePresentation == nil {
                navigationState.activePresentation = .onboarding(initialPage: 0)
            }
        }
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
        AppRouteHost(
            resolver: macRouteResolver(for: tab),
            path: Binding(
                get: { navigationState.path(for: tab) },
                set: { navigationState.setPath($0, for: tab) }
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
