import SwiftUI

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
    @Environment(AppSettingsCoordinator.self) private var appSettings

    let navigationState: MacShellNavigationState

    var body: some View {
        @Bindable var navigationState = navigationState

        NavigationSplitView(
            columnVisibility: $navigationState.columnVisibility,
            preferredCompactColumn: $navigationState.preferredCompactColumn
        ) {
            List(selection: $navigationState.selection) {
                Section {
                    ForEach(AppShellTab.allCases, id: \.self) { tab in
                        sidebarRow(.tab(tab))
                    }
                }

                Section(String(localized: "tab.section.tools", defaultValue: "Tools")) {
                    ForEach(AppTool.allCases, id: \.self) { tool in
                        sidebarRow(.tool(tool))
                    }
                }
            }
            .navigationTitle(AppProductIdentity.localizedDisplayName)
        } detail: {
            detailContent(for: navigationState.selection)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .screenReady("main.ready")
        .macPresentationHost($navigationState.activePresentation)
        .task {
            presentOnboardingIfNeeded()
        }
        .onChange(of: appSettings.snapshot) { _, _ in
            presentOnboardingIfNeeded()
        }
    }

    private func presentOnboardingIfNeeded() {
        guard appSettings.hasCompletedOnboarding == false,
              navigationState.activePresentation == nil else {
            return
        }
        navigationState.activePresentation = .onboarding(initialPage: 0)
    }

    private func sidebarRow(_ item: MacSidebarItem) -> some View {
        Label(item.title, systemImage: item.systemImage)
            .tag(item)
            .accessibilityIdentifier("sidebar.\(item.identifier)")
    }

    @ViewBuilder
    private func detailContent(for item: MacSidebarItem) -> some View {
        // Per-item identity (.id below) gives each sidebar destination its own
        // NavigationStack instance, and the binding ignores writes made once
        // the item is no longer selected — the outgoing stack clears its path
        // during teardown, which would otherwise erase the stored navigation
        // on every switch.
        AppRouteHost(
            resolver: macRouteResolver(for: item),
            path: Binding(
                get: { navigationState.path(for: item) },
                set: { newPath in
                    guard navigationState.selection == item else { return }
                    navigationState.setPath(newPath, for: item)
                }
            )
        ) {
            switch item {
            case .tab(.home):
                HomeView()
            case .tab(.keys):
                MyKeysView()
            case .tab(.contacts):
                ContactsView()
            case .tab(.settings):
                SettingsView()
            case .tool(.encrypt):
                EncryptView()
            case .tool(.decrypt):
                DecryptView()
            case .tool(.sign):
                SignView()
            case .tool(.verify):
                VerifyView()
            }
        }
        .id(item)
    }

    private func macRouteResolver(for item: MacSidebarItem) -> AppRouteDestinationResolver {
        AppRouteDestinationResolver { route in
            switch route {
            case .keyGeneration:
                AnyView(
                    KeyGenerationView(
                        configuration: KeyGenerationView.Configuration(
                            postGenerationBehavior: .externalPrompt,
                            onPostGenerationPromptRequested: { identity in
                                navigationState.push(.postGenerationPrompt(identity: identity), for: item)
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
