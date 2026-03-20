import SwiftUI

/// Root view with TabView for main navigation.
/// Liquid Glass: TabView auto-adopts floating glass capsule — no manual styling needed.
struct ContentView: View {
    @Environment(AppConfiguration.self) private var config
    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(\.horizontalSizeClass) private var sizeClass

    @State private var selectedTab: AppTab = .home

    enum AppTab: Hashable {
        case home
        case keys
        case contacts
        case settings
        // Sidebar-only tools (hidden in compact; accessible via Home on iPhone)
        case encrypt
        case decrypt
        case sign
        case verify
    }

    var body: some View {
        TabView(selection: $selectedTab) {
            SwiftUI.Tab(
                String(localized: "tab.home", defaultValue: "Home"),
                systemImage: "house",
                value: AppTab.home
            ) {
                HomeView()
            }

            SwiftUI.Tab(
                String(localized: "tab.keys", defaultValue: "Keys"),
                systemImage: "key",
                value: AppTab.keys
            ) {
                NavigationStack {
                    MyKeysView()
                }
            }

            SwiftUI.Tab(
                String(localized: "tab.contacts", defaultValue: "Contacts"),
                systemImage: "person.2",
                value: AppTab.contacts
            ) {
                NavigationStack {
                    ContactsView()
                }
            }

            SwiftUI.Tab(
                String(localized: "tab.settings", defaultValue: "Settings"),
                systemImage: "gearshape",
                value: AppTab.settings
            ) {
                NavigationStack {
                    SettingsView()
                }
            }

            TabSection(String(localized: "tab.section.tools", defaultValue: "Tools")) {
                SwiftUI.Tab(
                    String(localized: "home.encrypt", defaultValue: "Encrypt"),
                    systemImage: "lock.fill",
                    value: AppTab.encrypt
                ) {
                    NavigationStack {
                        EncryptView()
                    }
                }

                SwiftUI.Tab(
                    String(localized: "home.decrypt", defaultValue: "Decrypt"),
                    systemImage: "lock.open.fill",
                    value: AppTab.decrypt
                ) {
                    NavigationStack {
                        DecryptView()
                    }
                }

                SwiftUI.Tab(
                    String(localized: "home.sign", defaultValue: "Sign"),
                    systemImage: "signature",
                    value: AppTab.sign
                ) {
                    NavigationStack {
                        SignView()
                    }
                }

                SwiftUI.Tab(
                    String(localized: "home.verify", defaultValue: "Verify"),
                    systemImage: "checkmark.seal",
                    value: AppTab.verify
                ) {
                    NavigationStack {
                        VerifyView()
                    }
                }
            }
            .hidden(sizeClass == .compact)
        }
        .tabViewStyle(.sidebarAdaptable)
        .onChange(of: sizeClass) { _, newSizeClass in
            if newSizeClass == .compact {
                switch selectedTab {
                case .encrypt, .decrypt, .sign, .verify:
                    selectedTab = .home
                default:
                    break
                }
            }
        }
    }
}
