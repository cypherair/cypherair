import SwiftUI

/// Root view with TabView for main navigation.
/// Liquid Glass: TabView auto-adopts floating glass capsule — no manual styling needed.
struct ContentView: View {
    @Environment(AppConfiguration.self) private var config
    @Environment(KeyManagementService.self) private var keyManagement

    @State private var selectedTab: AppTab = .home

    enum AppTab {
        case home
        case keys
        case contacts
        case settings
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
        }
    }
}
