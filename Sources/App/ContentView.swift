import SwiftUI

/// Root view with TabView for main navigation.
/// Liquid Glass: TabView auto-adopts floating glass capsule — no manual styling needed.
struct ContentView: View {
    @Environment(\.horizontalSizeClass) private var sizeClass

    @State private var selectedTab: AppShellTab = .home

    var body: some View {
        let definitions = AppShellComposition.definitions(
            resolver: .production
        )
        let primaryTabs = definitions.filter { $0.section == .primary }
        let toolTabs = definitions.filter { $0.section == .tools }

        TabView(selection: $selectedTab) {
            ForEach(primaryTabs) { definition in
                SwiftUI.Tab(
                    definition.title,
                    systemImage: definition.systemImage,
                    value: definition.tab
                ) {
                    definition.content
                }
            }

            TabSection(String(localized: "tab.section.tools", defaultValue: "Tools")) {
                ForEach(toolTabs) { definition in
                    SwiftUI.Tab(
                        definition.title,
                        systemImage: definition.systemImage,
                        value: definition.tab
                    ) {
                        definition.content
                    }
                }
            }
            .hidden(sizeClass == .compact)
        }
        .tabViewStyle(.sidebarAdaptable)
        .onChange(of: sizeClass) { _, newSizeClass in
            selectedTab = AppShellComposition.normalizedSelection(
                selectedTab,
                sizeClass: newSizeClass
            )
        }
    }
}
