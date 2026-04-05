import SwiftUI

struct SharedIOSTabShellView: View {
    @Environment(\.horizontalSizeClass) private var sizeClass

    @Binding var selectedTab: AppShellTab
    let definitions: [AppShellTabDefinition]

    var body: some View {
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
