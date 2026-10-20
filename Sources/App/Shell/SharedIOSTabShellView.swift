import SwiftUI

/// The iOS and visionOS shell: the same four tabs in every size class, so
/// opening, folding or rotating never changes the tab set under a selection.
struct SharedIOSTabShellView: View {
    @Binding var selectedTab: AppShellTab
    let definitions: [AppShellTabDefinition]

    var body: some View {
        TabView(selection: $selectedTab) {
            ForEach(definitions) { definition in
                Tab(
                    definition.tab.title,
                    systemImage: definition.tab.systemImage,
                    value: definition.tab
                ) {
                    definition.content
                }
            }
        }
        .environment(\.appShellTabSelection, $selectedTab)
    }
}
