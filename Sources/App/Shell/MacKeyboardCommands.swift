#if os(macOS)
import SwiftUI

/// macOS menu commands: the in-window About item, key actions in the Keys
/// menu, and sidebar tab selection (⌘1–⌘8) in the View menu.
struct MacKeyboardCommands: Commands {
    let navigationState: MacShellNavigationState

    var body: some Commands {
        // Keep File > New Window disabled: CypherAir uses a single-window
        // design; multiple windows would create independent privacy screen
        // states leading to inconsistent security behavior.
        CommandGroup(replacing: .newItem) { }

        // The standard About panel would open a second window; the
        // single-window design routes About into the main window instead,
        // matching how ⌘, selects the Settings tab.
        CommandGroup(replacing: .appInfo) {
            Button(String(
                localized: "menu.about",
                defaultValue: "About \(AppProductIdentity.localizedDisplayName)"
            )) {
                navigationState.selectedTab = .settings
                navigationState.setPath([.about], for: .settings)
            }
        }

        // Key actions live in their own menu; the single-window design leaves
        // no default File > New group to host them.
        CommandMenu(AppShellComposition.title(for: .keys)) {
            Button(String(localized: "menu.newKey", defaultValue: "New Key…")) {
                openOnKeysTab(.keyGeneration)
            }
            .keyboardShortcut("n", modifiers: .command)

            Button(String(localized: "menu.importKey", defaultValue: "Import Key…")) {
                openOnKeysTab(.importKey)
            }
            .keyboardShortcut("n", modifiers: [.command, .shift])
        }

        CommandGroup(after: .sidebar) {
            Divider()
            ForEach(Array(AppShellTab.allCases.enumerated()), id: \.element) { index, tab in
                Button(AppShellComposition.title(for: tab)) {
                    navigationState.selectedTab = tab
                }
                .keyboardShortcut(KeyEquivalent(Character("\(index + 1)")), modifiers: .command)
            }
        }
    }

    private func openOnKeysTab(_ route: AppRoute) {
        navigationState.selectedTab = .keys
        navigationState.setPath([route], for: .keys)
    }
}
#endif
