#if os(macOS)
import SwiftUI

/// macOS menu commands: key actions in the File menu and sidebar tab
/// selection (⌘1–⌘8) in the View menu.
struct MacKeyboardCommands: Commands {
    let navigationState: MacShellNavigationState

    var body: some Commands {
        // Keep File > New Window disabled: CypherAir uses a single-window
        // design; multiple windows would create independent privacy screen
        // states leading to inconsistent security behavior.
        CommandGroup(replacing: .newItem) { }

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
        guard navigationState.selectedTab != .keys else {
            navigationState.setPath([route], for: .keys)
            return
        }
        navigationState.selectedTab = .keys
        // The shared detail NavigationStack writes back an empty path while
        // its root swaps to the new tab; land the push on the next runloop
        // turn so it survives the tab switch.
        Task { @MainActor in
            navigationState.setPath([route], for: .keys)
        }
    }
}
#endif
