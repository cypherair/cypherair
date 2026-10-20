#if os(macOS)
import SwiftUI

/// macOS menu commands: the in-window About item, key actions in the Keys
/// menu, and sidebar selection (⌘1–⌘8) in the View menu.
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
                navigationState.selection = .tab(.settings)
                navigationState.setPath([.about], for: .tab(.settings))
            }
        }

        // Key actions live in their own menu; the single-window design leaves
        // no default File > New group to host them.
        CommandMenu(AppShellTab.keys.title) {
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
            ForEach(Array(MacSidebarItem.allCases.enumerated()), id: \.element) { index, item in
                Button(item.title) {
                    navigationState.selection = item
                }
                .keyboardShortcut(KeyEquivalent(Character("\(index + 1)")), modifiers: .command)
            }
        }
    }

    private func openOnKeysTab(_ route: AppRoute) {
        navigationState.selection = .tab(.keys)
        navigationState.setPath([route], for: .tab(.keys))
    }
}
#endif
