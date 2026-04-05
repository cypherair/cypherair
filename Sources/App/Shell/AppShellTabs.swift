import SwiftUI

enum AppShellTab: String, Hashable, CaseIterable {
    case home
    case keys
    case contacts
    case settings
    case encrypt
    case decrypt
    case sign
    case verify
}

enum AppShellTabSection {
    case primary
    case tools
}

struct AppShellTabDefinition: Identifiable {
    let tab: AppShellTab
    let title: String
    let systemImage: String
    let section: AppShellTabSection
    let visibleInCompact: Bool
    let content: AnyView

    var id: AppShellTab { tab }
}
