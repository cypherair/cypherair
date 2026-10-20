import SwiftUI

/// The app's four sections: the tab bar on iOS and visionOS in every size
/// class, and the first sidebar group on macOS.
enum AppShellTab: String, Hashable, CaseIterable {
    case home
    case keys
    case contacts
    case settings

    var title: String {
        switch self {
        case .home:
            String(localized: "tab.home", defaultValue: "Home")
        case .keys:
            String(localized: "tab.keys", defaultValue: "Keys")
        case .contacts:
            String(localized: "tab.contacts", defaultValue: "Contacts")
        case .settings:
            String(localized: "tab.settings", defaultValue: "Settings")
        }
    }

    var systemImage: String {
        switch self {
        case .home:
            "house"
        case .keys:
            "key"
        case .contacts:
            "person.2"
        case .settings:
            "gearshape"
        }
    }
}

/// The four message tools. On iOS and visionOS they are routes pushed from
/// Home's buttons and appear nowhere else; the macOS sidebar lists them as
/// its second group.
enum AppTool: String, Hashable, CaseIterable {
    case encrypt
    case decrypt
    case sign
    case verify

    var title: String {
        switch self {
        case .encrypt:
            String(localized: "home.encrypt", defaultValue: "Encrypt")
        case .decrypt:
            String(localized: "home.decrypt", defaultValue: "Decrypt")
        case .sign:
            String(localized: "home.sign", defaultValue: "Sign")
        case .verify:
            String(localized: "home.verify", defaultValue: "Verify")
        }
    }

    var systemImage: String {
        switch self {
        case .encrypt:
            "lock.fill"
        case .decrypt:
            "lock.open.fill"
        case .sign:
            "signature"
        case .verify:
            "checkmark.seal"
        }
    }

    var route: AppRoute {
        switch self {
        case .encrypt:
            .encrypt
        case .decrypt:
            .decrypt
        case .sign:
            .sign
        case .verify:
            .verify
        }
    }
}

struct AppShellTabDefinition: Identifiable {
    let tab: AppShellTab
    let content: AnyView

    var id: AppShellTab { tab }
}
