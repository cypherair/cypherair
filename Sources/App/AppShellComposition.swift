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

@MainActor
struct AppRouteDestinationResolver {
    let build: (AppRoute) -> AnyView

    func destination(for route: AppRoute) -> AnyView {
        build(route)
    }

    static let production = AppRouteDestinationResolver { route in
        AnyView(AppRouteDestinationView(route: route))
    }
}

struct AppRouteNavigator {
    let push: @MainActor (AppRoute) -> Void

    @MainActor
    func open(_ route: AppRoute) {
        push(route)
    }
}

private struct AppRouteNavigatorKey: EnvironmentKey {
    static let defaultValue = AppRouteNavigator { _ in }
}

extension EnvironmentValues {
    var appRouteNavigator: AppRouteNavigator {
        get { self[AppRouteNavigatorKey.self] }
        set { self[AppRouteNavigatorKey.self] = newValue }
    }
}

struct AppRouteHost<Root: View>: View {
    let resolver: AppRouteDestinationResolver
    private let externalPath: Binding<[AppRoute]>?
    @ViewBuilder let root: () -> Root
    @State private var path: [AppRoute] = []

    init(
        resolver: AppRouteDestinationResolver,
        path: Binding<[AppRoute]>? = nil,
        @ViewBuilder root: @escaping () -> Root
    ) {
        self.resolver = resolver
        self.externalPath = path
        self.root = root
    }

    var body: some View {
        let pathBinding = externalPath ?? $path

        return NavigationStack(path: pathBinding) {
            root()
                .navigationDestination(for: AppRoute.self) { route in
                    resolver.destination(for: route)
                }
        }
        .environment(
            \.appRouteNavigator,
            AppRouteNavigator { route in
                pathBinding.wrappedValue.append(route)
            }
        )
    }
}

struct AppRouteDestinationView: View {
    let route: AppRoute

    var body: some View {
        switch route {
        case .keyGeneration:
            KeyGenerationView()
        case .keyDetail(let fingerprint):
            KeyDetailView(fingerprint: fingerprint)
        case .backupKey(let fingerprint):
            BackupKeyView(fingerprint: fingerprint)
        case .importKey:
            ImportKeyView()
        case .contactDetail(let fingerprint):
            ContactDetailView(fingerprint: fingerprint)
        case .addContact:
            AddContactView()
        case .qrDisplay(let publicKeyData, let displayName):
            QRDisplayView(publicKeyData: publicKeyData, displayName: displayName)
        case .qrPhotoImport:
            QRPhotoImportView()
        case .encrypt:
            EncryptView()
        case .decrypt:
            DecryptView()
        case .sign:
            SignView()
        case .verify:
            VerifyView()
        case .selfTest:
            SelfTestView()
        case .about:
            AboutView()
        case .license:
            LicenseListView()
        case .appIcon:
            #if canImport(UIKit)
            AppIconPickerView()
            #else
            Text(String(localized: "common.comingSoon", defaultValue: "Coming soon"))
            #endif
        case .themePicker:
            ThemePickerView()
        }
    }
}

@MainActor
enum AppShellComposition {
    static func title(for tab: AppShellTab) -> String {
        switch tab {
        case .home:
            String(localized: "tab.home", defaultValue: "Home")
        case .keys:
            String(localized: "tab.keys", defaultValue: "Keys")
        case .contacts:
            String(localized: "tab.contacts", defaultValue: "Contacts")
        case .settings:
            String(localized: "tab.settings", defaultValue: "Settings")
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

    static func systemImage(for tab: AppShellTab) -> String {
        switch tab {
        case .home:
            "house"
        case .keys:
            "key"
        case .contacts:
            "person.2"
        case .settings:
            "gearshape"
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

    static func section(for tab: AppShellTab) -> AppShellTabSection {
        switch tab {
        case .home, .keys, .contacts, .settings:
            .primary
        case .encrypt, .decrypt, .sign, .verify:
            .tools
        }
    }

    static func visibleInCompact(_ tab: AppShellTab) -> Bool {
        section(for: tab) == .primary
    }

    static func content(
        for tab: AppShellTab,
        resolver: AppRouteDestinationResolver,
        rootDecorator: (AppShellTab, AnyView) -> AnyView = { _, root in root }
    ) -> AnyView {
        let root: AnyView

        switch tab {
        case .home:
            root = AnyView(
                AppRouteHost(resolver: resolver) {
                    HomeView()
                }
            )
        case .keys:
            root = AnyView(
                AppRouteHost(resolver: resolver) {
                    MyKeysView()
                }
            )
        case .contacts:
            root = AnyView(
                AppRouteHost(resolver: resolver) {
                    ContactsView()
                }
            )
        case .settings:
            root = AnyView(
                AppRouteHost(resolver: resolver) {
                    SettingsView()
                }
            )
        case .encrypt:
            root = AnyView(
                AppRouteHost(resolver: resolver) {
                    EncryptView()
                }
            )
        case .decrypt:
            root = AnyView(
                AppRouteHost(resolver: resolver) {
                    DecryptView()
                }
            )
        case .sign:
            root = AnyView(
                AppRouteHost(resolver: resolver) {
                    SignView()
                }
            )
        case .verify:
            root = AnyView(
                AppRouteHost(resolver: resolver) {
                    VerifyView()
                }
            )
        }

        return rootDecorator(tab, root)
    }

    static func normalizedSelection(
        _ selectedTab: AppShellTab,
        sizeClass: UserInterfaceSizeClass?
    ) -> AppShellTab {
        guard sizeClass == .compact else { return selectedTab }

        switch selectedTab {
        case .encrypt, .decrypt, .sign, .verify:
            return .home
        default:
            return selectedTab
        }
    }

    static func definitions(
        resolver: AppRouteDestinationResolver,
        rootDecorator: (AppShellTab, AnyView) -> AnyView = { _, root in root }
    ) -> [AppShellTabDefinition] {
        AppShellTab.allCases.map { tab in
            AppShellTabDefinition(
                tab: tab,
                title: title(for: tab),
                systemImage: systemImage(for: tab),
                section: section(for: tab),
                visibleInCompact: visibleInCompact(tab),
                content: content(for: tab, resolver: resolver, rootDecorator: rootDecorator)
            )
        }
    }
}
