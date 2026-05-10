import SwiftUI

struct AppRouteDestinationView: View {
    let route: AppRoute

    var body: some View {
        switch route {
        case .keyGeneration:
            KeyGenerationView()
        case .postGenerationPrompt(let identity):
            PostGenerationPromptView(identity: identity)
        case .keyDetail(let fingerprint):
            KeyDetailView(fingerprint: fingerprint)
        case .backupKey(let fingerprint):
            BackupKeyView(fingerprint: fingerprint)
        case .selectiveRevocation(let fingerprint):
            SelectiveRevocationView(fingerprint: fingerprint)
        case .importKey:
            ImportKeyView()
        case .contactDetail(let contactId):
            ContactDetailView(contactId: contactId)
        case .contactCertification(let contactId, let keyId, let intent):
            ContactCertificationDetailsView(
                contactId: contactId,
                keyId: keyId,
                intent: intent
            )
        case .contactCertificateSignatures(let fingerprint):
            ContactCertificateSignaturesView(fingerprint: fingerprint)
        case .tagManagement:
            TagManagementView()
        case .addContact:
            AddContactView()
        case .qrDisplay(let publicKeyData, let displayName):
            QRDisplayView(publicKeyData: publicKeyData, displayName: displayName)
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
        case .sourceCompliance:
            SourceComplianceView()
        case .license:
            LicenseListView()
        case .appIcon:
            #if os(iOS)
            AppIconPickerView()
            #elseif os(visionOS)
            VisionOSAppIconUnavailableView()
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
    static func definition(
        for tab: AppShellTab,
        content: AnyView
    ) -> AppShellTabDefinition {
        AppShellTabDefinition(
            tab: tab,
            title: title(for: tab),
            systemImage: systemImage(for: tab),
            section: section(for: tab),
            visibleInCompact: visibleInCompact(tab),
            content: content
        )
    }

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
                    MainWindowSettingsRootView()
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
            definition(
                for: tab,
                content: content(for: tab, resolver: resolver, rootDecorator: rootDecorator)
            )
        }
    }
}
