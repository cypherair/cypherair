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
        case .deviceBoundKeyExplainer(let fingerprint):
            DeviceBoundKeyExplainerView(fingerprint: fingerprint)
        case .backupKey(let fingerprint):
            BackupKeyView(fingerprint: fingerprint)
        case .selectiveRevocation(let fingerprint):
            SelectiveRevocationView(fingerprint: fingerprint)
        case .importKey:
            ImportKeyView()
        case .contactDetail(let contactId):
            ContactDetailView(contactId: contactId)
        case .contactCertification(let contactId, let keyId):
            ContactCertificationDetailsView(
                contactId: contactId,
                keyId: keyId
            )
        case .tagManagement:
            TagManagementView()
        case .tagDetail(let tagId):
            TagDetailView(tagId: tagId)
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

    private static func content(
        for tab: AppShellTab,
        resolver: AppRouteDestinationResolver,
        path: Binding<[AppRoute]>
    ) -> AnyView {
        AnyView(
            AppRouteHost(resolver: resolver, path: path) {
                root(for: tab)
            }
        )
    }

    @ViewBuilder
    private static func root(for tab: AppShellTab) -> some View {
        switch tab {
        case .home:
            HomeView()
        case .keys:
            MyKeysView()
        case .contacts:
            ContactsView()
        case .settings:
            MainWindowSettingsRootView()
        case .encrypt:
            EncryptView()
        case .decrypt:
            DecryptView()
        case .sign:
            SignView()
        case .verify:
            VerifyView()
        }
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
        path: (AppShellTab) -> Binding<[AppRoute]>
    ) -> [AppShellTabDefinition] {
        AppShellTab.allCases.map { tab in
            definition(
                for: tab,
                content: content(for: tab, resolver: resolver, path: path(tab))
            )
        }
    }
}
