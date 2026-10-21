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
    static func definitions(
        resolver: AppRouteDestinationResolver
    ) -> [AppShellTabDefinition] {
        AppShellTab.allCases.map { tab in
            AppShellTabDefinition(
                tab: tab,
                content: AnyView(
                    AppRouteHost(resolver: resolver) {
                        root(for: tab)
                    }
                )
            )
        }
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
            SettingsView()
        }
    }
}
