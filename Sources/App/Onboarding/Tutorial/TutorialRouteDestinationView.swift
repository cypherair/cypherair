import SwiftUI

@MainActor
struct TutorialRouteDestinationView: View {
    @Environment(TutorialSessionStore.self) private var tutorialStore

    let route: AppRoute
    let definitionTab: AppShellTab
    let sizeClass: UserInterfaceSizeClass?

    var body: some View {
        destination
    }

    private var destination: AnyView {
        if let blockedSurface = tutorialStore.blocklist.blockedRoute(for: route) {
            return AnyView(
                TutorialSurfaceView(tab: definitionTab, route: route) {
                    TutorialBlockedRouteView(surface: blockedSurface)
                }
            )
        }

        let factory = tutorialStore.configurationFactory

        switch route {
        case .keyGeneration:
            return AnyView(
                TutorialSurfaceView(tab: definitionTab, route: route) {
                    KeyGenerationView(
                        configuration: factory.keyGenerationConfiguration(
                            isActiveModule: tutorialStore.currentModule == .createDemoIdentity
                        )
                    )
                }
            )
        case .postGenerationPrompt(let identity):
            return AnyView(
                TutorialSurfaceView(tab: definitionTab, route: route) {
                    PostGenerationPromptView(identity: identity)
                }
            )
        case .addContact:
            return AnyView(
                TutorialSurfaceView(tab: definitionTab, route: route) {
                    AddContactView(
                        configuration: factory.addContactConfiguration(
                            isActiveModule: tutorialStore.currentModule == .addDemoContact
                        )
                    )
                }
            )
        case .encrypt:
            return AnyView(
                TutorialSurfaceView(tab: definitionTab, route: route) {
                    EncryptView(
                        configuration: factory.encryptConfiguration(
                            isActiveModule: tutorialStore.currentModule == .encryptDemoMessage
                        )
                    )
                }
            )
        case .decrypt:
            return AnyView(
                TutorialSurfaceView(tab: definitionTab, route: route) {
                    DecryptView(
                        configuration: factory.decryptConfiguration(
                            isActiveModule: tutorialStore.currentModule == .decryptAndVerify
                        )
                    )
                }
            )
        case .backupKey(let fingerprint):
            return AnyView(
                TutorialSurfaceView(tab: definitionTab, route: route) {
                    BackupKeyView(
                        fingerprint: fingerprint,
                        configuration: factory.backupConfiguration(
                            isActiveModule: tutorialStore.currentModule == .backupKey
                        )
                    )
                }
            )
        case .keyDetail(let fingerprint):
            return AnyView(TutorialSurfaceView(tab: definitionTab, route: route) { KeyDetailView(fingerprint: fingerprint) })
        case .contactDetail(let fingerprint):
            return AnyView(TutorialSurfaceView(tab: definitionTab, route: route) { ContactDetailView(fingerprint: fingerprint) })
        case .qrDisplay(let publicKeyData, let displayName):
            return AnyView(TutorialSurfaceView(tab: definitionTab, route: route) { QRDisplayView(publicKeyData: publicKeyData, displayName: displayName) })
        case .qrPhotoImport:
            return AnyView(TutorialSurfaceView(tab: definitionTab, route: route) { QRPhotoImportView() })
        case .importKey:
            return AnyView(TutorialSurfaceView(tab: definitionTab, route: route) { ImportKeyView() })
        case .sign:
            return AnyView(
                TutorialSurfaceView(tab: definitionTab, route: route) {
                    SignView(configuration: factory.signConfiguration())
                }
            )
        case .verify:
            return AnyView(
                TutorialSurfaceView(tab: definitionTab, route: route) {
                    VerifyView(configuration: factory.verifyConfiguration())
                }
            )
        case .selfTest:
            return AnyView(TutorialSurfaceView(tab: definitionTab, route: route) { SelfTestView() })
        case .about:
            return AnyView(TutorialSurfaceView(tab: definitionTab, route: route) { AboutView() })
        case .license:
            return AnyView(TutorialSurfaceView(tab: definitionTab, route: route) { LicenseListView() })
        case .appIcon:
            return AnyView(
                TutorialSurfaceView(tab: definitionTab, route: route) {
                    TutorialDisabledSettingView(
                        title: String(localized: "settings.appIcon", defaultValue: "App Icon"),
                        message: String(
                            localized: "guidedTutorial.settings.restricted.appIcon",
                            defaultValue: "App Icon changes affect the real app and are unavailable inside the tutorial sandbox."
                        ),
                        systemImage: "app"
                    )
                }
            )
        case .themePicker:
            return AnyView(TutorialSurfaceView(tab: definitionTab, route: route) { ThemePickerView() })
        }
    }

}

struct TutorialBlockedRouteView: View {
    let surface: TutorialBlockedSurface

    var body: some View {
        ContentUnavailableView {
            Label(surface.title, systemImage: surface.systemImage)
        } description: {
            Text(surface.message)
        }
        .navigationTitle(surface.title)
    }
}
