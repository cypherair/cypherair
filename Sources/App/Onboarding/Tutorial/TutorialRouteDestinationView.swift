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
        let factory = tutorialStore.configurationFactory

        switch route {
        case .keyGeneration:
            return AnyView(
                TutorialSurfaceView(tab: definitionTab, route: route) {
                    if tutorialStore.session.activeTask == .generateAliceKey {
                        TutorialTaskHostView(task: .generateAliceKey) {
                            KeyGenerationView(configuration: factory.keyGenerationConfiguration())
                        }
                    } else {
                        KeyGenerationView()
                    }
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
                    if tutorialStore.session.activeTask == .importBobKey {
                        TutorialTaskHostView(task: .importBobKey) {
                            AddContactView(configuration: factory.addContactConfiguration())
                        }
                    } else {
                        AddContactView()
                    }
                }
            )
        case .encrypt:
            return AnyView(
                TutorialSurfaceView(tab: definitionTab, route: route) {
                    if tutorialStore.session.activeTask == .composeAndEncryptMessage {
                        TutorialTaskHostView(task: .composeAndEncryptMessage) {
                            EncryptView(configuration: factory.encryptConfiguration())
                        }
                    } else {
                        EncryptView()
                    }
                }
            )
        case .decrypt:
            return AnyView(
                TutorialSurfaceView(tab: definitionTab, route: route) {
                    if tutorialStore.session.activeTask == .parseRecipients {
                        TutorialTaskHostView(task: .parseRecipients) {
                            DecryptView(configuration: factory.decryptConfiguration(for: .parseRecipients))
                        }
                    } else if tutorialStore.session.activeTask == .decryptMessage {
                        TutorialTaskHostView(task: .decryptMessage) {
                            DecryptView(configuration: factory.decryptConfiguration(for: .decryptMessage))
                        }
                    } else {
                        DecryptView()
                    }
                }
            )
        case .backupKey(let fingerprint):
            return AnyView(
                TutorialSurfaceView(tab: definitionTab, route: route) {
                    if tutorialStore.session.activeTask == .exportBackup {
                        TutorialTaskHostView(task: .exportBackup) {
                            BackupKeyView(
                                fingerprint: fingerprint,
                                configuration: factory.backupConfiguration()
                            )
                        }
                    } else {
                        BackupKeyView(fingerprint: fingerprint)
                    }
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
            return AnyView(TutorialSurfaceView(tab: definitionTab, route: route) { SignView() })
        case .verify:
            return AnyView(TutorialSurfaceView(tab: definitionTab, route: route) { VerifyView() })
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
