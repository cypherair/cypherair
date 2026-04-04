import SwiftUI
#if os(iOS)
import UIKit
#endif

@main
struct CypherAirApp: App {
    #if os(iOS)
    @UIApplicationDelegateAdaptor(CypherAirKeyboardPolicyDelegate.self)
    private var keyboardPolicyDelegate
    #endif

    // MARK: - Shared Dependencies

    @State private var container: AppContainer

    @State private var importError: CypherAirError?
    @State private var loadError: String?
    @State private var tutorialStore = TutorialSessionStore()
    @State private var importConfirmationCoordinator = ImportConfirmationCoordinator()

    // MARK: - Init

    init() {
        let container = AppContainer.makeDefault()
        let startupResult = AppStartupCoordinator().performStartup(using: container)

        _container = State(initialValue: container)
        _loadError = State(initialValue: startupResult.loadError)
    }

    // MARK: - Scene

    var body: some Scene {
        WindowGroup {
            ImportConfirmationSheetHost(coordinator: importConfirmationCoordinator) {
                ContentView()
                    .privacyScreen()
                    .optionalTint(container.config.colorTheme.accentColor)
                    .environment(container.config)
                    .environment(container.keyManagement)
                    .environment(container.contactService)
                    .environment(container.encryptionService)
                    .environment(container.decryptionService)
                    .environment(container.signingService)
                    .environment(container.qrService)
                    .environment(container.selfTestService)
                    .environment(container.authManager)
                    .environment(tutorialStore)
            }
                .sheet(isPresented: showOnboarding) {
                    OnboardingView()
                        .environment(container.config)
                        .environment(tutorialStore)
                        .interactiveDismissDisabled()
                }
                .alert(
                    String(localized: "import.error.alertTitle", defaultValue: "Import Failed"),
                    isPresented: Binding(
                        get: { importError != nil },
                        set: { if !$0 { importError = nil } }
                    )
                ) {
                    Button(String(localized: "import.error.ok", defaultValue: "OK")) {
                        importError = nil
                    }
                } message: {
                    if let importError {
                        Text(importError.localizedDescription)
                    }
                }
                .alert(
                    String(localized: "app.loadError.title", defaultValue: "Load Warning"),
                    isPresented: Binding(
                        get: { loadError != nil },
                        set: { if !$0 { loadError = nil } }
                    )
                ) {
                    Button(String(localized: "error.ok", defaultValue: "OK")) {
                        loadError = nil
                    }
                } message: {
                    if let loadError {
                        Text(loadError)
                    }
                }
                .onOpenURL { url in
                    handleIncomingURL(url)
                }
        }
        #if os(macOS)
        .defaultSize(width: 900, height: 650)
        .windowResizability(.contentMinSize)
        .commands {
            // Disable File > New Window on macOS.
            // CypherAir uses a single-window design; multiple windows would create
            // independent privacy screen states leading to inconsistent security behavior.
            CommandGroup(replacing: .newItem) { }
        }
        #endif

        #if os(macOS)
        Settings {
            AppRouteHost(resolver: .production) {
                SettingsView()
            }
            .optionalTint(container.config.colorTheme.accentColor)
            .environment(container.config)
            .environment(container.authManager)
            .environment(container.keyManagement)
            .environment(container.selfTestService)
            .environment(tutorialStore)
        }
        #endif
    }

    private var showOnboarding: Binding<Bool> {
        Binding(
            get: { !container.config.hasCompletedOnboarding },
            set: { newValue in
                if !newValue {
                    container.config.hasCompletedOnboarding = true
                }
            }
        )
    }

    // MARK: - URL Scheme Handling

    /// Handle cypherair:// URLs for public key import.
    /// The QRService validates the URL format and parses the OpenPGP key.
    /// The user must confirm before the key is added as a contact.
    private func handleIncomingURL(_ url: URL) {
        guard url.scheme == "cypherair" else { return }

        do {
            let publicKeyData = try container.qrService.parseImportURL(url)
            let keyInfo = try container.qrService.inspectKeyInfo(keyData: publicKeyData)
            let profile = try container.qrService.detectKeyProfile(keyData: publicKeyData)
            importConfirmationCoordinator.present(
                ImportConfirmationRequest(
                    keyData: publicKeyData,
                    keyInfo: keyInfo,
                    profile: profile,
                    allowsUnverifiedImport: true,
                    onImportVerified: {
                        completePendingImport(
                            keyData: publicKeyData,
                            verificationState: .verified
                        )
                    },
                    onImportUnverified: {
                        completePendingImport(
                            keyData: publicKeyData,
                            verificationState: .unverified
                        )
                    },
                    onCancel: { }
                )
            )
        } catch {
            importError = CypherAirError.from(error) { _ in .invalidQRCode }
        }
    }

    private func completePendingImport(
        keyData: Data,
        verificationState: ContactVerificationState
    ) {
        do {
            let result = try container.contactService.addContact(
                publicKeyData: keyData,
                verificationState: verificationState
            )
            if case .keyUpdateDetected(let newContact, let existingContact, let keyData) = result {
                // User confirmed import via ImportConfirmView — proceed with replacement.
                try container.contactService.confirmKeyUpdate(
                    existingFingerprint: existingContact.fingerprint,
                    newContact: newContact,
                    keyData: keyData
                )
            }
        } catch {
            importError = CypherAirError.from(error) { _ in .invalidQRCode }
        }
        importConfirmationCoordinator.dismiss()
    }
}

#if os(iOS)
private final class CypherAirKeyboardPolicyDelegate: NSObject, UIApplicationDelegate {
    func application(
        _ application: UIApplication,
        shouldAllowExtensionPointIdentifier extensionPointIdentifier: UIApplication.ExtensionPointIdentifier
    ) -> Bool {
        extensionPointIdentifier != .keyboard
    }
}
#endif

// MARK: - Optional Tint

private extension View {
    /// Apply `.tint()` only when a color is provided; omit entirely for `nil`
    /// so SwiftUI uses the system `Color.accentColor`.
    @ViewBuilder
    func optionalTint(_ color: Color?) -> some View {
        if let color {
            self.tint(color)
        } else {
            self
        }
    }
}
