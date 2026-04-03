import SwiftUI

@main
struct CypherAirApp: App {

    // MARK: - Shared Dependencies

    @State private var container: AppContainer

    /// Pending public key import awaiting user confirmation (Issue #3).
    @State private var pendingImport: PendingImport?
    @State private var importError: CypherAirError?
    @State private var loadError: String?
    @State private var tutorialStore = TutorialSessionStore()

    /// Holds parsed key data and info for the import confirmation sheet.
    private struct PendingImport {
        let keyData: Data
        let keyInfo: KeyInfo
        let profile: KeyProfile
    }

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
                .sheet(isPresented: showOnboarding) {
                    OnboardingView()
                        .environment(container.config)
                        .environment(tutorialStore)
                        .interactiveDismissDisabled()
                }
                .sheet(isPresented: Binding(
                    get: { pendingImport != nil },
                    set: { if !$0 { pendingImport = nil } }
                )) {
                    if let pending = pendingImport {
                        ImportConfirmView(
                            keyInfo: pending.keyInfo,
                            detectedProfile: pending.profile,
                            onImportVerified: {
                                completePendingImport(
                                    pending,
                                    verificationState: .verified
                                )
                            },
                            onImportUnverified: {
                                completePendingImport(
                                    pending,
                                    verificationState: .unverified
                                )
                            },
                            onCancel: {
                                pendingImport = nil
                            }
                        )
                    }
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
            // Show confirmation sheet — do NOT add directly (PRD Section 4.2).
            pendingImport = PendingImport(keyData: publicKeyData, keyInfo: keyInfo, profile: profile)
        } catch {
            importError = CypherAirError.from(error) { _ in .invalidQRCode }
        }
    }

    private func completePendingImport(
        _ pending: PendingImport,
        verificationState: ContactVerificationState
    ) {
        do {
            let result = try container.contactService.addContact(
                publicKeyData: pending.keyData,
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
        pendingImport = nil
    }
}

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
