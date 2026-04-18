import SwiftUI

/// Key generation form: profile selection, name, email, expiry.
struct KeyGenerationView: View {
    struct Configuration {
        enum PostGenerationBehavior: Equatable {
            case showPrompt
            case externalPrompt
            case suppressPrompt
        }

        var prefilledName: String?
        var prefilledEmail: String?
        var lockedProfile: KeyProfile?
        var lockedExpiryMonths: Int?
        var postGenerationBehavior: PostGenerationBehavior = .showPrompt
        var onGenerated: (@MainActor (PGPKeyIdentity) -> Void)?
        var onPostGenerationPromptRequested: (@MainActor (PGPKeyIdentity) -> Void)?

        static let `default` = Configuration()
    }

    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(AppConfiguration.self) private var config
    @Environment(\.dismiss) private var dismiss
    @Environment(\.appRouteNavigator) private var routeNavigator

    enum Field {
        case name
        case email
    }

    let configuration: Configuration

    @FocusState private var focusedField: Field?
    @State private var name = ""
    @State private var email = ""
    @State private var profile: KeyProfile = .universal
    @State private var expiryMonths = 24
    @State private var isGenerating = false
    @State private var error: CypherAirError?
    @State private var showError = false
    @State private var generatedIdentity: PGPKeyIdentity?

    private let expiryOptions = [12, 24, 36, 48, 60]

    init(configuration: Configuration = .default) {
        self.configuration = configuration
    }

    var body: some View {
        Form {
            Section {
                Picker(
                    String(localized: "keygen.profile", defaultValue: "Profile"),
                    selection: $profile
                ) {
                    Text(KeyProfile.universal.displayName).tag(KeyProfile.universal)
                    Text(KeyProfile.advanced.displayName).tag(KeyProfile.advanced)
                }
                .pickerStyle(.segmented)
                .disabled(configuration.lockedProfile != nil)

                Text(profile.shortDescription)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } header: {
                Text(String(localized: "keygen.profile.header", defaultValue: "Encryption Profile"))
            }

            Section {
                TextField(
                    String(localized: "keygen.name", defaultValue: "Name"),
                    text: $name
                )
                .accessibilityIdentifier("keygen.name")
                .textContentType(.name)
                .autocorrectionDisabled(true)
                .applyMacWritingToolsPolicy()
                #if canImport(UIKit)
                .textInputAutocapitalization(.words)
                #endif
                .focused($focusedField, equals: .name)
                .submitLabel(.next)
                .onSubmit { focusedField = .email }

                TextField(
                    String(localized: "keygen.email", defaultValue: "Email (optional)"),
                    text: $email
                )
                .accessibilityIdentifier("keygen.email")
                .textContentType(.emailAddress)
                .autocorrectionDisabled(true)
                .applyMacWritingToolsPolicy()
                #if canImport(UIKit)
                .keyboardType(.emailAddress)
                .textInputAutocapitalization(.never)
                #endif
                .focused($focusedField, equals: .email)
                .submitLabel(.done)
                .onSubmit { focusedField = nil }
            } header: {
                Text(String(localized: "keygen.identity.header", defaultValue: "Identity"))
            }

            Section {
                Picker(
                    String(localized: "keygen.expiry", defaultValue: "Expires After"),
                    selection: $expiryMonths
                ) {
                    ForEach(expiryOptions, id: \.self) { months in
                        Text(String(localized: "keygen.expiry.months", defaultValue: "\(months) months"))
                            .tag(months)
                    }
                }
                .disabled(configuration.lockedExpiryMonths != nil)
            } header: {
                Text(String(localized: "keygen.expiry.header", defaultValue: "Validity"))
            }

            Section {
                Button {
                    generate()
                } label: {
                    if isGenerating {
                        ProgressView()
                            .frame(maxWidth: .infinity)
                    } else {
                        Text(String(localized: "keygen.generate", defaultValue: "Generate Key"))
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty || isGenerating)
                .accessibilityIdentifier("keygen.generate")
            }
        }
        .scrollDismissesKeyboardInteractivelyIfAvailable()
        #if os(macOS)
        .formStyle(.grouped)
        #endif
        .accessibilityIdentifier("keygen.root")
        .screenReady("keygen.ready")
        .navigationTitle(String(localized: "keygen.title", defaultValue: "Generate Key"))
        .alert(
            String(localized: "error.title", defaultValue: "Error"),
            isPresented: $showError,
            presenting: error
        ) { _ in
            Button(String(localized: "error.ok", defaultValue: "OK")) {}
        } message: { err in
            Text(err.localizedDescription)
        }
        .sheet(item: $generatedIdentity) { identity in
            AppRouteHost(
                resolver: .production,
                macSheetSizing: .routedModal
            ) {
                PostGenerationPromptView(identity: identity)
                    .environment(keyManagement)
                    .interactiveDismissDisabled(false)
            }
        }
        .onAppear {
            if name.isEmpty, let prefilledName = configuration.prefilledName {
                name = prefilledName
            }
            if email.isEmpty, let prefilledEmail = configuration.prefilledEmail {
                email = prefilledEmail
            }
            if let lockedProfile = configuration.lockedProfile {
                profile = lockedProfile
            }
            if let lockedExpiryMonths = configuration.lockedExpiryMonths {
                expiryMonths = lockedExpiryMonths
            }
        }
    }

    private func generate() {
        isGenerating = true
        let trimmedName = name.trimmingCharacters(in: .whitespaces)
        let trimmedEmail = email.trimmingCharacters(in: .whitespaces)
        let expiryDate = Calendar.current.date(byAdding: .month, value: expiryMonths, to: Date()) ?? Date()
        let expirySeconds = UInt64(max(0, expiryDate.timeIntervalSinceNow))
        let service = keyManagement
        let authMode = config.authMode

        Task {
            do {
                let identity = try await service.generateKey(
                    name: trimmedName,
                    email: trimmedEmail.isEmpty ? nil : trimmedEmail,
                    expirySeconds: expirySeconds,
                    profile: profile,
                    authMode: authMode
                )
                configuration.onGenerated?(identity)

                switch configuration.postGenerationBehavior {
                case .showPrompt:
                    #if os(macOS)
                    routeNavigator.open(.postGenerationPrompt(identity: identity))
                    #else
                    generatedIdentity = identity
                    #endif
                case .externalPrompt:
                    configuration.onPostGenerationPromptRequested?(identity)
                case .suppressPrompt:
                    break
                }
            } catch {
                self.error = CypherAirError.from(error) { .keyGenerationFailed(reason: $0) }
                showError = true
            }
            isGenerating = false
        }
    }
}
