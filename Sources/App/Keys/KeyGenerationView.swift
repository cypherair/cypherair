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
        var lockedProfile: PGPKeyProfile?
        var lockedExpiryMonths: Int?
        var postGenerationBehavior: PostGenerationBehavior = .showPrompt
        var onGenerated: (@MainActor (PGPKeyIdentity) -> Void)?
        var onPostGenerationPromptRequested: (@MainActor (PGPKeyIdentity) -> Void)?

        static let `default` = Configuration()
    }

    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(AppSessionOrchestrator.self) private var appSessionOrchestrator
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
    @State private var profile: PGPKeyProfile = .universal
    @State private var expiryMonths = 24
    @State private var isGenerating = false
    @State private var error: CypherAirError?
    @State private var showError = false
    @State private var generatedIdentity: PGPKeyIdentity?
    @State private var generationTask: Task<Void, Never>?
    @State private var generationToken: UInt64 = 0

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
                    Text(PGPKeyProfile.universal.displayName).tag(PGPKeyProfile.universal)
                    Text(PGPKeyProfile.advanced.displayName).tag(PGPKeyProfile.advanced)
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
                CypherSingleLineTextField(
                    String(localized: "keygen.name", defaultValue: "Name"),
                    text: $name,
                    profile: .name,
                    submitLabel: .next,
                    onSubmit: { focusedField = .email }
                )
                .accessibilityIdentifier("keygen.name")
                .focused($focusedField, equals: .name)

                CypherSingleLineTextField(
                    String(localized: "keygen.email", defaultValue: "Email (optional)"),
                    text: $email,
                    profile: .email,
                    submitLabel: .done,
                    onSubmit: { focusedField = nil }
                )
                .accessibilityIdentifier("keygen.email")
                .focused($focusedField, equals: .email)
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
                            .cypherPrimaryActionLabelFrame()
                    } else {
                        Text(String(localized: "keygen.generate", defaultValue: "Generate Key"))
                            .cypherPrimaryActionLabelFrame()
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
        .cypherMacReadableContent()
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
        .onChange(of: appSessionOrchestrator.contentClearGeneration) {
            cancelGenerationAndClearTransientInput()
        }
    }

    private func generate() {
        generationTask?.cancel()
        generationToken &+= 1
        let token = generationToken
        isGenerating = true
        let trimmedName = name.trimmingCharacters(in: .whitespaces)
        let trimmedEmail = email.trimmingCharacters(in: .whitespaces)
        let selectedProfile = profile
        let expiryDate = Calendar.current.date(byAdding: .month, value: expiryMonths, to: Date()) ?? Date()
        let expirySeconds = UInt64(max(0, expiryDate.timeIntervalSinceNow))
        let service = keyManagement

        generationTask = Task { @MainActor in
            defer {
                if token == generationToken {
                    isGenerating = false
                    generationTask = nil
                }
            }

            do {
                let identity = try await service.generateKey(
                    name: trimmedName,
                    email: trimmedEmail.isEmpty ? nil : trimmedEmail,
                    expirySeconds: expirySeconds,
                    profile: selectedProfile
                )
                try Task.checkCancellation()
                guard token == generationToken else {
                    return
                }
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
                guard !Self.shouldIgnore(error), token == generationToken else {
                    return
                }
                self.error = CypherAirError.from(error) { .keyGenerationFailed(reason: $0) }
                showError = true
            }
        }
    }

    private func cancelGenerationAndClearTransientInput() {
        generationTask?.cancel()
        generationToken &+= 1
        generationTask = nil
        isGenerating = false
        clearTransientInput()
    }

    private func clearTransientInput() {
        name = ""
        email = ""
        focusedField = nil
        generatedIdentity = nil
    }

    private static func shouldIgnore(_ error: Error) -> Bool {
        if error is CancellationError {
            return true
        }
        if let cypherAirError = error as? CypherAirError,
           case .operationCancelled = cypherAirError {
            return true
        }
        if let pgpError = error as? PgpError,
           case .OperationCancelled = pgpError {
            return true
        }
        return false
    }
}
