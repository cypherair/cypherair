import SwiftUI

/// Key generation form: key-family (Key Type) selection, name, email, expiry.
struct KeyGenerationView: View {
    struct Configuration {
        enum PostGenerationBehavior: Equatable {
            case showPrompt
            case externalPrompt
            case suppressPrompt
        }

        var prefilledName: String?
        var prefilledEmail: String?
        var lockedFamily: PGPKeyConfiguration.Identity?
        var lockedExpiryMonths: Int?
        var postGenerationBehavior: PostGenerationBehavior = .showPrompt
        var onGenerated: (@MainActor (PGPKeyIdentity) -> Void)?
        var onPostGenerationPromptRequested: (@MainActor (PGPKeyIdentity) -> Void)?

        static let `default` = Configuration()
    }

    enum Field {
        case name
        case email
    }

    let configuration: Configuration

    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(AppSessionOrchestrator.self) private var appSessionOrchestrator
    @Environment(\.appRouteNavigator) private var routeNavigator

    init(configuration: Configuration = .default) {
        self.configuration = configuration
    }

    var body: some View {
        KeyGenerationScreenHostView(
            keyManagement: keyManagement,
            appSessionOrchestrator: appSessionOrchestrator,
            routeNavigator: routeNavigator,
            configuration: configuration
        )
    }
}

private struct KeyGenerationScreenHostView: View {
    let keyManagement: KeyManagementService
    let appSessionOrchestrator: AppSessionOrchestrator

    @State private var model: KeyGenerationScreenModel
    @FocusState private var focusedField: KeyGenerationView.Field?

    init(
        keyManagement: KeyManagementService,
        appSessionOrchestrator: AppSessionOrchestrator,
        routeNavigator: AppRouteNavigator,
        configuration: KeyGenerationView.Configuration
    ) {
        self.keyManagement = keyManagement
        self.appSessionOrchestrator = appSessionOrchestrator

        let postGenerationPromptAction: KeyGenerationScreenModel.PostGenerationPromptAction?
        #if os(macOS)
        postGenerationPromptAction = { identity in
            routeNavigator.open(.postGenerationPrompt(identity: identity))
        }
        #else
        postGenerationPromptAction = nil
        #endif

        _model = State(
            initialValue: KeyGenerationScreenModel(
                keyManagement: keyManagement,
                configuration: configuration,
                postGenerationPromptAction: postGenerationPromptAction
            )
        )
    }

    var body: some View {
        @Bindable var model = model

        Form {
            Section {
                ForEach(model.availableFamilies, id: \.self) { family in
                    KeyFamilySelectionRow(
                        family: family,
                        isSelected: model.selectedFamily == family,
                        isEnabled: model.configuration.lockedFamily == nil,
                        onSelect: { model.selectFamily(family) },
                        onInfo: { model.presentFamilyDetail(family) }
                    )
                }
            } header: {
                Text(String(localized: "keygen.keyType.header", defaultValue: "Key Type"))
            }

            Section {
                CypherSingleLineTextField(
                    String(localized: "keygen.name", defaultValue: "Name"),
                    text: $model.name,
                    profile: .name,
                    submitLabel: .next,
                    onSubmit: { focusedField = .email }
                )
                .accessibilityIdentifier("keygen.name")
                .focused($focusedField, equals: .name)

                CypherSingleLineTextField(
                    String(localized: "keygen.email", defaultValue: "Email (optional)"),
                    text: $model.email,
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
                    selection: $model.expiryMonths
                ) {
                    ForEach(model.expiryOptions, id: \.self) { months in
                        Text(String(localized: "keygen.expiry.months", defaultValue: "\(months) months"))
                            .tag(months)
                    }
                }
                .disabled(model.configuration.lockedExpiryMonths != nil)
            } header: {
                Text(String(localized: "keygen.expiry.header", defaultValue: "Validity"))
            }

            Section {
                Button {
                    model.generate()
                } label: {
                    if model.isGenerating {
                        ProgressView()
                            .cypherPrimaryActionLabelFrame()
                    } else {
                        Text(String(localized: "keygen.generate", defaultValue: "Generate Key"))
                            .cypherPrimaryActionLabelFrame()
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.generateButtonDisabled)
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
            isPresented: Binding(
                get: { model.showError },
                set: { if !$0 { model.dismissError() } }
            ),
            presenting: model.error
        ) { _ in
            Button(String(localized: "error.ok", defaultValue: "OK")) {
                model.dismissError()
            }
        } message: { err in
            Text(err.localizedDescription)
        }
        .sheet(isPresented: Binding(
            get: { model.deviceBoundCommitmentPending },
            set: { if !$0 { model.cancelDeviceBoundCommitment() } }
        )) {
            DeviceBoundKeyCommitmentSheet(
                onConfirm: { model.confirmDeviceBoundGeneration() },
                onCancel: { model.cancelDeviceBoundCommitment() }
            )
        }
        .sheet(isPresented: Binding(
            get: { model.presentedFamilyDetail != nil },
            set: { if !$0 { model.dismissFamilyDetail() } }
        )) {
            if let family = model.presentedFamilyDetail {
                KeyFamilyDetailSheet(
                    family: family,
                    onDismiss: { model.dismissFamilyDetail() }
                )
            }
        }
        .sheet(item: Binding(
            get: { model.generatedIdentity },
            set: { if $0 == nil { model.dismissGeneratedIdentity() } }
        )) { identity in
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
            model.handleAppear()
        }
        .onChange(of: appSessionOrchestrator.contentClearGeneration) {
            focusedField = nil
            model.handleContentClearGenerationChange()
        }
    }
}
