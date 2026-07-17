import SwiftUI

/// Generation step 2: identity, expiry, and the Generate action for the family
/// chosen on the picker. The header is the confirmation surface — it carries the
/// custody badge and any in-flow interoperability warning before generation.
struct KeyGenerationDetailsView: View {
    let model: KeyGenerationScreenModel
    let family: PGPKeyFamily

    @Environment(KeyManagementService.self) private var keyManagement
    @FocusState private var focusedField: KeyGenerationView.Field?
    @State private var showsTechnicalDetail = false

    var body: some View {
        @Bindable var model = model

        Form {
            Section {
                summaryHeader
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
                generateButton
            }
        }
        .scrollDismissesKeyboardInteractivelyIfAvailable()
        #if os(macOS)
        .formStyle(.grouped)
        #endif
        .cypherMacReadableContent()
        .accessibilityIdentifier("keygen.details.root")
        .screenReady("keygen.details.ready")
        .navigationTitle(family.familyDisplayName)
        #if !os(macOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
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
                family: family,
                onConfirm: { model.confirmDeviceBoundGeneration() },
                onCancel: { model.cancelDeviceBoundCommitment() }
            )
        }
        .sheet(isPresented: $showsTechnicalDetail) {
            KeyFamilyDetailSheet(
                family: family,
                onDismiss: { showsTechnicalDetail = false }
            )
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
    }

    private var summaryHeader: some View {
        VStack(alignment: .leading, spacing: CypherSpacing.compact) {
            HStack(spacing: CypherSpacing.compact) {
                Text(family.familyDisplayName)
                    .font(.headline)
                if family.custody == .deviceBound {
                    KeyCustodyBadge(style: .badge)
                }
            }

            Text(family.familyAlgorithmSubtitle)
                .font(.caption)
                .foregroundStyle(.secondary)

            if let warning = family.familyInteropWarning {
                Label(warning, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("keygen.details.interopWarning")
            }

            Button {
                showsTechnicalDetail = true
            } label: {
                Text(String(localized: "keygen.viewDetails", defaultValue: "View technical details"))
                    .font(.caption)
            }
            .buttonStyle(.plain)
            .foregroundStyle(Color.accentColor)
            .accessibilityIdentifier("keygen.details.viewTechnical")
        }
    }

    private var generateButton: some View {
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
