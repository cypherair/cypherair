import SwiftUI
import UniformTypeIdentifiers

/// Passphrase-protected key export for backup.
struct BackupKeyView: View {
    struct Configuration {
        enum ResultPresentation: Equatable {
            case fileExporter
            case inlinePreview
        }

        var resultPresentation: ResultPresentation = .fileExporter
        var onExported: (@MainActor (Data) -> Void)?

        static let `default` = Configuration()
    }

    let fingerprint: String
    let configuration: Configuration

    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(AppSessionOrchestrator.self) private var appSessionOrchestrator

    init(
        fingerprint: String,
        configuration: Configuration = .default
    ) {
        self.fingerprint = fingerprint
        self.configuration = configuration
    }

    var body: some View {
        BackupKeyScreenHostView(
            fingerprint: fingerprint,
            keyManagement: keyManagement,
            appSessionOrchestrator: appSessionOrchestrator,
            configuration: configuration
        )
    }
}

private struct BackupKeyScreenHostView: View {
    enum Field {
        case passphrase
        case confirm
    }

    let appSessionOrchestrator: AppSessionOrchestrator

    @State private var model: BackupKeyScreenModel
    @FocusState private var focusedField: Field?

    init(
        fingerprint: String,
        keyManagement: KeyManagementService,
        appSessionOrchestrator: AppSessionOrchestrator,
        configuration: BackupKeyView.Configuration
    ) {
        self.appSessionOrchestrator = appSessionOrchestrator
        _model = State(
            initialValue: BackupKeyScreenModel(
                fingerprint: fingerprint,
                keyManagement: keyManagement,
                configuration: configuration
            )
        )
    }

    var body: some View {
        @Bindable var model = model

        if model.isDeviceBound {
            deviceBoundUnavailableBody
        } else {
            passphraseFormBody
        }
    }

    /// Device-bound keys have no private-key backup; this route is not offered
    /// for them, but stale paths must land on a safe explanation, never the
    /// passphrase form.
    private var deviceBoundUnavailableBody: some View {
        ContentUnavailableView {
            Label(
                String(localized: "backup.deviceBound.unavailable.title", defaultValue: "Backup Not Available"),
                systemImage: "cpu"
            )
        } description: {
            Text(String(
                localized: "backup.deviceBound.unavailable.description",
                defaultValue: "Device-Bound keys cannot be exported or backed up."
            ))
        }
        .accessibilityIdentifier("backup.deviceBound.unavailable")
        .navigationTitle(String(localized: "backup.title", defaultValue: "Backup Key"))
    }

    private var passphraseFormBody: some View {
        @Bindable var model = model

        return Form {
            Section {
                CypherSecureTextField(
                    String(localized: "backup.passphrase", defaultValue: "Passphrase"),
                    text: $model.passphrase,
                    submitLabel: .next,
                    onSubmit: { focusedField = .confirm }
                )
                .focused($focusedField, equals: .passphrase)

                CypherSecureTextField(
                    String(localized: "backup.confirm", defaultValue: "Confirm Passphrase"),
                    text: $model.passphraseConfirm,
                    submitLabel: .done,
                    onSubmit: { focusedField = nil }
                )
                .focused($focusedField, equals: .confirm)
            } header: {
                Text(String(localized: "backup.header", defaultValue: "Protect your backup with a strong passphrase."))
            } footer: {
                if model.passphrasesMismatch {
                    Text(String(localized: "backup.mismatch", defaultValue: "Passphrases do not match."))
                        .foregroundStyle(.red)
                }
            }

            Section {
                Button {
                    model.exportBackup()
                } label: {
                    if model.isExporting {
                        ProgressView()
                            .cypherPrimaryActionLabelFrame()
                    } else {
                        Text(String(localized: "backup.export", defaultValue: "Export Backup"))
                            .cypherPrimaryActionLabelFrame()
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.exportButtonDisabled)
            }

            if model.configuration.resultPresentation == .inlinePreview,
               let exportedString = model.exportedString {
                Section {
                    CypherOutputTextBlock(
                        text: exportedString,
                        font: .system(.footnote, design: .monospaced),
                        minHeight: 100,
                        maxHeight: 220
                    )
                } header: {
                    Text(String(localized: "backup.ready", defaultValue: "Backup Ready"))
                }
            } else if model.exportedData != nil {
                Section {
                    Button {
                        model.showFileExporter = true
                    } label: {
                        Label(
                            String(localized: "backup.share", defaultValue: "Save Backup File"),
                            systemImage: "square.and.arrow.down"
                        )
                    }
                } header: {
                    Text(String(localized: "backup.ready", defaultValue: "Backup Ready"))
                }
            }
        }
        .scrollDismissesKeyboardInteractivelyIfAvailable()
        #if os(macOS)
        .formStyle(.grouped)
        #endif
        .cypherMacReadableContent()
        .accessibilityIdentifier("backup.root")
        .screenReady("backup.ready")
        .navigationTitle(String(localized: "backup.title", defaultValue: "Backup Key"))
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
        .fileExporter(
            isPresented: $model.showFileExporter,
            item: model.exportedData,
            contentTypes: [.data],
            defaultFilename: model.defaultFilename
        ) { result in
            model.handleFileExporterResult(result)
        }
        .onDisappear {
            focusedField = nil
            model.handleDisappear()
        }
        .onChange(of: appSessionOrchestrator.contentClearGeneration) {
            focusedField = nil
            model.handleContentClearGenerationChange()
        }
    }
}
