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
    @Environment(ContentClearSignal.self) private var contentClear

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
            contentClear: contentClear,
            configuration: configuration
        )
    }
}

private struct BackupKeyScreenHostView: View {
    let contentClear: ContentClearSignal

    @State private var model: BackupKeyScreenModel
    @FocusState private var focusedField: CypherPassphraseEntry.Field?

    init(
        fingerprint: String,
        keyManagement: KeyManagementService,
        contentClear: ContentClearSignal,
        configuration: BackupKeyView.Configuration
    ) {
        self.contentClear = contentClear
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
                CypherPassphraseEntry(
                    passphrase: $model.passphrase,
                    confirmation: $model.passphraseConfirm,
                    focus: $focusedField
                )
            } header: {
                Text(String(localized: "backup.header", defaultValue: "Protect your backup with a strong passphrase."))
            } footer: {
                Text(String(
                    localized: "backup.passphrase.stake",
                    defaultValue: "The passphrase is the whole of the backup's protection. Anyone who copies the file can keep guessing at it offline, for as long as they like."
                ))
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
        .onChange(of: contentClear.generation) {
            focusedField = nil
            model.handleContentClearGenerationChange()
        }
    }
}
