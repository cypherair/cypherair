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

    enum Field {
        case passphrase
        case confirm
    }

    @FocusState private var focusedField: Field?
    @State private var passphrase = ""
    @State private var passphraseConfirm = ""
    @State private var isExporting = false
    @State private var exportedData: Data?
    @State private var error: CypherAirError?
    @State private var showError = false
    @State private var showFileExporter = false

    init(
        fingerprint: String,
        configuration: Configuration = .default
    ) {
        self.fingerprint = fingerprint
        self.configuration = configuration
    }

    var body: some View {
        Form {
            Section {
                CypherSecureTextField(
                    String(localized: "backup.passphrase", defaultValue: "Passphrase"),
                    text: $passphrase,
                    submitLabel: .next,
                    onSubmit: { focusedField = .confirm }
                )
                .focused($focusedField, equals: .passphrase)

                CypherSecureTextField(
                    String(localized: "backup.confirm", defaultValue: "Confirm Passphrase"),
                    text: $passphraseConfirm,
                    submitLabel: .done,
                    onSubmit: { focusedField = nil }
                )
                .focused($focusedField, equals: .confirm)
            } header: {
                Text(String(localized: "backup.header", defaultValue: "Protect your backup with a strong passphrase."))
            } footer: {
                if !passphrase.isEmpty && passphrase != passphraseConfirm {
                    Text(String(localized: "backup.mismatch", defaultValue: "Passphrases do not match."))
                        .foregroundStyle(.red)
                }
            }

            Section {
                Button {
                    exportBackup()
                } label: {
                    if isExporting {
                        ProgressView()
                            .cypherPrimaryActionLabelFrame()
                    } else {
                        Text(String(localized: "backup.export", defaultValue: "Export Backup"))
                            .cypherPrimaryActionLabelFrame()
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(passphrase.isEmpty || passphrase != passphraseConfirm || isExporting)
            }

            if configuration.resultPresentation == .inlinePreview,
               let exportedData,
               let exportedString = String(data: exportedData, encoding: .utf8) {
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
            } else if exportedData != nil {
                Section {
                    Button {
                        showFileExporter = true
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
            isPresented: $showError,
            presenting: error
        ) { _ in
            Button(String(localized: "error.ok", defaultValue: "OK")) {}
        } message: { err in
            Text(err.localizedDescription)
        }
        .fileExporter(
            isPresented: Binding(
                get: { showFileExporter },
                set: {
                    showFileExporter = $0
                    if !$0 {
                        clearExportedData()
                    }
                }
            ),
            item: exportedData,
            contentTypes: [.data],
            defaultFilename: "\(fingerprint.prefix(16)).asc"
        ) { result in
            defer {
                clearExportedData()
            }
            if case .failure(let exportError) = result {
                error = CypherAirError.from(exportError) { .encryptionFailed(reason: $0) }
                showError = true
            }
        }
        .onDisappear {
            clearTransientInput()
        }
        .onChange(of: appSessionOrchestrator.contentClearGeneration) {
            clearTransientInput()
        }
    }

    private func exportBackup() {
        isExporting = true
        let service = keyManagement
        let fp = fingerprint
        let pass = passphrase

        Task {
            do {
                let data = try await service.exportKey(
                    fingerprint: fp,
                    passphrase: pass
                )
                exportedData = data
                configuration.onExported?(data)
                passphrase = ""
                passphraseConfirm = ""
            } catch {
                self.error = CypherAirError.from(error) { .encryptionFailed(reason: $0) }
                showError = true
            }
            isExporting = false
        }
    }

    private func clearTransientInput() {
        passphrase = ""
        passphraseConfirm = ""
        focusedField = nil
        showFileExporter = false
        clearExportedData()
    }

    private func clearExportedData() {
        exportedData?.resetBytes(in: 0..<(exportedData?.count ?? 0))
        exportedData = nil
    }
}
