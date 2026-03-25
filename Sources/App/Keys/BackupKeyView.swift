import SwiftUI
import UniformTypeIdentifiers

/// Passphrase-protected key export for backup.
struct BackupKeyView: View {
    let fingerprint: String

    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(\.dismiss) private var dismiss

    enum Field { case passphrase, confirm }
    @FocusState private var focusedField: Field?

    @State private var passphrase = ""
    @State private var passphraseConfirm = ""
    @State private var isExporting = false
    @State private var exportedData: Data?
    @State private var error: CypherAirError?
    @State private var showError = false
    @State private var showFileExporter = false

    var body: some View {
        Form {
            Section {
                SecureField(
                    String(localized: "backup.passphrase", defaultValue: "Passphrase"),
                    text: $passphrase
                )
                .focused($focusedField, equals: .passphrase)
                .submitLabel(.next)
                .onSubmit { focusedField = .confirm }

                SecureField(
                    String(localized: "backup.confirm", defaultValue: "Confirm Passphrase"),
                    text: $passphraseConfirm
                )
                .focused($focusedField, equals: .confirm)
                .submitLabel(.done)
                .onSubmit { focusedField = nil }
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
                            .frame(maxWidth: .infinity)
                    } else {
                        Text(String(localized: "backup.export", defaultValue: "Export Backup"))
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(passphrase.isEmpty || passphrase != passphraseConfirm || isExporting)
            }

            if exportedData != nil {
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
        #if canImport(UIKit)
        .scrollDismissesKeyboard(.interactively)
        #endif
        #if os(macOS)
        .formStyle(.grouped)
        #endif
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
            isPresented: $showFileExporter,
            item: exportedData,
            contentTypes: [UTType(filenameExtension: "asc") ?? .data],
            defaultFilename: "\(fingerprint.prefix(16)).asc"
        ) { result in
            if case .failure(let exportError) = result {
                error = CypherAirError.from(exportError) { .encryptionFailed(reason: $0) }
                showError = true
            }
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
                // Clear sensitive state after successful export.
                // Note: Swift String cannot be reliably zeroized (SECURITY.md §7.1),
                // but we minimize lifetime by clearing references immediately.
                passphrase = ""
                passphraseConfirm = ""
            } catch {
                self.error = CypherAirError.from(error) { .encryptionFailed(reason: $0) }
                showError = true
            }
            isExporting = false
        }
    }
}
