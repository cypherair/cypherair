import SwiftUI

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

            if let exportedData,
               let fileURL = exportedData.writeToShareTempFile(named: "\(fingerprint.prefix(16)).asc") {
                Section {
                    ShareLink(item: fileURL) {
                        Label(
                            String(localized: "backup.share", defaultValue: "Save Backup File"),
                            systemImage: "square.and.arrow.up"
                        )
                    }
                } header: {
                    Text(String(localized: "backup.ready", defaultValue: "Backup Ready"))
                }
            }
        }
        .scrollDismissesKeyboard(.interactively)
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
    }

    private func exportBackup() {
        isExporting = true
        Task {
            do {
                let data = try keyManagement.exportKey(
                    fingerprint: fingerprint,
                    passphrase: passphrase
                )
                exportedData = data
            } catch {
                self.error = CypherAirError.from(error) { .encryptionFailed(reason: $0) }
                showError = true
            }
            isExporting = false
        }
    }
}
