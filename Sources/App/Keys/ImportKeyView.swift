import SwiftUI

/// Import a private key from file, paste, or QR photo.
struct ImportKeyView: View {
    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(AppConfiguration.self) private var config
    @Environment(\.dismiss) private var dismiss

    @State private var armoredText = ""
    @State private var passphrase = ""
    @State private var isImporting = false
    @State private var error: CypherAirError?
    @State private var showError = false

    var body: some View {
        Form {
            Section {
                TextEditor(text: $armoredText)
                    .font(.system(.body, design: .monospaced))
                    .frame(minHeight: 120)
            } header: {
                Text(String(localized: "import.paste.header", defaultValue: "Paste armored private key"))
            }

            Section {
                SecureField(
                    String(localized: "import.passphrase", defaultValue: "Passphrase"),
                    text: $passphrase
                )
            } header: {
                Text(String(localized: "import.passphrase.header", defaultValue: "Key Passphrase"))
            }

            Section {
                Button {
                    importKey()
                } label: {
                    if isImporting {
                        ProgressView()
                            .frame(maxWidth: .infinity)
                    } else {
                        Text(String(localized: "import.button", defaultValue: "Import Key"))
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(armoredText.isEmpty || passphrase.isEmpty || isImporting)
            }
        }
        .navigationTitle(String(localized: "import.title", defaultValue: "Import Key"))
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

    private func importKey() {
        isImporting = true
        Task {
            do {
                let data = Data(armoredText.utf8)
                _ = try keyManagement.importKey(
                    armoredData: data,
                    passphrase: passphrase,
                    authMode: config.authMode
                )
                dismiss()
            } catch let err as CypherAirError {
                error = err
                showError = true
            } catch {
                self.error = .invalidKeyData(reason: error.localizedDescription)
                showError = true
            }
            isImporting = false
        }
    }
}
