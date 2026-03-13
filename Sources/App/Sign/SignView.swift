import SwiftUI

/// Cleartext signing view.
struct SignView: View {
    @Environment(SigningService.self) private var signingService
    @Environment(KeyManagementService.self) private var keyManagement

    @State private var text = ""
    @State private var isSigning = false
    @State private var signedMessage: String?
    @State private var error: CypherAirError?
    @State private var showError = false

    var body: some View {
        Form {
            Section {
                TextEditor(text: $text)
                    .frame(minHeight: 100)
            } header: {
                Text(String(localized: "sign.input", defaultValue: "Message to Sign"))
            }

            Section {
                Button {
                    sign()
                } label: {
                    if isSigning {
                        ProgressView()
                            .frame(maxWidth: .infinity)
                    } else {
                        Text(String(localized: "sign.button", defaultValue: "Sign"))
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(text.isEmpty || keyManagement.defaultKey == nil || isSigning)
            }

            if let signedMessage {
                Section {
                    Text(signedMessage)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                } header: {
                    Text(String(localized: "sign.result", defaultValue: "Signed Message"))
                }
            }
        }
        .navigationTitle(String(localized: "sign.title", defaultValue: "Sign"))
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

    private func sign() {
        guard let signerFp = keyManagement.defaultKey?.fingerprint else { return }
        isSigning = true
        let service = signingService
        let message = text
        Task {
            do {
                let signed = try await service.signCleartext(message, signerFingerprint: signerFp)
                signedMessage = String(data: signed, encoding: .utf8)
            } catch let err as CypherAirError {
                error = err
                showError = true
            } catch let pgpError as PgpError {
                error = CypherAirError(pgpError: pgpError)
                showError = true
            } catch {
                self.error = .signingFailed(reason: error.localizedDescription)
                showError = true
            }
            isSigning = false
        }
    }
}
