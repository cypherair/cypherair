import SwiftUI

/// Two-phase decryption view.
struct DecryptView: View {
    @Environment(DecryptionService.self) private var decryptionService

    @State private var ciphertextInput = ""
    @State private var isDecrypting = false
    @State private var decryptedText: String?
    @State private var signatureVerification: SignatureVerification?
    @State private var error: CypherAirError?
    @State private var showError = false

    var body: some View {
        Form {
            Section {
                TextEditor(text: $ciphertextInput)
                    .font(.system(.body, design: .monospaced))
                    .frame(minHeight: 100)
            } header: {
                Text(String(localized: "decrypt.input", defaultValue: "Encrypted Message"))
            }

            Section {
                Button {
                    decrypt()
                } label: {
                    if isDecrypting {
                        ProgressView()
                            .frame(maxWidth: .infinity)
                    } else {
                        Text(String(localized: "decrypt.button", defaultValue: "Decrypt"))
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(ciphertextInput.isEmpty || isDecrypting)
            }

            if let decryptedText {
                Section {
                    Text(decryptedText)
                        .textSelection(.enabled)
                } header: {
                    Text(String(localized: "decrypt.result", defaultValue: "Decrypted Message"))
                }
            }

            if let sigVerification = signatureVerification {
                Section {
                    HStack {
                        Image(systemName: sigVerification.symbolName)
                            .foregroundStyle(Color(sigVerification.statusColor))
                        Text(sigVerification.statusDescription)
                            .font(.subheadline)
                    }
                } header: {
                    Text(String(localized: "decrypt.signature", defaultValue: "Signature"))
                }
            }
        }
        .navigationTitle(String(localized: "decrypt.title", defaultValue: "Decrypt"))
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

    private func decrypt() {
        isDecrypting = true
        let service = decryptionService
        let inputData = Data(ciphertextInput.utf8)
        Task {
            do {
                let result = try await service.decryptMessage(ciphertext: inputData)

                if let text = String(data: result.plaintext, encoding: .utf8) {
                    decryptedText = text
                }
                signatureVerification = result.signature

                // Zeroize plaintext data
                var mutablePlaintext = result.plaintext
                mutablePlaintext.resetBytes(in: 0..<mutablePlaintext.count)
            } catch {
                self.error = CypherAirError.from(error) { .corruptData(reason: $0) }
                showError = true
            }
            isDecrypting = false
        }
    }
}
