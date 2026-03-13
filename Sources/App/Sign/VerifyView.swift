import SwiftUI

/// Signature verification view.
struct VerifyView: View {
    @Environment(SigningService.self) private var signingService

    @State private var signedInput = ""
    @State private var isVerifying = false
    @State private var originalText: String?
    @State private var verification: SignatureVerification?
    @State private var error: CypherAirError?
    @State private var showError = false

    var body: some View {
        Form {
            Section {
                TextEditor(text: $signedInput)
                    .font(.system(.body, design: .monospaced))
                    .frame(minHeight: 100)
            } header: {
                Text(String(localized: "verify.input", defaultValue: "Signed Message"))
            }

            Section {
                Button {
                    verify()
                } label: {
                    if isVerifying {
                        ProgressView()
                            .frame(maxWidth: .infinity)
                    } else {
                        Text(String(localized: "verify.button", defaultValue: "Verify"))
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(signedInput.isEmpty || isVerifying)
            }

            if let originalText {
                Section {
                    Text(originalText)
                        .textSelection(.enabled)
                } header: {
                    Text(String(localized: "verify.originalText", defaultValue: "Original Message"))
                }
            }

            if let verification {
                Section {
                    HStack {
                        Image(systemName: verification.symbolName)
                            .foregroundStyle(Color(verification.statusColor))
                        Text(verification.statusDescription)
                            .font(.subheadline)
                    }
                } header: {
                    Text(String(localized: "verify.result", defaultValue: "Verification Result"))
                }
            }
        }
        .navigationTitle(String(localized: "verify.title", defaultValue: "Verify"))
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

    private func verify() {
        isVerifying = true
        let service = signingService
        let inputData = Data(signedInput.utf8)
        Task {
            do {
                let result = try await service.verifyCleartext(inputData)
                if let content = result.text {
                    originalText = String(data: content, encoding: .utf8)
                }
                verification = result.verification
            } catch {
                self.error = CypherAirError.from(error) { _ in .badSignature }
                showError = true
            }
            isVerifying = false
        }
    }
}
