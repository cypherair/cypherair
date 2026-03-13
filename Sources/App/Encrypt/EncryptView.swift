import SwiftUI

/// Text encryption view: plaintext input, recipient selection, signature toggle.
struct EncryptView: View {
    @Environment(EncryptionService.self) private var encryptionService
    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(ContactService.self) private var contactService
    @Environment(AppConfiguration.self) private var config

    @State private var plaintext = ""
    @State private var selectedRecipients: Set<String> = []
    @State private var signMessage = true
    @State private var isEncrypting = false
    @State private var ciphertext: Data?
    @State private var error: CypherAirError?
    @State private var showError = false

    var body: some View {
        Form {
            Section {
                TextEditor(text: $plaintext)
                    .frame(minHeight: 100)
            } header: {
                Text(String(localized: "encrypt.plaintext", defaultValue: "Message"))
            }

            Section {
                ForEach(contactService.contacts.filter(\.canEncryptTo)) { contact in
                    Toggle(isOn: Binding(
                        get: { selectedRecipients.contains(contact.fingerprint) },
                        set: { isOn in
                            if isOn {
                                selectedRecipients.insert(contact.fingerprint)
                            } else {
                                selectedRecipients.remove(contact.fingerprint)
                            }
                        }
                    )) {
                        VStack(alignment: .leading) {
                            Text(contact.displayName)
                            Text(contact.profile.displayName)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            } header: {
                Text(String(localized: "encrypt.recipients", defaultValue: "Recipients"))
            }

            Section {
                Toggle(
                    String(localized: "encrypt.sign", defaultValue: "Sign Message"),
                    isOn: $signMessage
                )
            }

            Section {
                Button {
                    encrypt()
                } label: {
                    if isEncrypting {
                        ProgressView()
                            .frame(maxWidth: .infinity)
                    } else {
                        Text(String(localized: "encrypt.button", defaultValue: "Encrypt"))
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(plaintext.isEmpty || selectedRecipients.isEmpty || isEncrypting)
            }

            if let ciphertext, let ciphertextString = String(data: ciphertext, encoding: .utf8) {
                Section {
                    Text(ciphertextString)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                } header: {
                    Text(String(localized: "encrypt.result", defaultValue: "Encrypted Message"))
                }
            }
        }
        .navigationTitle(String(localized: "encrypt.title", defaultValue: "Encrypt"))
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

    private func encrypt() {
        isEncrypting = true
        let service = encryptionService
        let text = plaintext
        let recipients = Array(selectedRecipients)
        let signerFp = signMessage ? keyManagement.defaultKey?.fingerprint : nil
        let selfEncrypt = config.encryptToSelf
        Task {
            do {
                let result = try await service.encryptText(
                    text,
                    recipientFingerprints: recipients,
                    signWithFingerprint: signerFp,
                    encryptToSelf: selfEncrypt
                )
                ciphertext = result
            } catch {
                self.error = CypherAirError.from(error) { .encryptionFailed(reason: $0) }
                showError = true
            }
            isEncrypting = false
        }
    }
}
