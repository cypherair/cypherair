import SwiftUI
import UIKit

/// Text encryption view: plaintext input, recipient selection, signature toggle.
struct EncryptView: View {
    @Environment(EncryptionService.self) private var encryptionService
    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(ContactService.self) private var contactService
    @Environment(AppConfiguration.self) private var config

    @State private var plaintext = ""
    @State private var selectedRecipients: Set<String> = []
    @State private var signMessage = true
    @State private var signerFingerprint: String?
    @State private var isEncrypting = false
    @State private var ciphertext: Data?
    @State private var error: CypherAirError?
    @State private var showError = false
    @State private var showClipboardNotice = false

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
                        HStack {
                            compatibilityIndicator(for: contact)
                            VStack(alignment: .leading) {
                                Text(contact.displayName)
                                Text(contact.profile.displayName)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
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

                if signMessage && keyManagement.keys.count > 1 {
                    Picker(
                        String(localized: "encrypt.signingKey", defaultValue: "Signing Key"),
                        selection: $signerFingerprint
                    ) {
                        ForEach(keyManagement.keys) { key in
                            Text(key.userId ?? key.shortKeyId)
                                .tag(Optional(key.fingerprint))
                        }
                    }
                }
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

                    HStack {
                        Button {
                            UIPasteboard.general.string = ciphertextString
                            if config.clipboardNotice {
                                showClipboardNotice = true
                            }
                        } label: {
                            Label(
                                String(localized: "common.copy", defaultValue: "Copy"),
                                systemImage: "doc.on.doc"
                            )
                        }

                        Spacer()

                        ShareLink(
                            item: ciphertextString,
                            preview: SharePreview(String(localized: "encrypt.share.preview", defaultValue: "Encrypted Message"))
                        ) {
                            Label(
                                String(localized: "common.share", defaultValue: "Share"),
                                systemImage: "square.and.arrow.up"
                            )
                        }
                    }
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
        .alert(
            String(localized: "clipboard.notice.title", defaultValue: "Copied to Clipboard"),
            isPresented: $showClipboardNotice
        ) {
            Button(String(localized: "clipboard.notice.dismiss", defaultValue: "OK")) {}
            Button(String(localized: "clipboard.notice.dontShow", defaultValue: "Don't Show Again")) {
                config.clipboardNotice = false
            }
        } message: {
            Text(String(localized: "clipboard.notice.message", defaultValue: "The encrypted message has been copied. Remember to clear your clipboard after pasting."))
        }
        .onAppear {
            signerFingerprint = keyManagement.defaultKey?.fingerprint
        }
    }

    private func compatibilityIndicator(for contact: Contact) -> some View {
        Group {
            if contact.isExpired || contact.isRevoked {
                Image(systemName: "xmark.circle.fill")
                    .foregroundStyle(.red)
                    .accessibilityLabel(String(localized: "encrypt.compat.expired", defaultValue: "Key expired or revoked"))
            } else if keyManagement.defaultKey?.keyVersion == 6 && contact.keyVersion == 4 {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .accessibilityLabel(String(localized: "encrypt.compat.downgrade", defaultValue: "Format downgrade to SEIPDv1"))
            } else {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                    .accessibilityLabel(String(localized: "encrypt.compat.ok", defaultValue: "Compatible"))
            }
        }
    }

    private func encrypt() {
        isEncrypting = true
        let service = encryptionService
        let text = plaintext
        let recipients = Array(selectedRecipients)
        let signerFp = signMessage ? signerFingerprint : nil
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
