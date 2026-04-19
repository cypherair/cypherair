import SwiftUI

/// Shows details of a contact's public key.
struct ContactDetailView: View {
    struct Configuration {
        var showsCertificateSignatureEntry = true
        var allowsCertificateSignatureLaunch = true
        var certificateSignatureRestrictionMessage: String?

        static let `default` = Configuration()
    }

    let fingerprint: String
    let configuration: Configuration

    @Environment(ContactService.self) private var contactService
    @Environment(\.dismiss) private var dismiss

    init(
        fingerprint: String,
        configuration: Configuration = .default
    ) {
        self.fingerprint = fingerprint
        self.configuration = configuration
    }

    @State private var showDeleteConfirmation = false
    @State private var deleteError: String?
    @State private var showDeleteError = false

    private var contact: Contact? {
        contactService.contact(forFingerprint: fingerprint)
    }

    var body: some View {
        Group {
            if let contact {
                List {
                    Section {
                        if !contact.isVerified {
                            Label(
                                String(
                                    localized: "contactdetail.unverified",
                                    defaultValue: "This contact has not been verified yet. Confirm the fingerprint with the key owner before relying on it."
                                ),
                                systemImage: "exclamationmark.triangle.fill"
                            )
                            .foregroundStyle(.orange)

                            Button {
                                do {
                                    try contactService.setVerificationState(.verified, for: fingerprint)
                                } catch {
                                    deleteError = error.localizedDescription
                                    showDeleteError = true
                                }
                            } label: {
                                Label(
                                    String(localized: "contactdetail.markVerified", defaultValue: "I Verified This Fingerprint"),
                                    systemImage: "checkmark.shield"
                                )
                            }
                        }

                        LabeledContent(
                            String(localized: "contactdetail.name", defaultValue: "Name"),
                            value: contact.displayName
                        )
                        if let email = contact.email {
                            LabeledContent(
                                String(localized: "contactdetail.email", defaultValue: "Email"),
                                value: email
                            )
                        }
                        LabeledContent(
                            String(localized: "contactdetail.profile", defaultValue: "Profile"),
                            value: contact.profile.displayName
                        )
                        LabeledContent(
                            String(localized: "contactdetail.shortKeyId", defaultValue: "Short Key ID"),
                            value: contact.shortKeyId
                        )
                        LabeledContent(
                            String(localized: "contactdetail.algo", defaultValue: "Algorithm"),
                            value: [contact.primaryAlgo, contact.subkeyAlgo].compactMap { $0 }.joined(separator: " + ")
                        )
                    }

                    Section {
                        FingerprintView(fingerprint: contact.fingerprint)
                    } header: {
                        Text(String(localized: "contactdetail.fingerprint", defaultValue: "Fingerprint"))
                    }

                    Section {
                        HStack {
                            Text(String(localized: "contactdetail.canEncrypt", defaultValue: "Can Encrypt To"))
                            Spacer()
                            Image(systemName: contact.canEncryptTo ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .foregroundStyle(contact.canEncryptTo ? .green : .red)
                        }
                        .accessibilityElement(children: .combine)
                        .accessibilityLabel(
                            contact.canEncryptTo
                                ? String(localized: "contactdetail.canEncrypt.yes", defaultValue: "Can encrypt to this contact: Yes")
                                : String(localized: "contactdetail.canEncrypt.no", defaultValue: "Can encrypt to this contact: No")
                        )
                    }

                    Section {
                        if configuration.showsCertificateSignatureEntry {
                            NavigationLink(
                                value: AppRoute.contactCertificateSignatures(fingerprint: fingerprint)
                            ) {
                                Label(
                                    String(
                                        localized: "contactdetail.certificateSignatures",
                                        defaultValue: "Certificate Signatures"
                                    ),
                                    systemImage: "checkmark.seal"
                                )
                            }
                            .disabled(!configuration.allowsCertificateSignatureLaunch)
                            .accessibilityIdentifier("contactdetail.certificateSignatures")
                        }
                    } header: {
                        Text(String(localized: "contactdetail.actions", defaultValue: "Actions"))
                    } footer: {
                        if let restrictionMessage = configuration.certificateSignatureRestrictionMessage {
                            Text(restrictionMessage)
                        }
                    }

                    Section {
                        Button(role: .destructive) {
                            showDeleteConfirmation = true
                        } label: {
                            Label(
                                String(localized: "contactdetail.delete", defaultValue: "Remove Contact"),
                                systemImage: "trash"
                            )
                        }
                    }
                }
            } else {
                ContentUnavailableView(
                    String(localized: "contactdetail.notFound", defaultValue: "Contact Not Found"),
                    systemImage: "person.slash"
                )
            }
        }
        #if os(macOS)
        .listStyle(.inset)
        #endif
        .accessibilityIdentifier("contactdetail.root")
        .screenReady("contactdetail.ready")
        .navigationTitle(String(localized: "contactdetail.title", defaultValue: "Contact"))
        .confirmationDialog(
            String(localized: "contactdetail.delete.title", defaultValue: "Remove Contact"),
            isPresented: $showDeleteConfirmation,
            titleVisibility: .visible
        ) {
            Button(String(localized: "contactdetail.delete.confirm", defaultValue: "Remove"), role: .destructive) {
                do {
                    try contactService.removeContact(fingerprint: fingerprint)
                    dismiss()
                } catch {
                    deleteError = error.localizedDescription
                    showDeleteError = true
                }
            }
            Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .cancel) {}
        } message: {
            Text(String(localized: "contactdetail.delete.message", defaultValue: "This will remove the contact's public key from your device."))
        }
        .alert(
            String(localized: "error.title", defaultValue: "Error"),
            isPresented: $showDeleteError
        ) {
            Button(String(localized: "error.ok", defaultValue: "OK")) {}
        } message: {
            if let deleteError {
                Text(deleteError)
            }
        }
    }
}
