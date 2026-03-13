import SwiftUI

/// Shows details of a contact's public key.
struct ContactDetailView: View {
    let fingerprint: String

    @Environment(ContactService.self) private var contactService

    private var contact: Contact? {
        contactService.contact(forFingerprint: fingerprint)
    }

    var body: some View {
        Group {
            if let contact {
                List {
                    Section {
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
                            String(localized: "contactdetail.algo", defaultValue: "Algorithm"),
                            value: [contact.primaryAlgo, contact.subkeyAlgo].compactMap { $0 }.joined(separator: " + ")
                        )
                    }

                    Section {
                        Text(contact.formattedFingerprint)
                            .font(.system(.body, design: .monospaced))
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
                    }

                    Section {
                        Button(role: .destructive) {
                            try? contactService.removeContact(fingerprint: fingerprint)
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
        .navigationTitle(String(localized: "contactdetail.title", defaultValue: "Contact"))
    }
}
