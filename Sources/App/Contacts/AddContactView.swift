import SwiftUI

/// Unified contact import: paste public key or QR photo.
struct AddContactView: View {
    @Environment(ContactService.self) private var contactService
    @Environment(\.dismiss) private var dismiss

    @State private var armoredText = ""
    @State private var error: CypherAirError?
    @State private var showError = false
    @State private var pendingKeyUpdate: PendingKeyUpdate?
    @State private var showKeyUpdateAlert = false

    var body: some View {
        Form {
            Section {
                TextEditor(text: $armoredText)
                    .font(.system(.body, design: .monospaced))
                    .frame(minHeight: 120)
            } header: {
                Text(String(localized: "addcontact.paste.header", defaultValue: "Paste public key (armored or binary)"))
            }

            Section {
                Button {
                    addFromPaste()
                } label: {
                    Text(String(localized: "addcontact.add", defaultValue: "Add Contact"))
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .disabled(armoredText.isEmpty)
            }
        }
        .navigationTitle(String(localized: "addcontact.title", defaultValue: "Add Contact"))
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
            String(localized: "addcontact.keyUpdate.title", defaultValue: "Key Update Detected"),
            isPresented: $showKeyUpdateAlert,
            presenting: pendingKeyUpdate
        ) { update in
            Button(String(localized: "addcontact.keyUpdate.confirm", defaultValue: "Replace Key"), role: .destructive) {
                do {
                    try contactService.confirmKeyUpdate(
                        existingFingerprint: update.existingContact.fingerprint,
                        newContact: update.newContact,
                        keyData: update.keyData
                    )
                    dismiss()
                } catch {
                    self.error = CypherAirError.from(error) { .invalidKeyData(reason: $0) }
                    showError = true
                }
            }
            Button(String(localized: "addcontact.keyUpdate.cancel", defaultValue: "Cancel"), role: .cancel) {}
        } message: { update in
            Text(String(localized: "addcontact.keyUpdate.message",
                        defaultValue: "This contact (\(update.existingContact.displayName)) has a new key with a different fingerprint. Verify with the contact before accepting. Replace the existing key?"))
        }
    }

    private func addFromPaste() {
        do {
            let data = Data(armoredText.utf8)
            let result = try contactService.addContact(publicKeyData: data)
            switch result {
            case .added, .duplicate:
                dismiss()
            case .keyUpdateDetected(let newContact, let existingContact, let keyData):
                pendingKeyUpdate = PendingKeyUpdate(
                    newContact: newContact,
                    existingContact: existingContact,
                    keyData: keyData
                )
                showKeyUpdateAlert = true
            }
        } catch {
            self.error = CypherAirError.from(error) { .invalidKeyData(reason: $0) }
            showError = true
        }
    }
}

/// Holds state for a pending key update confirmation.
private struct PendingKeyUpdate {
    let newContact: Contact
    let existingContact: Contact
    let keyData: Data
}
