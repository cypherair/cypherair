import SwiftUI

/// Unified contact import: paste public key or QR photo.
struct AddContactView: View {
    @Environment(ContactService.self) private var contactService
    @Environment(\.dismiss) private var dismiss

    @State private var armoredText = ""
    @State private var error: CypherAirError?
    @State private var showError = false

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
    }

    private func addFromPaste() {
        do {
            let data = Data(armoredText.utf8)
            _ = try contactService.addContact(publicKeyData: data)
            dismiss()
        } catch let err as CypherAirError {
            error = err
            showError = true
        } catch let pgpError as PgpError {
            error = CypherAirError(pgpError: pgpError)
            showError = true
        } catch {
            self.error = .invalidKeyData(reason: error.localizedDescription)
            showError = true
        }
    }
}
