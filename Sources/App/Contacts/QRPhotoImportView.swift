import SwiftUI
import PhotosUI

/// Import a public key from a QR code in a photo.
/// Uses PHPickerViewController (no photo library permission required)
/// and CIDetector for QR code detection.
struct QRPhotoImportView: View {
    @Environment(QRService.self) private var qrService
    @Environment(ContactService.self) private var contactService
    @Environment(\.dismiss) private var dismiss

    @State private var selectedItem: PhotosPickerItem?
    @State private var isProcessing = false
    @State private var importedContact: Contact?
    @State private var error: CypherAirError?
    @State private var showError = false
    @State private var showSuccess = false
    @State private var pendingKeyUpdate: PendingQRKeyUpdate?
    @State private var showKeyUpdateAlert = false

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: "qrcode.viewfinder")
                .font(.system(size: 64))
                .foregroundStyle(.secondary)

            Text(String(localized: "qrImport.instruction", defaultValue: "Select a photo containing a Cypher Air QR code."))
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)

            PhotosPicker(
                selection: $selectedItem,
                matching: .images
            ) {
                Label(
                    String(localized: "qrImport.selectPhoto", defaultValue: "Choose Photo"),
                    systemImage: "photo.on.rectangle"
                )
            }
            .buttonStyle(.borderedProminent)

            if isProcessing {
                ProgressView(String(localized: "qrImport.processing", defaultValue: "Scanning QR code..."))
            }
        }
        .padding()
        .navigationTitle(String(localized: "qrImport.title", defaultValue: "QR from Photo"))
        .onChange(of: selectedItem) { _, newItem in
            guard let newItem else { return }
            processSelectedPhoto(newItem)
        }
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
            String(localized: "qrImport.success.title", defaultValue: "Contact Added"),
            isPresented: $showSuccess
        ) {
            Button(String(localized: "error.ok", defaultValue: "OK")) {
                dismiss()
            }
        } message: {
            if let contact = importedContact {
                Text(contact.displayName)
            }
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
                    importedContact = update.newContact
                    showSuccess = true
                } catch {
                    self.error = CypherAirError.from(error) { _ in .invalidQRCode }
                    showError = true
                }
            }
            Button(String(localized: "addcontact.keyUpdate.cancel", defaultValue: "Cancel"), role: .cancel) {}
        } message: { update in
            Text(String(localized: "addcontact.keyUpdate.message",
                        defaultValue: "This contact (\(update.existingContact.displayName)) has a new key with a different fingerprint. Verify with the contact before accepting. Replace the existing key?"))
        }
    }

    private func processSelectedPhoto(_ item: PhotosPickerItem) {
        isProcessing = true
        let service = qrService
        let contacts = contactService
        Task {
            defer { isProcessing = false }
            do {
                guard let data = try await item.loadTransferable(type: Data.self) else {
                    error = .invalidQRCode
                    showError = true
                    return
                }

                guard let ciImage = CIImage(data: data) else {
                    error = .invalidQRCode
                    showError = true
                    return
                }

                let qrStrings = try await service.decodeQRCodes(from: ciImage)

                // Find the first cypherair:// URL
                guard let urlString = qrStrings.first(where: { $0.hasPrefix("cypherair://") }),
                      let url = URL(string: urlString) else {
                    error = .invalidQRCode
                    showError = true
                    return
                }

                let publicKeyData = try service.parseImportURL(url)
                let result = try contacts.addContact(publicKeyData: publicKeyData)
                switch result {
                case .added(let contact), .duplicate(let contact):
                    importedContact = contact
                    showSuccess = true
                case .keyUpdateDetected(let newContact, let existingContact, let keyData):
                    pendingKeyUpdate = PendingQRKeyUpdate(
                        newContact: newContact,
                        existingContact: existingContact,
                        keyData: keyData
                    )
                    showKeyUpdateAlert = true
                }
            } catch {
                self.error = CypherAirError.from(error) { _ in .invalidQRCode }
                showError = true
            }
        }
    }
}

/// Holds state for a pending key update confirmation via QR import.
private struct PendingQRKeyUpdate {
    let newContact: Contact
    let existingContact: Contact
    let keyData: Data
}
