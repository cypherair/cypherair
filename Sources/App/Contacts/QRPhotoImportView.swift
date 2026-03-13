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
                let contact = try contacts.addContact(publicKeyData: publicKeyData)
                importedContact = contact
                showSuccess = true
            } catch let err as CypherAirError {
                error = err
                showError = true
            } catch {
                self.error = .invalidQRCode
                showError = true
            }
        }
    }
}
