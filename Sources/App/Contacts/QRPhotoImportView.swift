import SwiftUI
import PhotosUI

/// Import a public key from a QR code in a photo.
/// Uses PHPickerViewController (no photo library permission required)
/// and CIDetector for QR code detection.
///
/// PRD §4.2: All import paths require user confirmation with fingerprint verification reminder.
struct QRPhotoImportView: View {
    @Environment(QRService.self) private var qrService
    @Environment(ContactService.self) private var contactService
    @Environment(\.dismiss) private var dismiss
    @Environment(\.importConfirmationCoordinator) private var importConfirmationCoordinator

    @State private var selectedItem: PhotosPickerItem?
    @State private var isProcessing = false
    @State private var importedContact: Contact?
    @State private var error: CypherAirError?
    @State private var showError = false
    @State private var showSuccess = false
    @State private var pendingKeyUpdateRequest: ContactKeyUpdateConfirmationRequest?
    @State private var showKeyUpdateAlert = false
    @State private var fallbackImportConfirmationCoordinator = ImportConfirmationCoordinator()

    private var importLoader: PublicKeyImportLoader {
        PublicKeyImportLoader(qrService: qrService)
    }

    private var importWorkflow: ContactImportWorkflow {
        ContactImportWorkflow(contactService: contactService)
    }

    var body: some View {
        if importConfirmationCoordinator == nil {
            ImportConfirmationSheetHost(coordinator: fallbackImportConfirmationCoordinator) {
                content
            }
        } else {
            content
        }
    }

    private var content: some View {
        VStack(spacing: 24) {
            Image(systemName: "qrcode.viewfinder")
                .font(.system(size: 64))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)

            Text(String(localized: "qrImport.instruction", defaultValue: "Select a photo containing a CypherAir QR code."))
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
            presenting: pendingKeyUpdateRequest
        ) { request in
            Button(String(localized: "addcontact.keyUpdate.confirm", defaultValue: "Replace Key"), role: .destructive) {
                pendingKeyUpdateRequest = nil
                request.onConfirm()
            }
            Button(String(localized: "addcontact.keyUpdate.cancel", defaultValue: "Cancel"), role: .cancel) {
                pendingKeyUpdateRequest = nil
                request.onCancel()
            }
        } message: { request in
            Text(String(localized: "addcontact.keyUpdate.message",
                        defaultValue: "This contact (\(request.pendingUpdate.existingContact.displayName)) has a new key with a different fingerprint. Verify with the contact before accepting. Replace the existing key?"))
        }
    }

    private func processSelectedPhoto(_ item: PhotosPickerItem) {
        isProcessing = true
        Task {
            defer { isProcessing = false }
            do {
                let inspection = try await importLoader.loadFromQRPhoto(item)
                activeImportConfirmationCoordinator.present(
                    importWorkflow.makeImportConfirmationRequest(
                        inspection: inspection,
                        allowsUnverifiedImport: true,
                        onSuccess: { contact in
                            activeImportConfirmationCoordinator.dismiss()
                            importedContact = contact
                            showSuccess = true
                        },
                        onReplaceRequested: { request in
                            activeImportConfirmationCoordinator.dismiss()
                            pendingKeyUpdateRequest = request
                            showKeyUpdateAlert = true
                        },
                        onFailure: { importError in
                            error = importError
                            activeImportConfirmationCoordinator.dismiss()
                            showError = true
                        }
                    )
                )
            } catch {
                self.error = CypherAirError.from(error) { _ in .invalidQRCode }
                showError = true
            }
        }
    }

    private var activeImportConfirmationCoordinator: ImportConfirmationCoordinator {
        importConfirmationCoordinator ?? fallbackImportConfirmationCoordinator
    }
}
