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

    @State private var selectedItem: PhotosPickerItem?
    @State private var isProcessing = false
    @State private var importedContact: Contact?
    @State private var error: CypherAirError?
    @State private var showError = false
    @State private var showSuccess = false
    @State private var pendingConfirm: PendingQRImport?
    @State private var pendingKeyUpdate: PendingQRKeyUpdate?
    @State private var showKeyUpdateAlert = false

    var body: some View {
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
        .sheet(item: $pendingConfirm) { pending in
            ImportConfirmView(
                keyInfo: pending.keyInfo,
                detectedProfile: pending.profile,
                onImportVerified: {
                    confirmImport(
                        pending,
                        verificationState: .verified
                    )
                },
                onImportUnverified: {
                    confirmImport(
                        pending,
                        verificationState: .unverified
                    )
                },
                onCancel: {
                    pendingConfirm = nil
                }
            )
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

                // PRD §4.2: Show confirmation with fingerprint verification before adding.
                let keyInfo = try service.inspectKeyInfo(keyData: publicKeyData)
                let profile = try service.detectKeyProfile(keyData: publicKeyData)
                pendingConfirm = PendingQRImport(
                    keyData: publicKeyData,
                    keyInfo: keyInfo,
                    profile: profile
                )
            } catch {
                self.error = CypherAirError.from(error) { _ in .invalidQRCode }
                showError = true
            }
        }
    }

    private func confirmImport(
        _ pending: PendingQRImport,
        verificationState: ContactVerificationState
    ) {
        do {
            let result = try contactService.addContact(
                publicKeyData: pending.keyData,
                verificationState: verificationState
            )
            switch result {
            case .added(let contact), .duplicate(let contact):
                importedContact = contact
                pendingConfirm = nil
                showSuccess = true
            case .keyUpdateDetected(let newContact, let existingContact, let keyData):
                pendingConfirm = nil
                pendingKeyUpdate = PendingQRKeyUpdate(
                    newContact: newContact,
                    existingContact: existingContact,
                    keyData: keyData
                )
                showKeyUpdateAlert = true
            }
        } catch {
            self.error = CypherAirError.from(error) { _ in .invalidQRCode }
            pendingConfirm = nil
            showError = true
        }
    }
}

/// Holds parsed key data pending user confirmation via ImportConfirmView.
private struct PendingQRImport: Identifiable {
    let id = UUID()
    let keyData: Data
    let keyInfo: KeyInfo
    let profile: KeyProfile
}

/// Holds state for a pending key update confirmation via QR import.
private struct PendingQRKeyUpdate {
    let newContact: Contact
    let existingContact: Contact
    let keyData: Data
}
