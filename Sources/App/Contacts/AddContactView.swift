import SwiftUI
import PhotosUI
import UniformTypeIdentifiers

/// Unified contact import: paste public key, QR photo, or file.
struct AddContactView: View {
    @Environment(ContactService.self) private var contactService
    @Environment(QRService.self) private var qrService
    @Environment(\.dismiss) private var dismiss

    enum ImportMode: String, CaseIterable {
        case paste, qrPhoto, file
        var label: String {
            switch self {
            case .paste: String(localized: "addcontact.mode.paste", defaultValue: "Paste")
            case .qrPhoto: String(localized: "addcontact.mode.qrPhoto", defaultValue: "QR Photo")
            case .file: String(localized: "addcontact.mode.file", defaultValue: "File")
            }
        }
    }

    @State private var importMode: ImportMode = .paste
    @State private var armoredText = ""
    @State private var error: CypherAirError?
    @State private var showError = false
    @State private var pendingKeyUpdate: PendingKeyUpdate?
    @State private var showKeyUpdateAlert = false

    // QR Photo state
    @State private var selectedPhotoItem: PhotosPickerItem?
    @State private var isProcessingQR = false

    // File import state
    @State private var showFileImporter = false
    /// Raw key data for binary .gpg/.pgp files that cannot be represented as a String.
    @State private var importedKeyData: Data?
    @State private var importedFileName: String?

    var body: some View {
        Form {
            Section {
                Picker(String(localized: "addcontact.mode", defaultValue: "Import Method"), selection: $importMode) {
                    ForEach(ImportMode.allCases, id: \.self) { mode in
                        Text(mode.label).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
            }

            switch importMode {
            case .paste:
                pasteContent

            case .qrPhoto:
                qrPhotoContent

            case .file:
                fileContent
            }

            Section {
                Button {
                    addContact()
                } label: {
                    Text(String(localized: "addcontact.add", defaultValue: "Add Contact"))
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .disabled(addButtonDisabled)
            }
        }
        #if canImport(UIKit)
        .scrollDismissesKeyboard(.interactively)
        #endif
        #if os(macOS)
        .formStyle(.grouped)
        #endif
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
        .fileImporter(
            isPresented: $showFileImporter,
            allowedContentTypes: [
                UTType(filenameExtension: "asc") ?? .plainText,
                UTType(filenameExtension: "gpg") ?? .data,
                UTType(filenameExtension: "pgp") ?? .data,
                .data
            ],
            allowsMultipleSelection: false
        ) { result in
            if case .success(let urls) = result, let url = urls.first {
                loadFileContents(from: url)
            }
        }
        .onChange(of: importMode) { _, _ in
            // Clear stale binary data when switching modes
            importedKeyData = nil
            importedFileName = nil
        }
        .onChange(of: selectedPhotoItem) { _, newItem in
            guard let newItem else { return }
            processQRPhoto(newItem)
        }
    }

    // MARK: - Subviews

    @ViewBuilder
    private var pasteContent: some View {
        Section {
            TextEditor(text: $armoredText)
                .font(.system(.body, design: .monospaced))
                #if canImport(UIKit)
                .frame(minHeight: 120)
                #else
                .frame(minHeight: 200)
                #endif
        } header: {
            Text(String(localized: "addcontact.paste.header", defaultValue: "Paste public key (armored or binary)"))
        }
    }

    @ViewBuilder
    private var qrPhotoContent: some View {
        Section {
            PhotosPicker(
                selection: $selectedPhotoItem,
                matching: .images
            ) {
                Label(
                    String(localized: "addcontact.qr.selectPhoto", defaultValue: "Choose Photo"),
                    systemImage: "photo.on.rectangle"
                )
            }

            if isProcessingQR {
                ProgressView(String(localized: "addcontact.qr.scanning", defaultValue: "Scanning QR code..."))
            }
        } header: {
            Text(String(localized: "addcontact.qr.header", defaultValue: "QR Code from Photo"))
        }
    }

    @ViewBuilder
    private var fileContent: some View {
        Section {
            Button {
                showFileImporter = true
            } label: {
                Label(
                    String(localized: "addcontact.file.select", defaultValue: "Select Key File"),
                    systemImage: "doc"
                )
            }

            if let fileName = importedFileName, importedKeyData != nil {
                HStack {
                    Label(fileName, systemImage: "doc.fill")
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    Button {
                        importedKeyData = nil
                        importedFileName = nil
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(String(localized: "addcontact.clearFile", defaultValue: "Clear file"))
                }
            }
        } header: {
            Text(String(localized: "addcontact.file.header", defaultValue: "Public Key File (.asc, .gpg, .pgp)"))
        }
    }

    // MARK: - State

    private var addButtonDisabled: Bool {
        switch importMode {
        case .paste: return armoredText.isEmpty
        case .qrPhoto: return (armoredText.isEmpty && importedKeyData == nil) || isProcessingQR
        case .file: return armoredText.isEmpty && importedKeyData == nil
        }
    }

    // MARK: - Actions

    private func addContact() {
        do {
            let data = importedKeyData ?? Data(armoredText.utf8)
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

    private func processQRPhoto(_ item: PhotosPickerItem) {
        isProcessingQR = true
        let service = qrService
        Task {
            defer { isProcessingQR = false }
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

                guard let urlString = qrStrings.first(where: { $0.hasPrefix("cypherair://") }),
                      let url = URL(string: urlString) else {
                    error = .invalidQRCode
                    showError = true
                    return
                }

                let publicKeyData = try service.parseImportURL(url)
                // Populate armoredText so the user must confirm via the "Add Contact" button
                // rather than bypassing the confirmation flow (PRD Section 4.2).
                if let armoredString = String(data: publicKeyData, encoding: .utf8) {
                    armoredText = armoredString
                    importedKeyData = nil
                    importedFileName = nil
                } else {
                    // Binary key data — store raw Data, bypass String conversion
                    importedKeyData = publicKeyData
                    importedFileName = String(localized: "addcontact.qr.binaryKey", defaultValue: "Binary key from QR")
                    armoredText = ""
                }
            } catch {
                self.error = CypherAirError.from(error) { _ in .invalidQRCode }
                showError = true
            }
        }
    }

    private func loadFileContents(from url: URL) {
        guard url.startAccessingSecurityScopedResource() else { return }
        defer { url.stopAccessingSecurityScopedResource() }
        do {
            let data = try Data(contentsOf: url)
            if let text = String(data: data, encoding: .utf8) {
                armoredText = text
                importedKeyData = nil
                importedFileName = nil
            } else {
                // Binary .gpg/.pgp key — store raw Data, bypass String conversion
                importedKeyData = data
                importedFileName = url.lastPathComponent
                armoredText = ""
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
