import PhotosUI
import SwiftUI
import UniformTypeIdentifiers

/// Unified contact import: paste public key, QR photo, or file.
struct AddContactView: View {
    struct Configuration {
        enum VerificationPolicy: Equatable {
            case verifiedOnly
            case allowUnverified
        }

        var allowedImportModes: [ImportMode] = ImportMode.allCases
        var prefilledArmoredText: String?
        var verificationPolicy: VerificationPolicy = .allowUnverified
        var onImported: (@MainActor (Contact) -> Void)?
        var onImportConfirmationRequested: (@MainActor (ImportConfirmationRequest) -> Void)?

        static let `default` = Configuration()
    }

    @Environment(ContactService.self) private var contactService
    @Environment(QRService.self) private var qrService
    @Environment(\.dismiss) private var dismiss
    @Environment(\.importConfirmationCoordinator) private var importConfirmationCoordinator

    enum ImportMode: String, CaseIterable {
        case paste
        case qrPhoto
        case file

        var label: String {
            switch self {
            case .paste:
                String(localized: "addcontact.mode.paste", defaultValue: "Paste")
            case .qrPhoto:
                String(localized: "addcontact.mode.qrPhoto", defaultValue: "QR Photo")
            case .file:
                String(localized: "addcontact.mode.file", defaultValue: "File")
            }
        }
    }

    private struct PendingKeyUpdate {
        let newContact: Contact
        let existingContact: Contact
        let keyData: Data
    }

    let configuration: Configuration

    @State private var importMode: ImportMode = .paste
    @State private var armoredText = ""
    @State private var error: CypherAirError?
    @State private var showError = false
    @State private var pendingKeyUpdate: PendingKeyUpdate?
    @State private var showKeyUpdateAlert = false
    @State private var selectedPhotoItem: PhotosPickerItem?
    @State private var isProcessingQR = false
    @State private var showFileImporter = false
    @State private var importedKeyData: Data?
    @State private var importedFileName: String?
    @State private var fallbackImportConfirmationCoordinator = ImportConfirmationCoordinator()

    init(configuration: Configuration = .default) {
        self.configuration = configuration
    }

    var body: some View {
        if importConfirmationCoordinator == nil,
           configuration.onImportConfirmationRequested == nil {
            ImportConfirmationSheetHost(coordinator: fallbackImportConfirmationCoordinator) {
                formContent
            }
        } else {
            formContent
        }
    }

    private var formContent: some View {
        Form {
            Section {
                Picker(String(localized: "addcontact.mode", defaultValue: "Import Method"), selection: $importMode) {
                    ForEach(configuration.allowedImportModes, id: \.self) { mode in
                        Text(mode.label).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .disabled(configuration.allowedImportModes.count == 1)
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
            importedKeyData = nil
            importedFileName = nil
        }
        .onAppear {
            importMode = configuration.allowedImportModes.first ?? .paste
            if armoredText.isEmpty, let prefilled = configuration.prefilledArmoredText {
                armoredText = prefilled
            }
        }
        .onChange(of: selectedPhotoItem) { _, newItem in
            guard let newItem else { return }
            processQRPhoto(newItem)
        }
    }

    @ViewBuilder
    private var pasteContent: some View {
        Section {
            CypherMultilineTextInput(
                text: $armoredText,
                mode: .machineText
            )
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
                            .frame(minWidth: 44, minHeight: 44)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(String(localized: "addcontact.clearFile", defaultValue: "Clear file"))
                }
            }
        } header: {
            Text(String(localized: "addcontact.file.header", defaultValue: "Public Key File (.asc, .gpg, .pgp)"))
        }
    }

    private var addButtonDisabled: Bool {
        switch importMode {
        case .paste:
            armoredText.isEmpty
        case .qrPhoto:
            (armoredText.isEmpty && importedKeyData == nil) || isProcessingQR
        case .file:
            armoredText.isEmpty && importedKeyData == nil
        }
    }

    private func addContact() {
        do {
            let data = importedKeyData ?? Data(armoredText.utf8)
            let keyInfo = try qrService.inspectKeyInfo(keyData: data)
            let profile = try qrService.detectKeyProfile(keyData: data)
            let request = ImportConfirmationRequest(
                keyData: data,
                keyInfo: keyInfo,
                profile: profile,
                allowsUnverifiedImport: configuration.verificationPolicy == .allowUnverified,
                onImportVerified: {
                    completeAddContact(
                        keyData: data,
                        verificationState: .verified
                    )
                },
                onImportUnverified: {
                    completeAddContact(
                        keyData: data,
                        verificationState: .unverified
                    )
                },
                onCancel: { }
            )

            if let onImportConfirmationRequested = configuration.onImportConfirmationRequested {
                onImportConfirmationRequested(request)
            } else {
                activeImportConfirmationCoordinator.present(request)
            }
        } catch {
            self.error = CypherAirError.from(error) { .invalidKeyData(reason: $0) }
            showError = true
        }
    }

    private func completeAddContact(
        keyData: Data,
        verificationState: ContactVerificationState
    ) {
        do {
            let result = try contactService.addContact(
                publicKeyData: keyData,
                verificationState: verificationState
            )
            switch result {
            case .added(let contact), .duplicate(let contact):
                activeImportConfirmationCoordinator.dismiss()
                Task { @MainActor in
                    configuration.onImported?(contact)
                }
                if configuration.onImported == nil {
                    dismiss()
                }
            case .keyUpdateDetected(let newContact, let existingContact, let keyData):
                activeImportConfirmationCoordinator.dismiss()
                pendingKeyUpdate = PendingKeyUpdate(
                    newContact: newContact,
                    existingContact: existingContact,
                    keyData: keyData
                )
                showKeyUpdateAlert = true
            }
        } catch {
            self.error = CypherAirError.from(error) { .invalidKeyData(reason: $0) }
            activeImportConfirmationCoordinator.dismiss()
            showError = true
        }
    }

    private var activeImportConfirmationCoordinator: ImportConfirmationCoordinator {
        importConfirmationCoordinator ?? fallbackImportConfirmationCoordinator
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
                if let armoredString = String(data: publicKeyData, encoding: .utf8) {
                    armoredText = armoredString
                    importedKeyData = nil
                    importedFileName = nil
                } else {
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
        do {
            let data = try withSecurityScopedAccess(
                to: url,
                failure: .invalidKeyData(reason: String(localized: "addcontact.file.readFailed", defaultValue: "Could not read key file"))
            ) {
                try Data(contentsOf: url)
            }

            if let armoredString = String(data: data, encoding: .utf8) {
                armoredText = armoredString
                importedKeyData = nil
            } else {
                armoredText = ""
                importedKeyData = data
            }
            importedFileName = url.lastPathComponent
        } catch let error as CypherAirError {
            self.error = error
            showError = true
        } catch {
            self.error = CypherAirError.from(error) { .invalidKeyData(reason: $0) }
            showError = true
        }
    }

    private func withSecurityScopedAccess<T>(
        to url: URL,
        failure: CypherAirError,
        operation: () throws -> T
    ) throws -> T {
        guard url.startAccessingSecurityScopedResource() else {
            throw failure
        }

        defer { url.stopAccessingSecurityScopedResource() }
        return try operation()
    }
}
