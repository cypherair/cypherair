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

    struct RuntimeSyncKey: Equatable {
        let allowedImportModes: [ImportMode]
        let prefilledArmoredText: String?
        let verificationPolicy: Configuration.VerificationPolicy
        let hasOnImported: Bool
        let hasOnImportConfirmationRequested: Bool

        init(configuration: Configuration) {
            allowedImportModes = configuration.allowedImportModes
            prefilledArmoredText = configuration.prefilledArmoredText
            verificationPolicy = configuration.verificationPolicy
            hasOnImported = configuration.onImported != nil
            hasOnImportConfirmationRequested = configuration.onImportConfirmationRequested != nil
        }
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

    let configuration: Configuration

    init(configuration: Configuration = .default) {
        self.configuration = configuration
    }

    var body: some View {
        AddContactScreenHostView(
            importLoader: PublicKeyImportLoader(qrService: qrService),
            importWorkflow: ContactImportWorkflow(contactService: contactService),
            importConfirmationCoordinator: importConfirmationCoordinator,
            configuration: configuration,
            dismissAction: { dismiss() }
        )
    }
}

private struct AddContactScreenHostView: View {
    let importLoader: PublicKeyImportLoader
    let importWorkflow: ContactImportWorkflow
    let importConfirmationCoordinator: ImportConfirmationCoordinator?
    let configuration: AddContactView.Configuration
    let dismissAction: @MainActor () -> Void

    @State private var model: AddContactScreenModel
    @State private var selectedPhotoItem: PhotosPickerItem?
    @State private var fallbackImportConfirmationCoordinator = ImportConfirmationCoordinator()

    init(
        importLoader: PublicKeyImportLoader,
        importWorkflow: ContactImportWorkflow,
        importConfirmationCoordinator: ImportConfirmationCoordinator?,
        configuration: AddContactView.Configuration,
        dismissAction: @escaping @MainActor () -> Void
    ) {
        self.importLoader = importLoader
        self.importWorkflow = importWorkflow
        self.importConfirmationCoordinator = importConfirmationCoordinator
        self.configuration = configuration
        self.dismissAction = dismissAction
        _model = State(
            initialValue: AddContactScreenModel(
                importLoader: importLoader,
                importWorkflow: importWorkflow,
                configuration: configuration
            )
        )
    }

    var body: some View {
        wrappedContent
            .onAppear {
                model.handleAppear()
            }
            .onChange(of: selectedPhotoItem) { _, newItem in
                guard let newItem else {
                    return
                }

                model.processSelectedQRPhoto {
                    try await importLoader.loadKeyDataFromQRPhoto(newItem)
                }
            }
            .onChange(of: runtimeSyncKey) { _, _ in
                model.updateConfiguration(configuration)
            }
    }

    @ViewBuilder
    private var wrappedContent: some View {
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
        @Bindable var model = model

        return Form {
            Section {
                Picker(
                    String(localized: "addcontact.mode", defaultValue: "Import Method"),
                    selection: Binding(
                        get: { model.importMode },
                        set: { model.setImportMode($0) }
                    )
                ) {
                    ForEach(model.configuration.allowedImportModes, id: \.self) { mode in
                        Text(mode.label).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .disabled(model.configuration.allowedImportModes.count == 1)
            }

            switch model.importMode {
            case .paste:
                pasteContent
            case .qrPhoto:
                qrPhotoContent
            case .file:
                fileContent
            }

            Section {
                Button {
                    model.addContact(actions: hostActions)
                } label: {
                    Text(String(localized: "addcontact.add", defaultValue: "Add Contact"))
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.addButtonDisabled)
                .accessibilityIdentifier("addcontact.add")
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
            isPresented: Binding(
                get: { model.showError },
                set: { if !$0 { model.dismissError() } }
            ),
            presenting: model.error
        ) { _ in
            Button(String(localized: "error.ok", defaultValue: "OK")) {}
        } message: { err in
            Text(err.localizedDescription)
        }
        .alert(
            String(localized: "addcontact.keyUpdate.title", defaultValue: "Key Update Detected"),
            isPresented: Binding(
                get: { model.showKeyUpdateAlert },
                set: { if !$0 { model.dismissPendingKeyUpdateRequest() } }
            ),
            presenting: model.pendingKeyUpdateRequest
        ) { request in
            Button(String(localized: "addcontact.keyUpdate.confirm", defaultValue: "Replace Key"), role: .destructive) {
                model.confirmPendingKeyUpdate()
            }
            Button(String(localized: "addcontact.keyUpdate.cancel", defaultValue: "Cancel"), role: .cancel) {
                model.cancelPendingKeyUpdate()
            }
        } message: { request in
            Text(String(localized: "addcontact.keyUpdate.message",
                        defaultValue: "This contact (\(request.pendingUpdate.existingContact.displayName)) has a new key with a different fingerprint. Verify with the contact before accepting. Replace the existing key?"))
        }
        .fileImporter(
            isPresented: $model.showFileImporter,
            allowedContentTypes: [
                UTType(filenameExtension: "asc") ?? .plainText,
                UTType(filenameExtension: "gpg") ?? .data,
                UTType(filenameExtension: "pgp") ?? .data,
                .data
            ],
            allowsMultipleSelection: false
        ) { result in
            if case .success(let urls) = result, let url = urls.first {
                model.loadFileContents(from: url)
            }
        }
    }

    @ViewBuilder
    private var pasteContent: some View {
        @Bindable var model = model

        Section {
            CypherMultilineTextInput(
                text: $model.armoredText,
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
        @Bindable var model = model

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

            if model.isProcessingQR {
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
                model.requestFileImport()
            } label: {
                Label(
                    String(localized: "addcontact.file.select", defaultValue: "Select Key File"),
                    systemImage: "doc"
                )
            }

            if let fileName = model.importedFileName, model.importedKeyData != nil {
                HStack {
                    Label(fileName, systemImage: "doc.fill")
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    Button {
                        model.clearImportedFile()
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

    private var activeImportConfirmationCoordinator: ImportConfirmationCoordinator {
        importConfirmationCoordinator ?? fallbackImportConfirmationCoordinator
    }

    private var hostActions: AddContactScreenHostActions {
        AddContactScreenHostActions(
            presentImportConfirmation: { request in
                if let onImportConfirmationRequested = configuration.onImportConfirmationRequested {
                    onImportConfirmationRequested(request)
                } else {
                    activeImportConfirmationCoordinator.present(request)
                }
            },
            dismissPresentedImportConfirmation: {
                activeImportConfirmationCoordinator.dismiss()
            },
            completeImportedContact: { contact in
                configuration.onImported?(contact)
                if configuration.onImported == nil {
                    dismissAction()
                }
            }
        )
    }

    private var runtimeSyncKey: AddContactView.RuntimeSyncKey {
        AddContactView.RuntimeSyncKey(configuration: configuration)
    }
}
