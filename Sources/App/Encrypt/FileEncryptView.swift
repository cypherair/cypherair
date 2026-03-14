import SwiftUI
import UIKit
import UniformTypeIdentifiers

/// File encryption view with document picker and progress.
/// Supports files up to 100 MB.
struct FileEncryptView: View {
    @Environment(EncryptionService.self) private var encryptionService
    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(ContactService.self) private var contactService
    @Environment(AppConfiguration.self) private var config

    @State private var selectedRecipients: Set<String> = []
    @State private var signMessage = true
    @State private var isEncrypting = false
    @State private var showDocumentPicker = false
    @State private var encryptedData: Data?
    @State private var originalFilename: String?
    @State private var error: CypherAirError?
    @State private var showError = false
    @State private var currentTask: Task<Void, Never>?

    var body: some View {
        Form {
            Section {
                Button {
                    showDocumentPicker = true
                } label: {
                    Label(
                        String(localized: "fileEncrypt.selectFile", defaultValue: "Select File"),
                        systemImage: "doc.badge.plus"
                    )
                }
            } header: {
                Text(String(localized: "fileEncrypt.file", defaultValue: "File"))
            } footer: {
                Text(String(localized: "fileEncrypt.sizeLimit", defaultValue: "Maximum file size: 100 MB"))
            }

            Section {
                ForEach(contactService.contacts.filter(\.canEncryptTo)) { contact in
                    Toggle(isOn: Binding(
                        get: { selectedRecipients.contains(contact.fingerprint) },
                        set: { isOn in
                            if isOn {
                                selectedRecipients.insert(contact.fingerprint)
                            } else {
                                selectedRecipients.remove(contact.fingerprint)
                            }
                        }
                    )) {
                        Text(contact.displayName)
                    }
                }
            } header: {
                Text(String(localized: "encrypt.recipients", defaultValue: "Recipients"))
            }

            Section {
                Toggle(
                    String(localized: "encrypt.sign", defaultValue: "Sign Message"),
                    isOn: $signMessage
                )
            }

            if isEncrypting {
                Section {
                    HStack {
                        ProgressView(String(localized: "fileEncrypt.encrypting", defaultValue: "Encrypting..."))
                        Spacer()
                        Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .destructive) {
                            currentTask?.cancel()
                            currentTask = nil
                            isEncrypting = false
                        }
                    }
                }
            }

            if let data = encryptedData {
                Section {
                    ShareLink(
                        item: data,
                        preview: SharePreview(
                            "\(originalFilename ?? "encrypted").gpg",
                            image: Image(systemName: "lock.doc")
                        )
                    ) {
                        Label(
                            String(localized: "fileEncrypt.share", defaultValue: "Share Encrypted File"),
                            systemImage: "square.and.arrow.up"
                        )
                    }
                }
            }
        }
        .navigationTitle(String(localized: "fileEncrypt.title", defaultValue: "Encrypt File"))
        .fileImporter(
            isPresented: $showDocumentPicker,
            allowedContentTypes: [.data],
            allowsMultipleSelection: false
        ) { result in
            handleFileSelection(result)
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
    }

    private func handleFileSelection(_ result: Result<[URL], Error>) {
        guard case .success(let urls) = result, let url = urls.first else { return }

        originalFilename = url.lastPathComponent
        let service = encryptionService
        let recipients = Array(selectedRecipients)
        let signerFp = signMessage ? keyManagement.defaultKey?.fingerprint : nil
        let selfEncrypt = config.encryptToSelf

        isEncrypting = true
        currentTask = Task {
            var bgTaskID = UIBackgroundTaskIdentifier.invalid
            bgTaskID = UIApplication.shared.beginBackgroundTask {
                UIApplication.shared.endBackgroundTask(bgTaskID)
                bgTaskID = .invalid
            }
            defer {
                if bgTaskID != .invalid {
                    UIApplication.shared.endBackgroundTask(bgTaskID)
                }
                isEncrypting = false
                currentTask = nil
            }
            do {
                guard url.startAccessingSecurityScopedResource() else {
                    error = .corruptData(reason: "Cannot access file")
                    showError = true
                    return
                }
                defer { url.stopAccessingSecurityScopedResource() }

                let fileData = try Data(contentsOf: url)
                try Task.checkCancellation()
                let result = try await service.encryptFile(
                    fileData,
                    recipientFingerprints: recipients,
                    signWithFingerprint: signerFp,
                    encryptToSelf: selfEncrypt
                )
                try Task.checkCancellation()
                encryptedData = result
            } catch is CancellationError {
                // User cancelled — no error to show
            } catch {
                self.error = CypherAirError.from(error) { .encryptionFailed(reason: $0) }
                showError = true
            }
        }
    }
}
