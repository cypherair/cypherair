import SwiftUI
#if canImport(UIKit)
import UIKit
#endif
#if canImport(AppKit)
import AppKit
#endif
import UniformTypeIdentifiers

/// Unified text and file encryption view with segmented mode picker.
struct EncryptView: View {
    struct Configuration {
        enum TogglePolicy {
            case appDefault
            case initial(Bool)
            case fixed(Bool)

            func initialValue(appDefault: Bool) -> Bool {
                switch self {
                case .appDefault:
                    appDefault
                case .initial(let value), .fixed(let value):
                    value
                }
            }

            var isLocked: Bool {
                if case .fixed = self {
                    return true
                }
                return false
            }
        }

        var allowedModes: [EncryptMode] = EncryptMode.allCases
        var prefilledPlaintext: String?
        var initialRecipientFingerprints: [String] = []
        var initialSignerFingerprint: String?
        var signingPolicy: TogglePolicy = .initial(true)
        var encryptToSelfPolicy: TogglePolicy = .appDefault
        var onEncrypted: (@MainActor (Data) -> Void)?

        static let `default` = Configuration()
    }

    enum EncryptMode: String, CaseIterable {
        case text
        case file

        var label: String {
            switch self {
            case .text:
                String(localized: "encrypt.mode.text", defaultValue: "Text")
            case .file:
                String(localized: "encrypt.mode.file", defaultValue: "File")
            }
        }
    }

    @Environment(EncryptionService.self) private var encryptionService
    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(ContactService.self) private var contactService
    @Environment(AppConfiguration.self) private var config

    let configuration: Configuration

    @State private var encryptMode: EncryptMode = .text
    @State private var plaintext = ""
    @State private var selectedRecipients: Set<String> = []
    @State private var signMessage = true
    @State private var signerFingerprint: String?
    @State private var ciphertext: Data?
    @State private var encryptToSelf: Bool?
    @State private var encryptToSelfFingerprint: String?
    @State private var operation = OperationController()
    @State private var showFileImporter = false
    @State private var selectedFileURL: URL?
    @State private var selectedFileName: String?
    @State private var encryptedFileURL: URL?
    @State private var exportController = FileExportController()
    @State private var showUnverifiedRecipientsWarning = false

    init(configuration: Configuration = .default) {
        self.configuration = configuration
    }

    var body: some View {
        Form {
            Section {
                Picker(String(localized: "encrypt.mode", defaultValue: "Mode"), selection: $encryptMode) {
                    ForEach(configuration.allowedModes, id: \.self) { mode in
                        Text(mode.label).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .disabled(configuration.allowedModes.count == 1)
            }

            if encryptMode == .text {
                textInputContent
            } else {
                fileInputContent
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
                        HStack {
                            compatibilityIndicator(for: contact)
                            VStack(alignment: .leading) {
                                Text(contact.displayName)
                                HStack(spacing: 6) {
                                    Text(contact.profile.displayName)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                    if !contact.isVerified {
                                        Text(String(localized: "encrypt.contact.unverified", defaultValue: "Unverified"))
                                            .font(.caption2.weight(.semibold))
                                            .padding(.horizontal, 6)
                                            .padding(.vertical, 2)
                                            .background(Color.orange.opacity(0.14), in: Capsule())
                                            .foregroundStyle(.orange)
                                    }
                                }
                            }
                        }
                    }
                }

                if !selectedUnverifiedContacts.isEmpty {
                    Label(
                        String(
                            localized: "encrypt.unverified.warning",
                            defaultValue: "One or more selected recipients are still unverified. Verify their fingerprints before relying on them."
                        ),
                        systemImage: "exclamationmark.triangle.fill"
                    )
                    .font(.footnote)
                    .foregroundStyle(.orange)
                }
            } header: {
                Text(String(localized: "encrypt.recipients", defaultValue: "Recipients"))
            }

            Section {
                Toggle(
                    String(localized: "encrypt.encryptToSelf", defaultValue: "Encrypt to Self"),
                    isOn: Binding(
                        get: { encryptToSelf ?? config.encryptToSelf },
                        set: { encryptToSelf = $0 }
                    )
                )
                .disabled(configuration.encryptToSelfPolicy.isLocked)

                if (encryptToSelf ?? config.encryptToSelf) && keyManagement.keys.count > 1 {
                    Picker(
                        String(localized: "encrypt.encryptToSelfKey", defaultValue: "Encrypt to Self With"),
                        selection: $encryptToSelfFingerprint
                    ) {
                        ForEach(keyManagement.keys) { key in
                            Text(key.userId ?? key.shortKeyId)
                                .tag(Optional(key.fingerprint))
                        }
                    }
                }

                Toggle(
                    String(localized: "encrypt.sign", defaultValue: "Sign Message"),
                    isOn: $signMessage
                )
                .disabled(configuration.signingPolicy.isLocked)

                if signMessage && keyManagement.keys.count > 1 {
                    Picker(
                        String(localized: "encrypt.signingKey", defaultValue: "Signing Key"),
                        selection: $signerFingerprint
                    ) {
                        ForEach(keyManagement.keys) { key in
                            Text(key.userId ?? key.shortKeyId)
                                .tag(Optional(key.fingerprint))
                        }
                    }
                }
            }

            Section {
                Button {
                    requestEncrypt()
                } label: {
                    if operation.isRunning {
                        HStack {
                            if encryptMode == .file, let progress = operation.progress {
                                ProgressView(value: progress.fractionCompleted)
                                    .progressViewStyle(.linear)
                                Text(String(localized: "fileEncrypt.encrypting", defaultValue: "Encrypting..."))
                            } else {
                                ProgressView()
                            }
                            if encryptMode == .file {
                                Spacer()
                                Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .destructive) {
                                    operation.cancel()
                                }
                            }
                        }
                        .frame(maxWidth: .infinity)
                    } else {
                        Text(String(localized: "encrypt.button", defaultValue: "Encrypt"))
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(encryptButtonDisabled)
            }

            if encryptMode == .text, let ciphertext, let ciphertextString = String(data: ciphertext, encoding: .utf8) {
                Section {
                    Text(ciphertextString)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)

                    Button {
                        operation.copyToClipboard(ciphertextString, config: config)
                    } label: {
                        Label(
                            String(localized: "common.copy", defaultValue: "Copy"),
                            systemImage: "doc.on.doc"
                        )
                    }

                    Button {
                        do {
                            try exportController.prepareDataExport(
                                ciphertext,
                                suggestedFilename: "encrypted.asc"
                            )
                        } catch {
                            operation.present(
                                error: .encryptionFailed(
                                    reason: String(
                                        localized: "fileEncrypt.readFailed",
                                        defaultValue: "Could not read encrypted file"
                                    )
                                )
                            )
                        }
                    } label: {
                        Label(
                            String(localized: "common.save", defaultValue: "Save"),
                            systemImage: "square.and.arrow.down"
                        )
                    }
                } header: {
                    Text(String(localized: "encrypt.result", defaultValue: "Encrypted Message"))
                }
            }

            if encryptMode == .file, encryptedFileURL != nil {
                Section {
                    Button {
                        if let url = encryptedFileURL {
                            guard FileManager.default.fileExists(atPath: url.path) else {
                                operation.present(
                                    error: .encryptionFailed(
                                        reason: String(
                                            localized: "fileEncrypt.readFailed",
                                            defaultValue: "Could not read encrypted file"
                                        )
                                    )
                                )
                                return
                            }
                            exportController.prepareFileExport(
                                fileURL: url,
                                suggestedFilename: (selectedFileName ?? "file") + ".gpg"
                            )
                        }
                    } label: {
                        Label(
                            String(localized: "fileEncrypt.share", defaultValue: "Save Encrypted File"),
                            systemImage: "square.and.arrow.down"
                        )
                    }
                }
            }
        }
        #if canImport(UIKit)
        .scrollDismissesKeyboard(.interactively)
        #endif
        #if os(macOS)
        .formStyle(.grouped)
        #endif
        .navigationTitle(String(localized: "encrypt.title", defaultValue: "Encrypt"))
        .fileImporter(
            isPresented: $showFileImporter,
            allowedContentTypes: [.data],
            allowsMultipleSelection: false
        ) { result in
            if case .success(let urls) = result, let url = urls.first {
                selectedFileURL = url
                selectedFileName = url.lastPathComponent
            }
        }
        .alert(
            String(localized: "error.title", defaultValue: "Error"),
            isPresented: Binding(
                get: { operation.isShowingError },
                set: { if !$0 { operation.dismissError() } }
            ),
            presenting: operation.error
        ) { _ in
            Button(String(localized: "error.ok", defaultValue: "OK")) {}
        } message: { err in
            Text(err.localizedDescription)
        }
        .alert(
            String(localized: "clipboard.notice.title", defaultValue: "Copied to Clipboard"),
            isPresented: Binding(
                get: { operation.isShowingClipboardNotice },
                set: { if !$0 { operation.dismissClipboardNotice() } }
            )
        ) {
            Button(String(localized: "clipboard.notice.dismiss", defaultValue: "OK")) {
                operation.dismissClipboardNotice()
            }
            Button(String(localized: "clipboard.notice.dontShow", defaultValue: "Don't Show Again")) {
                operation.dismissClipboardNotice(disableFutureNoticesIn: config)
            }
        } message: {
            Text(String(localized: "clipboard.notice.message", defaultValue: "The encrypted message has been copied. Remember to clear your clipboard after pasting."))
        }
        .fileExporter(
            isPresented: Binding(
                get: { exportController.isPresented },
                set: { if !$0 { exportController.finish() } }
            ),
            item: exportController.payload,
            contentTypes: [.data],
            defaultFilename: exportController.defaultFilename
        ) { result in
            exportController.finish()
            if case .failure(let exportError) = result {
                operation.present(error: mapEncryptionError(exportError))
            }
        }
        .confirmationDialog(
            String(localized: "encrypt.unverified.confirm.title", defaultValue: "Use Unverified Recipients?"),
            isPresented: $showUnverifiedRecipientsWarning,
            titleVisibility: .visible
        ) {
            Button(String(localized: "encrypt.unverified.confirm.action", defaultValue: "Encrypt Anyway")) {
                performEncrypt()
            }
            Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .cancel) { }
        } message: {
            Text(
                String.localizedStringWithFormat(
                    String(
                        localized: "encrypt.unverified.confirm.message",
                        defaultValue: "These recipients are not verified yet: %@. Continue only if you trust these keys."
                    ),
                    selectedUnverifiedContacts.map(\.displayName).joined(separator: ", ")
                )
            )
        }
        .onAppear {
            encryptMode = configuration.allowedModes.first ?? .text

            if plaintext.isEmpty, let prefilledPlaintext = configuration.prefilledPlaintext {
                plaintext = prefilledPlaintext
            }
            if !configuration.initialRecipientFingerprints.isEmpty {
                selectedRecipients = Set(configuration.initialRecipientFingerprints)
            }

            let defaultSigner = configuration.initialSignerFingerprint ?? keyManagement.defaultKey?.fingerprint
            signerFingerprint = defaultSigner
            encryptToSelfFingerprint = defaultSigner
            signMessage = configuration.signingPolicy.initialValue(appDefault: true)
            encryptToSelf = configuration.encryptToSelfPolicy.initialValue(appDefault: config.encryptToSelf)
        }
    }

    @ViewBuilder
    private var textInputContent: some View {
        Section {
            TextEditor(text: $plaintext)
                .frame(
                    minHeight: editorHeightRange.min,
                    idealHeight: editorHeightRange.ideal,
                    maxHeight: editorHeightRange.max
                )
        } header: {
            Text(String(localized: "encrypt.plaintext", defaultValue: "Message"))
        }
    }

    @ViewBuilder
    private var fileInputContent: some View {
        Section {
            Button {
                showFileImporter = true
            } label: {
                Label(
                    String(localized: "fileEncrypt.selectFile", defaultValue: "Select File"),
                    systemImage: "doc.badge.plus"
                )
            }

            if let selectedFileName {
                LabeledContent(
                    String(localized: "fileEncrypt.selectedFile", defaultValue: "Selected"),
                    value: selectedFileName
                )
            }
        } header: {
            Text(String(localized: "fileEncrypt.file", defaultValue: "File"))
        }
    }

    private func compatibilityIndicator(for contact: Contact) -> some View {
        Group {
            if contact.isExpired || contact.isRevoked {
                Image(systemName: "xmark.circle.fill")
                    .foregroundStyle(.red)
                    .accessibilityLabel(String(localized: "encrypt.compat.expired", defaultValue: "Key expired or revoked"))
            } else if keyManagement.defaultKey?.keyVersion == 6 && contact.keyVersion == 4 {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .accessibilityLabel(String(localized: "encrypt.compat.downgrade", defaultValue: "Format downgrade to SEIPDv1"))
            } else {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                    .accessibilityLabel(String(localized: "encrypt.compat.ok", defaultValue: "Compatible"))
            }
        }
    }

    private var encryptButtonDisabled: Bool {
        if operation.isRunning { return true }
        if selectedRecipients.isEmpty { return true }
        switch encryptMode {
        case .text:
            return plaintext.isEmpty
        case .file:
            return selectedFileURL == nil
        }
    }

    private var selectedUnverifiedContacts: [Contact] {
        contactService.contacts
            .filter { selectedRecipients.contains($0.fingerprint) && !$0.isVerified }
    }

    private var editorHeightRange: (min: CGFloat, ideal: CGFloat, max: CGFloat) {
        #if canImport(UIKit)
        (110, 160, 240)
        #else
        (150, 220, 320)
        #endif
    }

    private func requestEncrypt() {
        if !selectedUnverifiedContacts.isEmpty {
            showUnverifiedRecipientsWarning = true
            return
        }

        performEncrypt()
    }

    private func performEncrypt() {
        if encryptMode == .text {
            encryptText()
        } else {
            encryptFile()
        }
    }

    private func encryptText() {
        let service = encryptionService
        let text = plaintext
        let recipients = Array(selectedRecipients)
        let signerFp = signMessage ? signerFingerprint : nil
        let selfEncrypt = encryptToSelf ?? config.encryptToSelf
        let selfEncryptFp = selfEncrypt ? encryptToSelfFingerprint : nil
        ciphertext = nil
        operation.run(mapError: mapEncryptionError) {
            let result = try await service.encryptText(
                text,
                recipientFingerprints: recipients,
                signWithFingerprint: signerFp,
                encryptToSelf: selfEncrypt,
                encryptToSelfFingerprint: selfEncryptFp
            )
            ciphertext = result
            configuration.onEncrypted?(result)
        }
    }

    private func encryptFile() {
        guard let fileURL = selectedFileURL else { return }
        let service = encryptionService
        let recipients = Array(selectedRecipients)
        let signerFp = signMessage ? signerFingerprint : nil
        let selfEncrypt = encryptToSelf ?? config.encryptToSelf
        let selfEncryptFp = selfEncrypt ? encryptToSelfFingerprint : nil
        encryptedFileURL = nil
        operation.runFileOperation(mapError: mapEncryptionError) { progress in
            let result = try await SecurityScopedFileAccess.withAccess(
                to: [
                    SecurityScopedAccessRequest(
                        resource: fileURL,
                        failure: .corruptData(
                            reason: String(
                                localized: "fileEncrypt.cannotAccess",
                                defaultValue: "Cannot access file"
                            )
                        )
                    )
                ]
            ) {
                try await service.encryptFileStreaming(
                    inputURL: fileURL,
                    recipientFingerprints: recipients,
                    signWithFingerprint: signerFp,
                    encryptToSelf: selfEncrypt,
                    encryptToSelfFingerprint: selfEncryptFp,
                    progress: progress
                )
            }
            try Task.checkCancellation()
            encryptedFileURL = result
        }
    }

    private func mapEncryptionError(_ error: Error) -> CypherAirError {
        CypherAirError.from(error) { .encryptionFailed(reason: $0) }
    }
}
