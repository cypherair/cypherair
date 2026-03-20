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
    @Environment(EncryptionService.self) private var encryptionService
    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(ContactService.self) private var contactService
    @Environment(AppConfiguration.self) private var config

    enum EncryptMode: String, CaseIterable {
        case text, file
        var label: String {
            switch self {
            case .text: String(localized: "encrypt.mode.text", defaultValue: "Text")
            case .file: String(localized: "encrypt.mode.file", defaultValue: "File")
            }
        }
    }

    @State private var encryptMode: EncryptMode = .text
    @State private var plaintext = ""
    @State private var selectedRecipients: Set<String> = []
    @State private var signMessage = true
    @State private var signerFingerprint: String?
    @State private var isEncrypting = false
    @State private var ciphertext: Data?
    @State private var error: CypherAirError?
    @State private var showError = false
    @State private var showClipboardNotice = false
    @State private var encryptToSelf: Bool?
    @State private var encryptToSelfFingerprint: String?

    // File mode state
    @State private var showFileImporter = false
    @State private var selectedFileURL: URL?
    @State private var selectedFileName: String?
    @State private var encryptedFileURL: URL?
    @State private var currentTask: Task<Void, Never>?
    @State private var fileProgress: FileProgressReporter?

    var body: some View {
        Form {
            Section {
                Picker(String(localized: "encrypt.mode", defaultValue: "Mode"), selection: $encryptMode) {
                    ForEach(EncryptMode.allCases, id: \.self) { mode in
                        Text(mode.label).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
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
                                Text(contact.profile.displayName)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
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
                    if encryptMode == .text {
                        encryptText()
                    } else {
                        encryptFile()
                    }
                } label: {
                    if isEncrypting {
                        HStack {
                            if encryptMode == .file, let progress = fileProgress {
                                ProgressView(value: progress.fractionCompleted)
                                    .progressViewStyle(.linear)
                                Text(String(localized: "fileEncrypt.encrypting", defaultValue: "Encrypting..."))
                            } else {
                                ProgressView()
                            }
                            if encryptMode == .file {
                                Spacer()
                                Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .destructive) {
                                    fileProgress?.cancel()
                                    currentTask?.cancel()
                                    currentTask = nil
                                    isEncrypting = false
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

            // Text mode result
            if encryptMode == .text, let ciphertext, let ciphertextString = String(data: ciphertext, encoding: .utf8) {
                Section {
                    Text(ciphertextString)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)

                    GlassEffectContainer(spacing: 8) {
                        HStack {
                            Button {
                                #if canImport(UIKit)
                                UIPasteboard.general.string = ciphertextString
                                #elseif canImport(AppKit)
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(ciphertextString, forType: .string)
                                #endif
                                if config.clipboardNotice {
                                    showClipboardNotice = true
                                }
                            } label: {
                                Label(
                                    String(localized: "common.copy", defaultValue: "Copy"),
                                    systemImage: "doc.on.doc"
                                )
                            }
                            .glassEffect()

                            Spacer()

                            ShareLink(
                                item: ciphertextString,
                                preview: SharePreview(String(localized: "encrypt.share.preview", defaultValue: "Encrypted Message"))
                            ) {
                                Label(
                                    String(localized: "common.share", defaultValue: "Share"),
                                    systemImage: "square.and.arrow.up"
                                )
                            }
                            .glassEffect()
                        }
                    }
                } header: {
                    Text(String(localized: "encrypt.result", defaultValue: "Encrypted Message"))
                }
            }

            // File mode result
            if encryptMode == .file, let encryptedURL = encryptedFileURL {
                Section {
                    ShareLink(item: encryptedURL) {
                        Label(
                            String(localized: "fileEncrypt.share", defaultValue: "Share Encrypted File"),
                            systemImage: "square.and.arrow.up"
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
            isPresented: $showError,
            presenting: error
        ) { _ in
            Button(String(localized: "error.ok", defaultValue: "OK")) {}
        } message: { err in
            Text(err.localizedDescription)
        }
        .alert(
            String(localized: "clipboard.notice.title", defaultValue: "Copied to Clipboard"),
            isPresented: $showClipboardNotice
        ) {
            Button(String(localized: "clipboard.notice.dismiss", defaultValue: "OK")) {}
            Button(String(localized: "clipboard.notice.dontShow", defaultValue: "Don't Show Again")) {
                config.clipboardNotice = false
            }
        } message: {
            Text(String(localized: "clipboard.notice.message", defaultValue: "The encrypted message has been copied. Remember to clear your clipboard after pasting."))
        }
        .onAppear {
            signerFingerprint = keyManagement.defaultKey?.fingerprint
            encryptToSelfFingerprint = keyManagement.defaultKey?.fingerprint
        }
    }

    // MARK: - Subviews

    @ViewBuilder
    private var textInputContent: some View {
        Section {
            TextEditor(text: $plaintext)
                #if canImport(UIKit)
                .frame(minHeight: 100)
                #else
                .frame(minHeight: 250)
                #endif
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

    // MARK: - State

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
        if isEncrypting { return true }
        if selectedRecipients.isEmpty { return true }
        switch encryptMode {
        case .text: return plaintext.isEmpty
        case .file: return selectedFileURL == nil
        }
    }

    // MARK: - Actions

    private func encryptText() {
        isEncrypting = true
        let service = encryptionService
        let text = plaintext
        let recipients = Array(selectedRecipients)
        let signerFp = signMessage ? signerFingerprint : nil
        let selfEncrypt = encryptToSelf ?? config.encryptToSelf
        let selfEncryptFp = selfEncrypt ? encryptToSelfFingerprint : nil
        Task {
            do {
                let result = try await service.encryptText(
                    text,
                    recipientFingerprints: recipients,
                    signWithFingerprint: signerFp,
                    encryptToSelf: selfEncrypt,
                    encryptToSelfFingerprint: selfEncryptFp
                )
                ciphertext = result
            } catch {
                self.error = CypherAirError.from(error) { .encryptionFailed(reason: $0) }
                showError = true
            }
            isEncrypting = false
        }
    }

    private func encryptFile() {
        guard let fileURL = selectedFileURL else { return }
        let service = encryptionService
        let recipients = Array(selectedRecipients)
        let signerFp = signMessage ? signerFingerprint : nil
        let selfEncrypt = encryptToSelf ?? config.encryptToSelf
        let selfEncryptFp = selfEncrypt ? encryptToSelfFingerprint : nil

        let progress = FileProgressReporter()
        fileProgress = progress

        isEncrypting = true
        currentTask = Task {
            #if canImport(UIKit)
            var bgTaskID = UIBackgroundTaskIdentifier.invalid
            bgTaskID = UIApplication.shared.beginBackgroundTask {
                UIApplication.shared.endBackgroundTask(bgTaskID)
                bgTaskID = .invalid
            }
            #endif
            defer {
                #if canImport(UIKit)
                if bgTaskID != .invalid {
                    UIApplication.shared.endBackgroundTask(bgTaskID)
                }
                #endif
                fileProgress = nil
                isEncrypting = false
                currentTask = nil
            }
            do {
                guard fileURL.startAccessingSecurityScopedResource() else {
                    error = .corruptData(reason: String(localized: "fileEncrypt.cannotAccess", defaultValue: "Cannot access file"))
                    showError = true
                    return
                }
                defer { fileURL.stopAccessingSecurityScopedResource() }

                let result = try await service.encryptFileStreaming(
                    inputURL: fileURL,
                    recipientFingerprints: recipients,
                    signWithFingerprint: signerFp,
                    encryptToSelf: selfEncrypt,
                    encryptToSelfFingerprint: selfEncryptFp,
                    progress: progress
                )
                try Task.checkCancellation()
                encryptedFileURL = result
            } catch is CancellationError {
                // User cancelled — no error to show
            } catch {
                if case .operationCancelled = error as? CypherAirError { return }
                self.error = CypherAirError.from(error) { .encryptionFailed(reason: $0) }
                showError = true
            }
        }
    }
}
