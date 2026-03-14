import SwiftUI
import UIKit
import UniformTypeIdentifiers

/// Cleartext and detached signing view.
struct SignView: View {
    @Environment(SigningService.self) private var signingService
    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(AppConfiguration.self) private var config

    enum SignMode: String, CaseIterable {
        case text, file
        var label: String {
            switch self {
            case .text: String(localized: "sign.mode.text", defaultValue: "Text")
            case .file: String(localized: "sign.mode.file", defaultValue: "File")
            }
        }
    }

    @State private var signMode: SignMode = .text
    @State private var text = ""
    @State private var signerFingerprint: String?
    @State private var isSigning = false
    @State private var signedMessage: String?
    @State private var detachedSignature: Data?
    @State private var error: CypherAirError?
    @State private var showError = false
    @State private var showClipboardNotice = false
    @State private var showFileImporter = false
    @State private var selectedFileURL: URL?
    @State private var selectedFileName: String?

    var body: some View {
        Form {
            Section {
                Picker(String(localized: "sign.mode", defaultValue: "Mode"), selection: $signMode) {
                    ForEach(SignMode.allCases, id: \.self) { mode in
                        Text(mode.label).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
            }

            if signMode == .text {
                textSigningContent
            } else {
                fileSigningContent
            }

            Section {
                if keyManagement.keys.count > 1 {
                    Picker(
                        String(localized: "sign.signingKey", defaultValue: "Signing Key"),
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
                    if signMode == .text {
                        signText()
                    } else {
                        signFile()
                    }
                } label: {
                    if isSigning {
                        ProgressView()
                            .frame(maxWidth: .infinity)
                    } else {
                        Text(String(localized: "sign.button", defaultValue: "Sign"))
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(signButtonDisabled)
            }

            if signMode == .text, let signedMessage {
                Section {
                    Text(signedMessage)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)

                    HStack {
                        Button {
                            UIPasteboard.general.string = signedMessage
                            if config.clipboardNotice {
                                showClipboardNotice = true
                            }
                        } label: {
                            Label(
                                String(localized: "common.copy", defaultValue: "Copy"),
                                systemImage: "doc.on.doc"
                            )
                        }

                        Spacer()

                        ShareLink(
                            item: signedMessage,
                            preview: SharePreview(String(localized: "sign.share.preview", defaultValue: "Signed Message"))
                        ) {
                            Label(
                                String(localized: "common.share", defaultValue: "Share"),
                                systemImage: "square.and.arrow.up"
                            )
                        }
                    }
                } header: {
                    Text(String(localized: "sign.result", defaultValue: "Signed Message"))
                }
            }

            if signMode == .file, let detachedSignature,
               let sigURL = detachedSignature.writeToShareTempFile(named: (selectedFileName ?? "file") + ".sig") {
                Section {
                    ShareLink(item: sigURL) {
                        Label(
                            String(localized: "sign.share.signature", defaultValue: "Share .sig File"),
                            systemImage: "square.and.arrow.up"
                        )
                    }
                } header: {
                    Text(String(localized: "sign.detached.result", defaultValue: "Detached Signature"))
                }
            }
        }
        .navigationTitle(String(localized: "sign.title", defaultValue: "Sign"))
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
            Text(String(localized: "clipboard.notice.message", defaultValue: "The signed message has been copied. Remember to clear your clipboard after pasting."))
        }
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
        .onAppear {
            signerFingerprint = keyManagement.defaultKey?.fingerprint
        }
    }

    // MARK: - Subviews

    @ViewBuilder
    private var textSigningContent: some View {
        Section {
            TextEditor(text: $text)
                .frame(minHeight: 100)
        } header: {
            Text(String(localized: "sign.input", defaultValue: "Message to Sign"))
        }
    }

    @ViewBuilder
    private var fileSigningContent: some View {
        Section {
            Button {
                showFileImporter = true
            } label: {
                Label(
                    String(localized: "sign.selectFile", defaultValue: "Select File"),
                    systemImage: "doc"
                )
            }

            if let selectedFileName {
                LabeledContent(
                    String(localized: "sign.selectedFile", defaultValue: "Selected"),
                    value: selectedFileName
                )
            }
        } header: {
            Text(String(localized: "sign.file.header", defaultValue: "File to Sign"))
        }
    }

    // MARK: - State

    private var signButtonDisabled: Bool {
        if isSigning { return true }
        if keyManagement.defaultKey == nil && signerFingerprint == nil { return true }
        switch signMode {
        case .text: return text.isEmpty
        case .file: return selectedFileURL == nil
        }
    }

    // MARK: - Actions

    private func signText() {
        guard let signerFp = signerFingerprint ?? keyManagement.defaultKey?.fingerprint else { return }
        isSigning = true
        let service = signingService
        let message = text
        Task {
            do {
                let signed = try await service.signCleartext(message, signerFingerprint: signerFp)
                signedMessage = String(data: signed, encoding: .utf8)
            } catch {
                self.error = CypherAirError.from(error) { .signingFailed(reason: $0) }
                showError = true
            }
            isSigning = false
        }
    }

    private func signFile() {
        guard let fileURL = selectedFileURL,
              let signerFp = signerFingerprint ?? keyManagement.defaultKey?.fingerprint else { return }
        isSigning = true
        let service = signingService
        Task {
            do {
                guard fileURL.startAccessingSecurityScopedResource() else {
                    throw CypherAirError.internalError(reason: "Cannot access selected file")
                }
                defer { fileURL.stopAccessingSecurityScopedResource() }
                let fileData = try Data(contentsOf: fileURL)
                let sig = try await service.signDetached(fileData, signerFingerprint: signerFp)
                detachedSignature = sig
            } catch {
                self.error = CypherAirError.from(error) { .signingFailed(reason: $0) }
                showError = true
            }
            isSigning = false
        }
    }
}
