import SwiftUI
#if canImport(UIKit)
import UIKit
#endif
#if canImport(AppKit)
import AppKit
#endif
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
    @State private var currentTask: Task<Void, Never>?
    @State private var fileProgress: FileProgressReporter?
    private enum SignExportType {
        case signedText
        case detachedSig
    }
    @State private var activeSignExport: SignExportType?

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
                        HStack {
                            if signMode == .file, let progress = fileProgress {
                                ProgressView(value: progress.fractionCompleted)
                                    .progressViewStyle(.linear)
                                Text(String(localized: "sign.signing", defaultValue: "Signing..."))
                            } else {
                                ProgressView()
                            }
                            if signMode == .file {
                                Spacer()
                                Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .destructive) {
                                    fileProgress?.cancel()
                                    currentTask?.cancel()
                                    currentTask = nil
                                    isSigning = false
                                }
                            }
                        }
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

                    Button {
                        #if canImport(UIKit)
                        UIPasteboard.general.string = signedMessage
                        #elseif canImport(AppKit)
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(signedMessage, forType: .string)
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

                    Button {
                        activeSignExport = .signedText
                    } label: {
                        Label(
                            String(localized: "common.save", defaultValue: "Save"),
                            systemImage: "square.and.arrow.down"
                        )
                    }
                } header: {
                    Text(String(localized: "sign.result", defaultValue: "Signed Message"))
                }
            }

            if signMode == .file, detachedSignature != nil {
                Section {
                    Button {
                        activeSignExport = .detachedSig
                    } label: {
                        Label(
                            String(localized: "sign.share.signature", defaultValue: "Save .sig File"),
                            systemImage: "square.and.arrow.down"
                        )
                    }
                } header: {
                    Text(String(localized: "sign.detached.result", defaultValue: "Detached Signature"))
                }
            }
        }
        #if canImport(UIKit)
        .scrollDismissesKeyboard(.interactively)
        #endif
        #if os(macOS)
        .formStyle(.grouped)
        #endif
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
        .fileExporter(
            isPresented: Binding(
                get: { activeSignExport != nil },
                set: { if !$0 { activeSignExport = nil } }
            ),
            item: signExportItem,
            contentTypes: [.data],
            defaultFilename: signExportFilename
        ) { result in
            activeSignExport = nil
            if case .failure(let exportError) = result {
                error = CypherAirError.from(exportError) { .signingFailed(reason: $0) }
                showError = true
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
                #if canImport(UIKit)
                .frame(minHeight: 100)
                #else
                .frame(minHeight: 250)
                #endif
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

    private var signExportItem: Data? {
        switch activeSignExport {
        case .signedText: return signedMessage.flatMap { Data($0.utf8) }
        case .detachedSig: return detachedSignature
        case nil: return nil
        }
    }

    private var signExportFilename: String {
        switch activeSignExport {
        case .signedText: return "signed.asc"
        case .detachedSig: return (selectedFileName ?? "file") + ".sig"
        case nil: return "export"
        }
    }

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
        let service = signingService
        let progress = FileProgressReporter()
        fileProgress = progress

        isSigning = true
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
                isSigning = false
                currentTask = nil
            }
            do {
                guard fileURL.startAccessingSecurityScopedResource() else {
                    throw CypherAirError.internalError(reason: String(localized: "sign.cannotAccessFile", defaultValue: "Cannot access selected file"))
                }
                defer { fileURL.stopAccessingSecurityScopedResource() }
                let sig = try await service.signDetachedStreaming(
                    fileURL: fileURL,
                    signerFingerprint: signerFp,
                    progress: progress
                )
                try Task.checkCancellation()
                detachedSignature = sig
            } catch is CancellationError {
                // User cancelled — no error to show
            } catch {
                if case .operationCancelled = error as? CypherAirError { return }
                self.error = CypherAirError.from(error) { .signingFailed(reason: $0) }
                showError = true
            }
        }
    }
}
