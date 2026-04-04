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
    @State private var signedMessage: String?
    @State private var detachedSignature: Data?
    @State private var showFileImporter = false
    @State private var selectedFileURL: URL?
    @State private var selectedFileName: String?
    @State private var operation = OperationController()
    @State private var exportController = FileExportController()

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
                    if operation.isRunning {
                        HStack {
                            if signMode == .file, let progress = operation.progress {
                                ProgressView(value: progress.fractionCompleted)
                                    .progressViewStyle(.linear)
                                Text(String(localized: "sign.signing", defaultValue: "Signing..."))
                            } else {
                                ProgressView()
                            }
                            if signMode == .file {
                                Spacer()
                                Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .destructive) {
                                    operation.cancel()
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
                        operation.copyToClipboard(signedMessage, config: config)
                    } label: {
                        Label(
                            String(localized: "common.copy", defaultValue: "Copy"),
                            systemImage: "doc.on.doc"
                        )
                    }

                    Button {
                        do {
                            try exportController.prepareDataExport(
                                Data(signedMessage.utf8),
                                suggestedFilename: "signed.asc"
                            )
                        } catch {
                            operation.present(error: mapSigningError(error))
                        }
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
                        guard let detachedSignature else { return }
                        do {
                            try exportController.prepareDataExport(
                                detachedSignature,
                                suggestedFilename: (selectedFileName ?? "file") + ".sig"
                            )
                        } catch {
                            operation.present(error: mapSigningError(error))
                        }
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
                get: { exportController.isPresented },
                set: { if !$0 { exportController.finish() } }
            ),
            item: exportController.payload,
            contentTypes: [.data],
            defaultFilename: exportController.defaultFilename
        ) { result in
            exportController.finish()
            if case .failure(let exportError) = result {
                operation.present(error: mapSigningError(exportError))
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
            CypherMultilineTextInput(
                text: $text,
                mode: .prose
            )
                .frame(
                    minHeight: editorHeightRange.min,
                    idealHeight: editorHeightRange.ideal,
                    maxHeight: editorHeightRange.max
                )
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
        if operation.isRunning { return true }
        if keyManagement.defaultKey == nil && signerFingerprint == nil { return true }
        switch signMode {
        case .text: return text.isEmpty
        case .file: return selectedFileURL == nil
        }
    }

    private var editorHeightRange: (min: CGFloat, ideal: CGFloat, max: CGFloat) {
        #if canImport(UIKit)
        return (110, 160, 240)
        #else
        return (150, 220, 320)
        #endif
    }

    // MARK: - Actions

    private func signText() {
        guard let signerFp = signerFingerprint ?? keyManagement.defaultKey?.fingerprint else { return }
        let service = signingService
        let message = text
        signedMessage = nil
        operation.run(mapError: mapSigningError) {
            let signed = try await service.signCleartext(message, signerFingerprint: signerFp)
            signedMessage = String(data: signed, encoding: .utf8)
        }
    }

    private func signFile() {
        guard let fileURL = selectedFileURL,
              let signerFp = signerFingerprint ?? keyManagement.defaultKey?.fingerprint else { return }
        let service = signingService
        detachedSignature = nil
        operation.runFileOperation(mapError: mapSigningError) { progress in
            let sig = try await SecurityScopedFileAccess.withAccess(
                to: [
                    SecurityScopedAccessRequest(
                        resource: fileURL,
                        failure: .internalError(
                            reason: String(
                                localized: "sign.cannotAccessFile",
                                defaultValue: "Cannot access selected file"
                            )
                        )
                    )
                ]
            ) {
                try await service.signDetachedStreaming(
                    fileURL: fileURL,
                    signerFingerprint: signerFp,
                    progress: progress
                )
            }
            try Task.checkCancellation()
            detachedSignature = sig
        }
    }

    private func mapSigningError(_ error: Error) -> CypherAirError {
        CypherAirError.from(error) { .signingFailed(reason: $0) }
    }
}
