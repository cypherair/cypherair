import SwiftUI
import UniformTypeIdentifiers

/// Signature verification view — supports cleartext and detached signatures.
struct VerifyView: View {
    @Environment(SigningService.self) private var signingService

    enum VerifyMode: String, CaseIterable {
        case cleartext, detached
        var label: String {
            switch self {
            case .cleartext: String(localized: "verify.mode.cleartext", defaultValue: "Cleartext")
            case .detached: String(localized: "verify.mode.detached", defaultValue: "Detached")
            }
        }
    }

    @State private var verifyMode: VerifyMode = .cleartext
    @State private var signedInput = ""
    // Per-mode results (preserved when switching modes, cleared on view exit)
    @State private var cleartextOriginalText: String?
    @State private var cleartextVerification: SignatureVerification?
    @State private var detachedVerification: SignatureVerification?
    @State private var operation = OperationController()

    // Detached mode state — single file importer with target tracking
    enum FilePickerTarget { case original, signature }
    @State private var filePickerTarget: FilePickerTarget?
    @State private var showFileImporter = false
    @State private var originalFileURL: URL?
    @State private var originalFileName: String?
    @State private var signatureFileURL: URL?
    @State private var signatureFileName: String?

    var body: some View {
        Form {
            Section {
                Picker(String(localized: "verify.mode", defaultValue: "Mode"), selection: $verifyMode) {
                    ForEach(VerifyMode.allCases, id: \.self) { mode in
                        Text(mode.label).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
            }

            if verifyMode == .cleartext {
                cleartextContent
            } else {
                detachedContent
            }

            Section {
                Button {
                    if verifyMode == .cleartext {
                        verifyCleartext()
                    } else {
                        verifyDetached()
                    }
                } label: {
                    if operation.isRunning {
                        HStack {
                            if verifyMode == .detached, let progress = operation.progress {
                                ProgressView(value: progress.fractionCompleted)
                                    .progressViewStyle(.linear)
                                Text(String(localized: "verify.verifying", defaultValue: "Verifying..."))
                            } else {
                                ProgressView()
                            }
                            if verifyMode == .detached {
                                Spacer()
                                Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .destructive) {
                                    operation.cancel()
                                }
                            }
                        }
                        .frame(maxWidth: .infinity)
                    } else {
                        Text(String(localized: "verify.button", defaultValue: "Verify"))
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(verifyButtonDisabled)
            }

            if verifyMode == .cleartext, let cleartextOriginalText {
                Section {
                    Text(cleartextOriginalText)
                        .textSelection(.enabled)
                } header: {
                    Text(String(localized: "verify.originalText", defaultValue: "Original Message"))
                }
            }

            if let activeVerification {
                Section {
                    HStack {
                        Image(systemName: activeVerification.symbolName)
                            .foregroundStyle(activeVerification.statusColor)
                        Text(activeVerification.statusDescription)
                            .font(.subheadline)
                    }
                    .accessibilityElement(children: .combine)
                } header: {
                    Text(String(localized: "verify.result", defaultValue: "Verification Result"))
                }
            }
        }
        #if canImport(UIKit)
        .scrollDismissesKeyboard(.interactively)
        #endif
        #if os(macOS)
        .formStyle(.grouped)
        #endif
        .navigationTitle(String(localized: "verify.title", defaultValue: "Verify"))
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
        .fileImporter(
            isPresented: $showFileImporter,
            allowedContentTypes: filePickerTarget == .signature
                ? [UTType(filenameExtension: "sig") ?? .data, .data]
                : [.data],
            allowsMultipleSelection: false
        ) { result in
            if case .success(let urls) = result, let url = urls.first {
                switch filePickerTarget {
                case .original:
                    originalFileURL = url
                    originalFileName = url.lastPathComponent
                case .signature:
                    signatureFileURL = url
                    signatureFileName = url.lastPathComponent
                case nil:
                    break
                }
            }
        }
    }

    // MARK: - Subviews

    @ViewBuilder
    private var cleartextContent: some View {
        Section {
            TextEditor(text: $signedInput)
                .font(.system(.body, design: .monospaced))
                #if canImport(UIKit)
                .frame(minHeight: 100)
                #else
                .frame(minHeight: 250)
                #endif
        } header: {
            Text(String(localized: "verify.input", defaultValue: "Signed Message"))
        }
    }

    @ViewBuilder
    private var detachedContent: some View {
        Section {
            Button {
                filePickerTarget = .original
                showFileImporter = true
            } label: {
                Label(
                    String(localized: "verify.selectOriginal", defaultValue: "Select Original File"),
                    systemImage: "doc"
                )
            }
            if let originalFileName {
                LabeledContent(
                    String(localized: "verify.originalFile", defaultValue: "Original"),
                    value: originalFileName
                )
            }
        } header: {
            Text(String(localized: "verify.detached.original", defaultValue: "Original File"))
        }

        Section {
            Button {
                filePickerTarget = .signature
                showFileImporter = true
            } label: {
                Label(
                    String(localized: "verify.selectSignature", defaultValue: "Select .sig File"),
                    systemImage: "signature"
                )
            }
            if let signatureFileName {
                LabeledContent(
                    String(localized: "verify.signatureFile", defaultValue: "Signature"),
                    value: signatureFileName
                )
            }
        } header: {
            Text(String(localized: "verify.detached.signature", defaultValue: "Signature File"))
        }
    }

    // MARK: - State

    private var activeVerification: SignatureVerification? {
        switch verifyMode {
        case .cleartext: return cleartextVerification
        case .detached: return detachedVerification
        }
    }

    private var verifyButtonDisabled: Bool {
        if operation.isRunning { return true }
        switch verifyMode {
        case .cleartext: return signedInput.isEmpty
        case .detached: return originalFileURL == nil || signatureFileURL == nil
        }
    }

    // MARK: - Actions

    private func verifyCleartext() {
        let service = signingService
        let inputData = Data(signedInput.utf8)
        cleartextOriginalText = nil
        cleartextVerification = nil
        operation.run(mapError: mapVerificationError) {
            let result = try await service.verifyCleartext(inputData)
            if let content = result.text {
                cleartextOriginalText = String(data: content, encoding: .utf8)
            }
            cleartextVerification = result.verification
        }
    }

    private func verifyDetached() {
        guard let origURL = originalFileURL, let sigURL = signatureFileURL else { return }
        let service = signingService
        detachedVerification = nil
        operation.runFileOperation(mapError: mapVerificationError) { progress in
            let result = try await SecurityScopedFileAccess.withAccess(
                to: [
                    SecurityScopedAccessRequest(
                        resource: origURL,
                        failure: .internalError(
                            reason: String(
                                localized: "verify.cannotAccessOriginal",
                                defaultValue: "Cannot access original file"
                            )
                        )
                    ),
                    SecurityScopedAccessRequest(
                        resource: sigURL,
                        failure: .internalError(
                            reason: String(
                                localized: "verify.cannotAccessSignature",
                                defaultValue: "Cannot access signature file"
                            )
                        )
                    )
                ]
            ) {
                // Load only the small .sig file into memory
                let sigData = try Data(contentsOf: sigURL)
                try Task.checkCancellation()
                // Stream the original file for verification
                return try await service.verifyDetachedStreaming(
                    fileURL: origURL,
                    signature: sigData,
                    progress: progress
                )
            }
            try Task.checkCancellation()
            detachedVerification = result
        }
    }

    private func mapVerificationError(_ error: Error) -> CypherAirError {
        CypherAirError.from(error) { _ in .badSignature }
    }
}
