import SwiftUI
import UniformTypeIdentifiers

/// Signature verification view — supports cleartext and detached signatures.
struct VerifyView: View {
    struct Configuration {
        var allowsCleartextFileImport = true
        var allowsDetachedOriginalImport = true
        var allowsDetachedSignatureImport = true
        var cleartextFileRestrictionMessage: String?
        var detachedFileRestrictionMessage: String?

        static let `default` = Configuration()
    }

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
    enum FilePickerTarget { case cleartextSignedImport, original, signature }
    @State private var filePickerTarget: FilePickerTarget?
    @State private var showFileImporter = false
    @State private var importedCleartext = ImportedTextInputState()
    @State private var originalFileURL: URL?
    @State private var originalFileName: String?
    @State private var signatureFileURL: URL?
    @State private var signatureFileName: String?
    @State private var textInputSectionEpoch = 0
    
    let configuration: Configuration

    init(configuration: Configuration = .default) {
        self.configuration = configuration
    }

    var body: some View {
        Form {
            Section {
                Picker(String(localized: "verify.mode", defaultValue: "Mode"), selection: $verifyMode) {
                    ForEach(VerifyMode.allCases, id: \.self) { mode in
                        Text(mode.label).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .disabled(operation.isRunning)
            }

            if verifyMode == .cleartext {
                cleartextContent
                    .disabled(operation.isRunning)
            } else {
                detachedContent
                    .disabled(operation.isRunning)
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
                                Text(
                                    operation.isCancelling
                                        ? String(localized: "common.cancelling", defaultValue: "Cancelling...")
                                        : String(localized: "verify.verifying", defaultValue: "Verifying...")
                                )
                            } else {
                                ProgressView()
                                if operation.isCancelling {
                                    Text(String(localized: "common.cancelling", defaultValue: "Cancelling..."))
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

            if showsDetachedCancelAction {
                Section {
                    if operation.isCancelling {
                        LabeledContent {
                            Text(String(localized: "common.cancelling", defaultValue: "Cancelling..."))
                                .foregroundStyle(.secondary)
                        } label: {
                            Text(String(localized: "common.cancel", defaultValue: "Cancel"))
                        }
                    } else {
                        Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .destructive) {
                            operation.cancel()
                        }
                    }
                }
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

                if activeVerification.shouldShowSignerIdentity {
                    Section {
                        SignatureIdentityCardView(verification: activeVerification)
                    } header: {
                        Text(String(localized: "verify.signer", defaultValue: "Signer"))
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
            allowedContentTypes: allowedImportContentTypes,
            allowsMultipleSelection: false
        ) { result in
            if case .success(let urls) = result, let url = urls.first {
                switch filePickerTarget {
                case .cleartextSignedImport:
                    importCleartextFile(from: url)
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
            filePickerTarget = nil
        }
        .onDisappear {
            importedCleartext.clear()
            filePickerTarget = nil
        }
    }

    // MARK: - Subviews

    @ViewBuilder
    private var cleartextContent: some View {
        Section {
            CypherMultilineTextInput(
                text: cleartextBinding,
                mode: .machineText
            )
                .frame(
                    minHeight: editorHeightRange.min,
                    idealHeight: editorHeightRange.ideal,
                    maxHeight: editorHeightRange.max
            )

            Button {
                guard configuration.allowsCleartextFileImport else { return }
                filePickerTarget = .cleartextSignedImport
                showFileImporter = true
            } label: {
                Label(
                    String(localized: "verify.importCleartextFile", defaultValue: "Import Signed File"),
                    systemImage: "doc.badge.plus"
                )
            }
            .disabled(!configuration.allowsCleartextFileImport)

            if let importedFileName = importedCleartext.fileName, importedCleartext.hasImportedFile {
                HStack {
                    Label(importedFileName, systemImage: "doc.fill")
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    Button {
                        clearImportedCleartext()
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.secondary)
                            .frame(minWidth: 44, minHeight: 44)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(String(localized: "verify.clearImportedFile", defaultValue: "Clear imported file"))
                }
            }
        } header: {
            Text(String(localized: "verify.input", defaultValue: "Signed Message"))
        } footer: {
            if !configuration.allowsCleartextFileImport,
               let cleartextFileRestrictionMessage = configuration.cleartextFileRestrictionMessage {
                Text(cleartextFileRestrictionMessage)
            }
        }
        .id(textInputSectionEpoch)
    }

    @ViewBuilder
    private var detachedContent: some View {
        Section {
            Button {
                guard configuration.allowsDetachedOriginalImport else { return }
                filePickerTarget = .original
                showFileImporter = true
            } label: {
                Label(
                    String(localized: "verify.selectOriginal", defaultValue: "Select Original File"),
                    systemImage: "doc"
                )
            }
            .disabled(!configuration.allowsDetachedOriginalImport)
            if let originalFileName {
                LabeledContent(
                    String(localized: "verify.originalFile", defaultValue: "Original"),
                    value: originalFileName
                )
            }
        } header: {
            Text(String(localized: "verify.detached.original", defaultValue: "Original File"))
        } footer: {
            if let detachedFileRestrictionMessage = configuration.detachedFileRestrictionMessage {
                Text(detachedFileRestrictionMessage)
            }
        }

        Section {
            Button {
                guard configuration.allowsDetachedSignatureImport else { return }
                filePickerTarget = .signature
                showFileImporter = true
            } label: {
                Label(
                    String(localized: "verify.selectSignature", defaultValue: "Select .sig File"),
                    systemImage: "signature"
                )
            }
            .disabled(!configuration.allowsDetachedSignatureImport)
            if let signatureFileName {
                LabeledContent(
                    String(localized: "verify.signatureFile", defaultValue: "Signature"),
                    value: signatureFileName
                )
            }
        } header: {
            Text(String(localized: "verify.detached.signature", defaultValue: "Signature File"))
        } footer: {
            if let detachedFileRestrictionMessage = configuration.detachedFileRestrictionMessage {
                Text(detachedFileRestrictionMessage)
            }
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
        case .cleartext:
            return signedInput.isEmpty && importedCleartext.rawData == nil
        case .detached: return originalFileURL == nil || signatureFileURL == nil
        }
    }

    private var allowedImportContentTypes: [UTType] {
        switch filePickerTarget {
        case .cleartextSignedImport:
            return [
                UTType(filenameExtension: "asc") ?? .plainText,
                .plainText
            ]
        case .signature:
            return [UTType(filenameExtension: "sig") ?? .data, .data]
        case .original, .none:
            return [.data]
        }
    }

    private var cleartextBinding: Binding<String> {
        Binding(
            get: { signedInput },
            set: { newValue in
                guard newValue != signedInput else { return }
                signedInput = newValue
                _ = importedCleartext.invalidateIfEditedTextDiffers(newValue)
                invalidateCleartextVerificationState()
            }
        )
    }

    private var editorHeightRange: (min: CGFloat, ideal: CGFloat, max: CGFloat) {
        #if canImport(UIKit)
        return (110, 160, 240)
        #else
        return (150, 220, 320)
        #endif
    }

    private var showsDetachedCancelAction: Bool {
        verifyMode == .detached && operation.isRunning && operation.progress != nil
    }

    // MARK: - Actions

    private func verifyCleartext() {
        let service = signingService
        let inputData = importedCleartext.rawData ?? Data(signedInput.utf8)
        invalidateCleartextVerificationState()
        operation.run(mapError: mapVerificationError) {
            let result = try await service.verifyCleartext(inputData)
            if let content = result.text {
                cleartextOriginalText = String(data: content, encoding: .utf8)
            }
            cleartextVerification = result.verification
            textInputSectionEpoch &+= 1
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

    private func importCleartextFile(from url: URL) {
        do {
            let data = try SecurityScopedFileAccess.withAccess(
                to: url,
                failure: .corruptData(
                    reason: String(localized: "verify.importCleartextReadFailed",
                                   defaultValue: "Could not read signed message file")
                )
            ) {
                try Data(contentsOf: url)
            }

            guard let text = String(data: data, encoding: .utf8) else {
                throw CypherAirError.corruptData(
                    reason: String(localized: "verify.importCleartextReadFailed",
                                   defaultValue: "Could not read signed message file")
                )
            }

            importedCleartext.setImportedFile(
                data: data,
                fileName: url.lastPathComponent,
                text: text
            )
            signedInput = text
            invalidateCleartextVerificationState()
        } catch let error as CypherAirError {
            operation.present(error: error)
        } catch {
            operation.present(error: mapVerificationError(error))
        }
    }

    private func clearImportedCleartext() {
        importedCleartext.clear()
        signedInput = ""
        invalidateCleartextVerificationState()
    }

    private func invalidateCleartextVerificationState() {
        cleartextOriginalText = nil
        cleartextVerification = nil
        textInputSectionEpoch &+= 1
    }
}
