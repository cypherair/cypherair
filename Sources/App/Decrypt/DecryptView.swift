import SwiftUI
#if canImport(UIKit)
import UIKit
#endif
import UniformTypeIdentifiers

/// Unified two-phase decryption view for text and files.
struct DecryptView: View {
    struct Configuration {
        var prefilledCiphertext: String?
        var initialPhase1Result: DecryptionService.Phase1Result?
        var allowsTextFileImport = true
        var allowsFileInput = true
        var allowsFileResultExport = true
        var textFileRestrictionMessage: String?
        var fileRestrictionMessage: String?
        var outputInterceptionPolicy: OutputInterceptionPolicy = .passthrough
        var onParsed: (@MainActor (DecryptionService.Phase1Result) -> Void)?
        var onDecrypted: (@MainActor (Data, SignatureVerification) -> Void)?

        static let `default` = Configuration()
    }

    struct RuntimeSyncKey: Equatable {
        struct InitialPhase1Seed: Equatable {
            let recipientKeyIds: [String]
            let matchedKeyFingerprint: String?
            let ciphertext: Data

            init(_ result: DecryptionService.Phase1Result) {
                recipientKeyIds = result.recipientKeyIds
                matchedKeyFingerprint = result.matchedKey?.fingerprint
                ciphertext = result.ciphertext
            }
        }

        let prefilledCiphertext: String?
        let initialPhase1Result: InitialPhase1Seed?
        let allowsTextFileImport: Bool
        let allowsFileInput: Bool
        let allowsFileResultExport: Bool
        let textFileRestrictionMessage: String?
        let fileRestrictionMessage: String?
        let hasFileExportInterceptor: Bool
        let hasOnParsed: Bool
        let hasOnDecrypted: Bool

        init(configuration: Configuration) {
            // When adding configuration fields, evaluate whether they should
            // participate in runtime host-to-model sync.
            prefilledCiphertext = configuration.prefilledCiphertext
            initialPhase1Result = configuration.initialPhase1Result.map(InitialPhase1Seed.init)
            allowsTextFileImport = configuration.allowsTextFileImport
            allowsFileInput = configuration.allowsFileInput
            allowsFileResultExport = configuration.allowsFileResultExport
            textFileRestrictionMessage = configuration.textFileRestrictionMessage
            fileRestrictionMessage = configuration.fileRestrictionMessage
            hasFileExportInterceptor =
                configuration.outputInterceptionPolicy.interceptFileExport != nil
            hasOnParsed = configuration.onParsed != nil
            hasOnDecrypted = configuration.onDecrypted != nil
        }
    }

    enum DecryptMode: String, CaseIterable {
        case text
        case file

        var label: String {
            switch self {
            case .text:
                String(localized: "decrypt.mode.text", defaultValue: "Text")
            case .file:
                String(localized: "decrypt.mode.file", defaultValue: "File")
            }
        }
    }

    enum FileImportTarget {
        case textCiphertextImport
        case fileCiphertextImport
    }

    @Environment(DecryptionService.self) private var decryptionService
    @Environment(AppConfiguration.self) private var config

    let configuration: Configuration

    init(configuration: Configuration = .default) {
        self.configuration = configuration
    }

    var body: some View {
        DecryptScreenHostView(
            decryptionService: decryptionService,
            appConfiguration: config,
            configuration: configuration
        )
    }
}

private struct DecryptScreenHostView: View {
    let appConfiguration: AppConfiguration
    let configuration: DecryptView.Configuration

    @State private var model: DecryptScreenModel

    init(
        decryptionService: DecryptionService,
        appConfiguration: AppConfiguration,
        configuration: DecryptView.Configuration
    ) {
        self.appConfiguration = appConfiguration
        self.configuration = configuration
        _model = State(
            initialValue: DecryptScreenModel(
                decryptionService: decryptionService,
                configuration: configuration
            )
        )
    }

    var body: some View {
        @Bindable var model = model
        let operation = model.operation
        let exportController = model.exportController

        Form {
            Section {
                Picker(String(localized: "decrypt.mode", defaultValue: "Mode"), selection: $model.decryptMode) {
                    ForEach(DecryptView.DecryptMode.allCases, id: \.self) { mode in
                        Text(mode.label).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .disabled(operation.isRunning)
            }

            if model.decryptMode == .text {
                textInputContent
                    .disabled(operation.isRunning)
            } else {
                fileInputContent
                    .disabled(operation.isRunning)
            }

            Section {
                Button {
                    if model.decryptMode == .text {
                        model.parseRecipientsText()
                    } else {
                        model.parseRecipientsFile()
                    }
                } label: {
                    if operation.isRunning && !model.hasPhase1Result {
                        HStack {
                            ProgressView()
                            Text(String(localized: "decrypt.parse.checking", defaultValue: "Checking recipients..."))
                        }
                        .frame(maxWidth: .infinity)
                    } else {
                        Text(String(localized: "decrypt.parse.button", defaultValue: "Check Recipients"))
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.decryptButtonDisabled || model.hasPhase1Result)
            }

            if let matchedKey = model.activeMatchedKey {
                Section {
                    LabeledContent(
                        String(localized: "decrypt.matchedKey.name", defaultValue: "Key"),
                        value: matchedKey.userId ?? matchedKey.shortKeyId
                    )
                    LabeledContent(
                        String(localized: "decrypt.matchedKey.profile", defaultValue: "Profile"),
                        value: matchedKey.profile.displayName
                    )
                    FingerprintView(
                        fingerprint: matchedKey.fingerprint,
                        font: .system(.caption, design: .monospaced),
                        foregroundColor: .secondary
                    )
                } header: {
                    Text(String(localized: "decrypt.matchedKey", defaultValue: "Matched Key"))
                }

                Section {
                    Button {
                        if model.decryptMode == .text {
                            model.decryptText()
                        } else {
                            model.decryptFile()
                        }
                    } label: {
                        if operation.isRunning {
                            HStack {
                                if model.decryptMode == .file, let progress = operation.progress {
                                    ProgressView(value: progress.fractionCompleted)
                                        .progressViewStyle(.linear)
                                    Text(
                                        operation.isCancelling
                                            ? String(localized: "common.cancelling", defaultValue: "Cancelling...")
                                            : String(localized: "fileDecrypt.decrypting", defaultValue: "Decrypting...")
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
                            Text(String(localized: "decrypt.button", defaultValue: "Decrypt with \(matchedKey.userId ?? matchedKey.shortKeyId)"))
                                .frame(maxWidth: .infinity)
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(operation.isRunning)
                }

                if model.showsFileDecryptCancelAction {
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
            }

            if model.decryptMode == .text, let decryptedText = model.decryptedText {
                Section {
                    Text(decryptedText)
                        .textSelection(.enabled)
                } header: {
                    Text(String(localized: "decrypt.result", defaultValue: "Decrypted Message"))
                }
            }

            if model.decryptMode == .file, model.decryptedFileURL != nil {
                Section {
                    Button {
                        model.exportDecryptedFile()
                    } label: {
                        Label(
                            String(localized: "fileDecrypt.save", defaultValue: "Save Decrypted File"),
                            systemImage: "square.and.arrow.down"
                        )
                    }
                    .disabled(!model.configuration.allowsFileResultExport)
                }
            }

            if let detailedVerification = model.detailedSignatureVerification {
                DetailedSignatureSectionView(
                    verification: detailedVerification,
                    resultTitle: "decrypt.signature",
                    signerTitle: "decrypt.signer"
                )
            }
        }
        .scrollDismissesKeyboardInteractivelyIfAvailable()
        #if os(macOS)
        .formStyle(.grouped)
        #endif
        .navigationTitle(String(localized: "decrypt.title", defaultValue: "Decrypt"))
        .fileImporter(
            isPresented: $model.showFileImporter,
            allowedContentTypes: allowedImportContentTypes,
            allowsMultipleSelection: false
        ) { result in
            defer {
                model.finishFileImportRequest()
            }

            if case .success(let urls) = result,
               let url = urls.first {
                model.handleImportedFile(url)
            }
        }
        .confirmationDialog(
            String(localized: "decrypt.openAsText.title", defaultValue: "Open as Text?"),
            isPresented: Binding(
                get: { model.showTextModeSuggestion },
                set: { if !$0 { model.dismissTextModeSuggestion() } }
            ),
            titleVisibility: .visible
        ) {
            Button(String(localized: "decrypt.openAsText.action", defaultValue: "Open as Text")) {
                model.openPendingFileAsText()
            }
            Button(String(localized: "decrypt.openAsText.keepFile", defaultValue: "Keep as File")) {
                model.keepPendingFileAsFile()
            }
            Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .cancel) {}
        } message: {
            Text(String(localized: "decrypt.openAsText.message", defaultValue: "This file looks like an armored text message. Open it in Text mode instead?"))
        }
        .alert(
            String(localized: "error.title", defaultValue: "Error"),
            isPresented: Binding(
                get: { operation.isShowingError },
                set: { if !$0 { model.dismissError() } }
            ),
            presenting: operation.error
        ) { _ in
            Button(String(localized: "error.ok", defaultValue: "OK")) {}
        } message: { err in
            Text(err.localizedDescription)
        }
        .fileExporter(
            isPresented: Binding(
                get: { exportController.isPresented },
                set: { if !$0 { model.finishExport() } }
            ),
            item: exportController.payload,
            contentTypes: [.data],
            defaultFilename: exportController.defaultFilename
        ) { result in
            model.finishExport()
            if case .failure(let exportError) = result {
                model.handleExportError(exportError)
            }
        }
        .onDisappear {
            model.handleDisappear()
        }
        .onChange(of: appConfiguration.contentClearGeneration) {
            model.handleContentClearGenerationChange()
        }
        .onChange(of: runtimeSyncKey) { _, _ in
            model.updateConfiguration(configuration)
        }
        .onAppear {
            model.handleAppear()
        }
    }

    @ViewBuilder
    private var textInputContent: some View {
        @Bindable var model = model

        Section {
            CypherMultilineTextInput(
                text: ciphertextBinding,
                mode: .machineText
            )
                .frame(
                    minHeight: editorHeightRange.min,
                    idealHeight: editorHeightRange.ideal,
                    maxHeight: editorHeightRange.max
                )

            Button {
                model.requestTextCiphertextImport()
            } label: {
                Label(
                    String(localized: "decrypt.importTextFile", defaultValue: "Import .asc File"),
                    systemImage: "doc.badge.plus"
                )
            }
            .disabled(!model.configuration.allowsTextFileImport)

            if let importedFileName = model.importedCiphertext.fileName,
               model.importedCiphertext.hasImportedFile {
                HStack {
                    Label(importedFileName, systemImage: "doc.fill")
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    Button {
                        model.clearImportedCiphertext()
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.secondary)
                            .frame(minWidth: 44, minHeight: 44)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(String(localized: "decrypt.clearImportedFile", defaultValue: "Clear imported file"))
                }
            }
        } header: {
            Text(String(localized: "decrypt.input", defaultValue: "Encrypted Message"))
        } footer: {
            if !model.configuration.allowsTextFileImport,
               let textFileRestrictionMessage = model.configuration.textFileRestrictionMessage {
                Text(textFileRestrictionMessage)
            }
        }
        .id(model.textInputSectionEpoch)
    }

    @ViewBuilder
    private var fileInputContent: some View {
        @Bindable var model = model

        Section {
            Button {
                model.requestFileCiphertextImport()
            } label: {
                Label(
                    String(localized: "fileDecrypt.selectFile", defaultValue: "Select Encrypted File"),
                    systemImage: "doc.badge.arrow.up"
                )
            }
            .disabled(!model.configuration.allowsFileInput)

            if let selectedFileName = model.selectedFileName {
                LabeledContent(
                    String(localized: "fileDecrypt.selectedFile", defaultValue: "Selected"),
                    value: selectedFileName
                )
            }
        } header: {
            Text(String(localized: "fileDecrypt.file", defaultValue: "Encrypted File"))
        } footer: {
            if let fileRestrictionMessage = model.configuration.fileRestrictionMessage {
                Text(fileRestrictionMessage)
            } else {
                Text(String(localized: "fileDecrypt.types", defaultValue: "Supports .gpg, .pgp, and .asc files"))
            }
        }
    }

    private var editorHeightRange: (min: CGFloat, ideal: CGFloat, max: CGFloat) {
        #if canImport(UIKit)
        (110, 160, 240)
        #else
        (150, 220, 320)
        #endif
    }

    private var allowedImportContentTypes: [UTType] {
        switch model.fileImportTarget {
        case .textCiphertextImport?:
            [
                UTType(filenameExtension: "asc") ?? .plainText,
                .plainText,
            ]
        case .fileCiphertextImport?, .none:
            [
                UTType(filenameExtension: "gpg") ?? .data,
                UTType(filenameExtension: "pgp") ?? .data,
                UTType(filenameExtension: "asc") ?? .data,
                .data,
            ]
        }
    }

    private var ciphertextBinding: Binding<String> {
        Binding(
            get: { model.ciphertextInput },
            set: { model.setCiphertextInput($0) }
        )
    }

    private var runtimeSyncKey: DecryptView.RuntimeSyncKey {
        DecryptView.RuntimeSyncKey(configuration: configuration)
    }
}
