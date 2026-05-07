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

    let configuration: Configuration

    init(configuration: Configuration = .default) {
        self.configuration = configuration
    }

    var body: some View {
        VerifyScreenHostView(
            signingService: signingService,
            configuration: configuration
        )
    }
}

private struct VerifyScreenHostView: View {
    @State private var model: VerifyScreenModel

    init(
        signingService: SigningService,
        configuration: VerifyView.Configuration
    ) {
        _model = State(
            initialValue: VerifyScreenModel(
                signingService: signingService,
                configuration: configuration
            )
        )
    }

    var body: some View {
        @Bindable var model = model
        let operation = model.operation

        Form {
            Section {
                Picker(String(localized: "verify.mode", defaultValue: "Mode"), selection: $model.verifyMode) {
                    ForEach(VerifyView.VerifyMode.allCases, id: \.self) { mode in
                        Text(mode.label).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .disabled(operation.isRunning)
            }

            if model.verifyMode == .cleartext {
                cleartextContent
                    .disabled(operation.isRunning)
            } else {
                detachedContent
                    .disabled(operation.isRunning)
            }

            Section {
                Button {
                    model.verify()
                } label: {
                    if operation.isRunning {
                        HStack {
                            if model.verifyMode == .detached, let progress = operation.progress {
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
                        .cypherPrimaryActionLabelFrame()
                    } else {
                        Text(String(localized: "verify.button", defaultValue: "Verify"))
                            .cypherPrimaryActionLabelFrame()
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.verifyButtonDisabled)
            }

            if model.showsDetachedCancelAction {
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

            if model.verifyMode == .cleartext, let cleartextOriginalText = model.cleartextOriginalText {
                Section {
                    CypherOutputTextBlock(
                        text: cleartextOriginalText,
                        font: .body,
                        minHeight: 80,
                        maxHeight: 220
                    )
                } header: {
                    Text(String(localized: "verify.originalText", defaultValue: "Original Message"))
                }
            }

            if let activeDetailedVerification = model.activeDetailedVerification {
                DetailedSignatureSectionView(
                    verification: activeDetailedVerification,
                    resultTitle: "verify.result",
                    signerTitle: "verify.signer"
                )
            }
        }
        .scrollDismissesKeyboardInteractivelyIfAvailable()
        #if os(macOS)
        .formStyle(.grouped)
        #endif
        .cypherMacReadableContent(maxWidth: MacPresentationWidth.textHeavy)
        .navigationTitle(String(localized: "verify.title", defaultValue: "Verify"))
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
        .fileImporter(
            isPresented: $model.showFileImporter,
            allowedContentTypes: model.allowedImportContentTypes,
            allowsMultipleSelection: false
        ) { result in
            defer {
                model.finishFileImportRequest()
            }

            if case .success(let urls) = result, let url = urls.first {
                model.handleImportedFile(url)
            }
        }
        .onDisappear {
            model.handleDisappear()
        }
    }

    // MARK: - Subviews

    @ViewBuilder
    private var cleartextContent: some View {
        @Bindable var model = model

        Section {
            CypherMultilineTextInput(
                text: Binding(
                    get: { model.signedInput },
                    set: { model.setSignedInput($0) }
                ),
                mode: .machineText
            )
                .frame(
                    minHeight: editorHeightRange.min,
                    idealHeight: editorHeightRange.ideal,
                    maxHeight: editorHeightRange.max
            )

            Button {
                model.requestCleartextFileImport()
            } label: {
                Label(
                    String(localized: "verify.importCleartextFile", defaultValue: "Import Signed File"),
                    systemImage: "doc.badge.plus"
                )
            }
            .disabled(!model.configuration.allowsCleartextFileImport)

            if let importedFileName = model.importedCleartext.fileName,
               model.importedCleartext.hasImportedFile {
                HStack {
                    Label(importedFileName, systemImage: "doc.fill")
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    CypherClearImportedFileButton(
                        accessibilityLabel: String(localized: "verify.clearImportedFile", defaultValue: "Clear imported file")
                    ) {
                        model.clearImportedCleartext()
                    }
                }
            }
        } header: {
            Text(String(localized: "verify.input", defaultValue: "Signed Message"))
        } footer: {
            if !model.configuration.allowsCleartextFileImport,
               let cleartextFileRestrictionMessage = model.configuration.cleartextFileRestrictionMessage {
                Text(cleartextFileRestrictionMessage)
            }
        }
        .id(model.textInputSectionEpoch)
    }

    @ViewBuilder
    private var detachedContent: some View {
        Section {
            Button {
                model.requestOriginalFileImport()
            } label: {
                Label(
                    String(localized: "verify.selectOriginal", defaultValue: "Select Original File"),
                    systemImage: "doc"
                )
            }
            .disabled(!model.configuration.allowsDetachedOriginalImport)
            if let originalFileName = model.originalFileName {
                LabeledContent(
                    String(localized: "verify.originalFile", defaultValue: "Original"),
                    value: originalFileName
                )
            }
        } header: {
            Text(String(localized: "verify.detached.original", defaultValue: "Original File"))
        } footer: {
            if let detachedFileRestrictionMessage = model.configuration.detachedFileRestrictionMessage {
                Text(detachedFileRestrictionMessage)
            }
        }

        Section {
            Button {
                model.requestSignatureFileImport()
            } label: {
                Label(
                    String(localized: "verify.selectSignature", defaultValue: "Select .sig File"),
                    systemImage: "signature"
                )
            }
            .disabled(!model.configuration.allowsDetachedSignatureImport)
            if let signatureFileName = model.signatureFileName {
                LabeledContent(
                    String(localized: "verify.signatureFile", defaultValue: "Signature"),
                    value: signatureFileName
                )
            }
        } header: {
            Text(String(localized: "verify.detached.signature", defaultValue: "Signature File"))
        } footer: {
            if let detachedFileRestrictionMessage = model.configuration.detachedFileRestrictionMessage {
                Text(detachedFileRestrictionMessage)
            }
        }
    }

    private var editorHeightRange: (min: CGFloat, ideal: CGFloat, max: CGFloat) {
        #if canImport(UIKit)
        return (110, 160, 240)
        #else
        return (150, 220, 320)
        #endif
    }
}
