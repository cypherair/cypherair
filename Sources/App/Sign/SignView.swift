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
    struct Configuration {
        var allowsClipboardWrite = true
        var allowsTextResultExport = true
        var allowsFileInput = true
        var allowsFileResultExport = true
        var fileRestrictionMessage: String?
        var resultRestrictionMessage: String?
        var outputInterceptionPolicy: OutputInterceptionPolicy = .passthrough

        static let `default` = Configuration()
    }

    enum SignMode: String, CaseIterable {
        case text
        case file

        var label: String {
            switch self {
            case .text:
                String(localized: "sign.mode.text", defaultValue: "Text")
            case .file:
                String(localized: "sign.mode.file", defaultValue: "File")
            }
        }
    }

    @Environment(SigningService.self) private var signingService
    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(AppConfiguration.self) private var config
    @Environment(\.authLifecycleTraceStore) private var authLifecycleTraceStore
    @Environment(\.protectedSettingsHost) private var protectedSettingsHost

    let configuration: Configuration

    init(configuration: Configuration = .default) {
        self.configuration = configuration
    }

    var body: some View {
        SignScreenHostView(
            signingService: signingService,
            keyManagement: keyManagement,
            config: config,
            authLifecycleTraceStore: authLifecycleTraceStore,
            protectedSettingsHost: protectedSettingsHost,
            configuration: configuration
        )
    }
}

private struct SignScreenHostView: View {
    @State private var model: SignScreenModel

    init(
        signingService: SigningService,
        keyManagement: KeyManagementService,
        config: AppConfiguration,
        authLifecycleTraceStore: AuthLifecycleTraceStore?,
        protectedSettingsHost: ProtectedSettingsHost?,
        configuration: SignView.Configuration
    ) {
        _model = State(
            initialValue: SignScreenModel(
                signingService: signingService,
                keyManagement: keyManagement,
                config: config,
                authLifecycleTraceStore: authLifecycleTraceStore,
                protectedSettingsHost: protectedSettingsHost,
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
                Picker(String(localized: "sign.mode", defaultValue: "Mode"), selection: $model.signMode) {
                    ForEach(SignView.SignMode.allCases, id: \.self) { mode in
                        Text(mode.label).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .disabled(operation.isRunning)
            }

            if model.signMode == .text {
                textSigningContent
                    .disabled(operation.isRunning)
            } else {
                fileSigningContent
                    .disabled(operation.isRunning)
            }

            Section {
                if model.signingKeys.count > 1 {
                    Picker(
                        String(localized: "sign.signingKey", defaultValue: "Signing Key"),
                        selection: $model.signerFingerprint
                    ) {
                        ForEach(model.signingKeys) { key in
                            Text(key.userId ?? key.shortKeyId)
                                .tag(Optional(key.fingerprint))
                        }
                    }
                }
            }
            .disabled(operation.isRunning)

            Section {
                Button {
                    model.sign()
                } label: {
                    CypherOperationButtonLabel(
                        idleTitle: String(localized: "sign.button", defaultValue: "Sign"),
                        runningTitle: String(localized: "sign.signing", defaultValue: "Signing..."),
                        isRunning: operation.isRunning,
                        isCancelling: operation.isCancelling,
                        progressFraction: model.signMode == .file ? operation.progress?.fractionCompleted : nil
                    )
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.signButtonDisabled)
            }

            if model.showsFileCancelAction {
                CypherOperationCancelSection(
                    isCancelling: operation.isCancelling,
                    cancel: operation.cancel
                )
            }

            if model.signMode == .text, let signedMessage = model.signedMessage {
                Section {
                    CypherOutputTextBlock(
                        text: signedMessage,
                        font: .system(.caption, design: .monospaced)
                    )

                    Button {
                        model.copySignedMessageToClipboard()
                    } label: {
                        Label(
                            String(localized: "common.copy", defaultValue: "Copy"),
                            systemImage: "doc.on.doc"
                        )
                    }
                    .disabled(!model.configuration.allowsClipboardWrite)

                    Button {
                        model.exportSignedMessage()
                    } label: {
                        Label(
                            String(localized: "common.save", defaultValue: "Save"),
                            systemImage: "square.and.arrow.down"
                        )
                    }
                    .disabled(!model.configuration.allowsTextResultExport)
                } header: {
                    Text(String(localized: "sign.result", defaultValue: "Signed Message"))
                } footer: {
                    if let resultRestrictionMessage = model.configuration.resultRestrictionMessage {
                        Text(resultRestrictionMessage)
                    }
                }
            }

            if model.signMode == .file, model.detachedSignature != nil {
                Section {
                    Button {
                        model.exportDetachedSignature()
                    } label: {
                        Label(
                            String(localized: "sign.share.signature", defaultValue: "Save .sig File"),
                            systemImage: "square.and.arrow.down"
                        )
                    }
                    .disabled(!model.configuration.allowsFileResultExport)
                } header: {
                    Text(String(localized: "sign.detached.result", defaultValue: "Detached Signature"))
                }
            }
        }
        .scrollDismissesKeyboardInteractivelyIfAvailable()
        #if os(macOS)
        .formStyle(.grouped)
        #endif
        .cypherMacReadableContent(maxWidth: MacPresentationWidth.textHeavy)
        .navigationTitle(String(localized: "sign.title", defaultValue: "Sign"))
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
        .alert(
            String(localized: "clipboard.notice.title", defaultValue: "Copied to Clipboard"),
            isPresented: Binding(
                get: { operation.isShowingClipboardNotice },
                set: { if !$0 { model.dismissClipboardNotice() } }
            )
        ) {
            Button(String(localized: "clipboard.notice.dismiss", defaultValue: "OK")) {
                model.dismissClipboardNotice()
            }
            Button(String(localized: "clipboard.notice.dontShow", defaultValue: "Don't Show Again")) {
                model.dismissClipboardNotice(disableFutureNotices: true)
            }
        } message: {
            Text(String(localized: "clipboard.notice.message", defaultValue: "The signed message has been copied. Remember to clear your clipboard after pasting."))
        }
        .fileImporter(
            isPresented: $model.showFileImporter,
            allowedContentTypes: [.data],
            allowsMultipleSelection: false
        ) { result in
            if case .success(let urls) = result, let url = urls.first {
                model.handleImportedFile(url)
            }
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
        .onAppear {
            model.syncSignerFromDefaultOnAppear()
        }
    }

    @ViewBuilder
    private var textSigningContent: some View {
        @Bindable var model = model

        Section {
            CypherMultilineTextInput(
                text: $model.text,
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
        .id(model.textInputSectionEpoch)
    }

    @ViewBuilder
    private var fileSigningContent: some View {
        Section {
            Button {
                model.requestFileImport()
            } label: {
                Label(
                    String(localized: "sign.selectFile", defaultValue: "Select File"),
                    systemImage: "doc"
                )
            }
            .disabled(!model.configuration.allowsFileInput)

            if let selectedFileName = model.selectedFileName {
                LabeledContent(
                    String(localized: "sign.selectedFile", defaultValue: "Selected"),
                    value: selectedFileName
                )
            }
        } header: {
            Text(String(localized: "sign.file.header", defaultValue: "File to Sign"))
        } footer: {
            if let fileRestrictionMessage = model.configuration.fileRestrictionMessage {
                Text(fileRestrictionMessage)
            }
        }
    }

    private var editorHeightRange: (min: CGFloat, ideal: CGFloat, max: CGFloat) {
        #if canImport(UIKit)
        (110, 160, 240)
        #else
        (120, 170, 240)
        #endif
    }
}
