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
        enum TogglePolicy: Equatable {
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

            func optionalInitialValue(appDefault: Bool?) -> Bool? {
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

        var prefilledPlaintext: String?
        var initialRecipientFingerprints: [String] = []
        var initialSignerFingerprint: String?
        var signingPolicy: TogglePolicy = .initial(true)
        var encryptToSelfPolicy: TogglePolicy = .appDefault
        var allowsClipboardWrite = true
        var allowsResultExport = true
        var allowsFileInput = true
        var allowsFileResultExport = true
        var fileRestrictionMessage: String?
        var outputInterceptionPolicy: OutputInterceptionPolicy = .passthrough
        var onEncrypted: (@MainActor (Data) -> Void)?

        static let `default` = Configuration()
    }

    struct RuntimeSyncKey: Equatable {
        let prefilledPlaintext: String?
        let initialRecipientFingerprints: [String]
        let initialSignerFingerprint: String?
        let signingPolicy: Configuration.TogglePolicy
        let encryptToSelfPolicy: Configuration.TogglePolicy
        let allowsClipboardWrite: Bool
        let allowsResultExport: Bool
        let allowsFileInput: Bool
        let allowsFileResultExport: Bool
        let fileRestrictionMessage: String?
        let hasClipboardCopyInterceptor: Bool
        let hasDataExportInterceptor: Bool
        let hasFileExportInterceptor: Bool
        let hasOnEncrypted: Bool

        init(configuration: Configuration) {
            // When adding configuration fields, evaluate whether they should
            // participate in runtime host-to-model sync.
            prefilledPlaintext = configuration.prefilledPlaintext
            initialRecipientFingerprints = configuration.initialRecipientFingerprints
            initialSignerFingerprint = configuration.initialSignerFingerprint
            signingPolicy = configuration.signingPolicy
            encryptToSelfPolicy = configuration.encryptToSelfPolicy
            allowsClipboardWrite = configuration.allowsClipboardWrite
            allowsResultExport = configuration.allowsResultExport
            allowsFileInput = configuration.allowsFileInput
            allowsFileResultExport = configuration.allowsFileResultExport
            fileRestrictionMessage = configuration.fileRestrictionMessage
            hasClipboardCopyInterceptor =
                configuration.outputInterceptionPolicy.interceptClipboardCopy != nil
            hasDataExportInterceptor =
                configuration.outputInterceptionPolicy.interceptDataExport != nil
            hasFileExportInterceptor =
                configuration.outputInterceptionPolicy.interceptFileExport != nil
            hasOnEncrypted = configuration.onEncrypted != nil
        }
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
    @Environment(ProtectedOrdinarySettingsCoordinator.self) private var protectedOrdinarySettings
    @Environment(\.authLifecycleTraceStore) private var authLifecycleTraceStore
    @Environment(\.protectedSettingsHost) private var protectedSettingsHost

    let configuration: Configuration

    init(configuration: Configuration = .default) {
        self.configuration = configuration
    }

    var body: some View {
        EncryptScreenHostView(
            encryptionService: encryptionService,
            keyManagement: keyManagement,
            contactService: contactService,
            config: config,
            protectedOrdinarySettings: protectedOrdinarySettings,
            authLifecycleTraceStore: authLifecycleTraceStore,
            protectedSettingsHost: protectedSettingsHost,
            configuration: configuration
        )
    }
}

private struct EncryptScreenHostView: View {
    let configuration: EncryptView.Configuration
    let protectedOrdinarySettings: ProtectedOrdinarySettingsCoordinator

    @State private var model: EncryptScreenModel

    init(
        encryptionService: EncryptionService,
        keyManagement: KeyManagementService,
        contactService: ContactService,
        config: AppConfiguration,
        protectedOrdinarySettings: ProtectedOrdinarySettingsCoordinator,
        authLifecycleTraceStore: AuthLifecycleTraceStore?,
        protectedSettingsHost: ProtectedSettingsHost?,
        configuration: EncryptView.Configuration
    ) {
        self.configuration = configuration
        self.protectedOrdinarySettings = protectedOrdinarySettings
        _model = State(
            initialValue: EncryptScreenModel(
                encryptionService: encryptionService,
                keyManagement: keyManagement,
                contactService: contactService,
                config: config,
                protectedOrdinarySettings: protectedOrdinarySettings,
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
                Picker(String(localized: "encrypt.mode", defaultValue: "Mode"), selection: $model.encryptMode) {
                    ForEach(EncryptView.EncryptMode.allCases, id: \.self) { mode in
                        Text(mode.label).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .disabled(operation.isRunning)
            }

            if model.encryptMode == .text {
                textInputContent
                    .disabled(operation.isRunning)
            } else {
                fileInputContent
                    .disabled(operation.isRunning)
            }

            Section {
                ForEach(model.encryptableContacts) { contact in
                    Toggle(isOn: Binding(
                        get: { model.selectedRecipients.contains(contact.fingerprint) },
                        set: { isOn in
                            model.toggleRecipient(contact.fingerprint, isOn: isOn)
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

                if !model.selectedUnverifiedContacts.isEmpty {
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
            .disabled(operation.isRunning)

            Section {
                Toggle(
                    String(localized: "encrypt.encryptToSelf", defaultValue: "Encrypt to Self"),
                    isOn: Binding(
                        get: { model.encryptToSelfToggleValue },
                        set: { model.encryptToSelf = $0 }
                    )
                )
                .disabled(!model.isEncryptToSelfControlEnabled)

                if model.encryptToSelfToggleValue && model.ownKeys.count > 1 {
                    Picker(
                        String(localized: "encrypt.encryptToSelfKey", defaultValue: "Encrypt to Self With"),
                        selection: $model.encryptToSelfFingerprint
                    ) {
                        ForEach(model.ownKeys) { key in
                            Text(key.userId ?? key.shortKeyId)
                                .tag(Optional(key.fingerprint))
                        }
                    }
                }

                Toggle(
                    String(localized: "encrypt.sign", defaultValue: "Sign Message"),
                    isOn: $model.signMessage
                )
                .disabled(model.configuration.signingPolicy.isLocked)

                if model.signMessage && model.ownKeys.count > 1 {
                    Picker(
                        String(localized: "encrypt.signingKey", defaultValue: "Signing Key"),
                        selection: $model.signerFingerprint
                    ) {
                        ForEach(model.ownKeys) { key in
                            Text(key.userId ?? key.shortKeyId)
                                .tag(Optional(key.fingerprint))
                        }
                    }
                }
            }
            .disabled(operation.isRunning)

            Section {
                Button {
                    model.requestEncrypt()
                } label: {
                    if operation.isRunning {
                        HStack {
                            if model.encryptMode == .file, let progress = operation.progress {
                                ProgressView(value: progress.fractionCompleted)
                                    .progressViewStyle(.linear)
                                Text(
                                    operation.isCancelling
                                        ? String(localized: "common.cancelling", defaultValue: "Cancelling...")
                                        : String(localized: "fileEncrypt.encrypting", defaultValue: "Encrypting...")
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
                        Text(String(localized: "encrypt.button", defaultValue: "Encrypt"))
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.encryptButtonDisabled)
            }

            if model.showsFileCancelAction {
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

            if model.encryptMode == .text, let ciphertextString = model.ciphertextString {
                Section {
                    Text(ciphertextString)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)

                    Button {
                        model.copyCiphertextToClipboard()
                    } label: {
                        Label(
                            String(localized: "common.copy", defaultValue: "Copy"),
                            systemImage: "doc.on.doc"
                        )
                    }
                    .disabled(!model.configuration.allowsClipboardWrite)

                    Button {
                        model.exportCiphertext()
                    } label: {
                        Label(
                            String(localized: "common.save", defaultValue: "Save"),
                            systemImage: "square.and.arrow.down"
                        )
                    }
                    .disabled(!model.configuration.allowsResultExport)
                } header: {
                    Text(String(localized: "encrypt.result", defaultValue: "Encrypted Message"))
                }
            }

            if model.encryptMode == .file, model.encryptedFileURL != nil {
                Section {
                    Button {
                        model.exportEncryptedFile()
                    } label: {
                        Label(
                            String(localized: "fileEncrypt.share", defaultValue: "Save Encrypted File"),
                            systemImage: "square.and.arrow.down"
                        )
                    }
                    .disabled(!model.configuration.allowsFileResultExport)
                }
            }
        }
        .scrollDismissesKeyboardInteractivelyIfAvailable()
        #if os(macOS)
        .formStyle(.grouped)
        #endif
        .navigationTitle(String(localized: "encrypt.title", defaultValue: "Encrypt"))
        .fileImporter(
            isPresented: $model.showFileImporter,
            allowedContentTypes: [.data],
            allowsMultipleSelection: false
        ) { result in
            if case .success(let urls) = result, let url = urls.first {
                model.handleImportedFile(url)
            }
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
            Text(String(localized: "clipboard.notice.message", defaultValue: "The encrypted message has been copied. Remember to clear your clipboard after pasting."))
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
        .confirmationDialog(
            String(localized: "encrypt.unverified.confirm.title", defaultValue: "Use Unverified Recipients?"),
            isPresented: Binding(
                get: { model.showUnverifiedRecipientsWarning },
                set: { if !$0 { model.dismissUnverifiedRecipientsWarning() } }
            ),
            titleVisibility: .visible
        ) {
            Button(String(localized: "encrypt.unverified.confirm.action", defaultValue: "Encrypt Anyway")) {
                model.confirmEncryptWithUnverifiedRecipients()
            }
            Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .cancel) { }
        } message: {
            Text(model.unverifiedRecipientsWarningMessage)
        }
        .onChange(of: runtimeSyncKey) { _, _ in
            model.updateConfiguration(configuration)
        }
        .onChange(of: protectedOrdinarySettings.state) { _, _ in
            model.refreshProtectedOrdinarySettings()
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
                text: $model.plaintext,
                mode: .prose
            )
                .frame(
                    minHeight: editorHeightRange.min,
                    idealHeight: editorHeightRange.ideal,
                    maxHeight: editorHeightRange.max
                )
        } header: {
            Text(String(localized: "encrypt.plaintext", defaultValue: "Message"))
        }
        .id(model.textInputSectionEpoch)
    }

    @ViewBuilder
    private var fileInputContent: some View {
        @Bindable var model = model

        Section {
            Button {
                model.requestFileImport()
            } label: {
                Label(
                    String(localized: "fileEncrypt.selectFile", defaultValue: "Select File"),
                    systemImage: "doc.badge.plus"
                )
            }
            .disabled(!model.configuration.allowsFileInput)

            if let selectedFileName = model.selectedFileName {
                LabeledContent(
                    String(localized: "fileEncrypt.selectedFile", defaultValue: "Selected"),
                    value: selectedFileName
                )
            }
        } header: {
            Text(String(localized: "fileEncrypt.file", defaultValue: "File"))
        } footer: {
            if let fileRestrictionMessage = model.configuration.fileRestrictionMessage {
                Text(fileRestrictionMessage)
            }
        }
    }

    private func compatibilityIndicator(for contact: Contact) -> some View {
        Group {
            if contact.isExpired || contact.isRevoked {
                Image(systemName: "xmark.circle.fill")
                    .foregroundStyle(.red)
                    .accessibilityLabel(String(localized: "encrypt.compat.expired", defaultValue: "Key expired or revoked"))
            } else if model.defaultKeyVersion == 6 && contact.keyVersion == 4 {
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

    private var editorHeightRange: (min: CGFloat, ideal: CGFloat, max: CGFloat) {
        #if canImport(UIKit)
        (110, 160, 240)
        #else
        (150, 220, 320)
        #endif
    }

    private var runtimeSyncKey: EncryptView.RuntimeSyncKey {
        EncryptView.RuntimeSyncKey(configuration: configuration)
    }
}
