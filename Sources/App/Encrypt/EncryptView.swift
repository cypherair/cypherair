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
        var initialRecipientContactIds: [String] = []
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
        let initialRecipientContactIds: [String]
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
            initialRecipientContactIds = configuration.initialRecipientContactIds
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
    @Environment(AppSessionOrchestrator.self) private var appSessionOrchestrator
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
            appSessionOrchestrator: appSessionOrchestrator,
            authLifecycleTraceStore: authLifecycleTraceStore,
            protectedSettingsHost: protectedSettingsHost,
            configuration: configuration
        )
    }
}

private struct EncryptScreenHostView: View {
    let configuration: EncryptView.Configuration
    let protectedOrdinarySettings: ProtectedOrdinarySettingsCoordinator
    let appSessionOrchestrator: AppSessionOrchestrator

    @State private var model: EncryptScreenModel

    init(
        encryptionService: EncryptionService,
        keyManagement: KeyManagementService,
        contactService: ContactService,
        config: AppConfiguration,
        protectedOrdinarySettings: ProtectedOrdinarySettingsCoordinator,
        appSessionOrchestrator: AppSessionOrchestrator,
        authLifecycleTraceStore: AuthLifecycleTraceStore?,
        protectedSettingsHost: ProtectedSettingsHost?,
        configuration: EncryptView.Configuration
    ) {
        self.configuration = configuration
        self.protectedOrdinarySettings = protectedOrdinarySettings
        self.appSessionOrchestrator = appSessionOrchestrator
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
                if model.contactsAvailability.isAvailable {
                    if !model.recipientLists.isEmpty {
                        ForEach(model.recipientLists) { recipientList in
                            Toggle(isOn: Binding(
                                get: { model.selectedRecipientListIds.contains(recipientList.recipientListId) },
                                set: { isOn in
                                    model.toggleRecipientList(recipientList.recipientListId, isOn: isOn)
                                }
                            )) {
                                VStack(alignment: .leading, spacing: 4) {
                                    HStack {
                                        Label(recipientList.name, systemImage: "person.3")
                                        if !recipientList.canEncryptToAll {
                                            CypherStatusBadge(
                                                title: recipientList.memberCount == 0
                                                    ? String(localized: "recipientLists.emptyList", defaultValue: "Empty")
                                                    : String(localized: "recipientLists.cannotEncrypt", defaultValue: "Needs Keys"),
                                                color: .orange
                                            )
                                        }
                                    }
                                    Text(
                                        String.localizedStringWithFormat(
                                            String(localized: "recipientLists.memberCount", defaultValue: "%d members"),
                                            recipientList.memberCount
                                        )
                                    )
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                }
                            }
                            .disabled(!recipientList.canEncryptToAll)
                        }
                    }

                    if model.encryptableContacts.isEmpty {
                        Text(String(localized: "encrypt.recipients.noMatches", defaultValue: "No matching recipients"))
                            .foregroundStyle(.secondary)
                    }

                    ForEach(model.encryptableContacts) { contact in
                        Toggle(isOn: Binding(
                            get: { model.selectedRecipients.contains(contact.contactId) },
                            set: { isOn in
                                model.toggleRecipient(contact.contactId, isOn: isOn)
                            }
                        )) {
                            HStack {
                                compatibilityIndicator(for: contact)
                                VStack(alignment: .leading) {
                                    Text(contact.displayName)
                                    HStack(spacing: 6) {
                                        Text(contact.preferredKey.profile.displayName)
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                        if !contact.isPreferredKeyVerified {
                                            CypherStatusBadge(
                                                title: String(localized: "encrypt.contact.unverified", defaultValue: "Unverified"),
                                                color: .orange
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if model.selectedRecipientListsContainInvalidMembers {
                        Label(
                            String(localized: "encrypt.recipientLists.invalidSelection", defaultValue: "A selected list now needs preferred keys before it can be used."),
                            systemImage: "exclamationmark.triangle.fill"
                        )
                        .font(.footnote)
                        .foregroundStyle(.orange)
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
                } else {
                    Label(
                        model.contactsAvailability.unavailableDescription,
                        systemImage: "lock"
                    )
                    .font(.footnote)
                    .foregroundStyle(.secondary)
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
                    CypherOperationButtonLabel(
                        idleTitle: String(localized: "encrypt.button", defaultValue: "Encrypt"),
                        runningTitle: String(localized: "fileEncrypt.encrypting", defaultValue: "Encrypting..."),
                        isRunning: operation.isRunning,
                        isCancelling: operation.isCancelling,
                        progressFraction: model.encryptMode == .file ? operation.progress?.fractionCompleted : nil
                    )
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.encryptButtonDisabled)
            }

            if model.showsFileCancelAction {
                CypherOperationCancelSection(
                    isCancelling: operation.isCancelling,
                    cancel: operation.cancel
                )
            }

            if model.encryptMode == .text, let ciphertextString = model.ciphertextString {
                Section {
                    CypherOutputTextBlock(
                        text: ciphertextString,
                        font: .system(.caption, design: .monospaced)
                    )

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
        .cypherMacReadableContent(maxWidth: MacPresentationWidth.textHeavy)
        .navigationTitle(String(localized: "encrypt.title", defaultValue: "Encrypt"))
        .searchable(
            text: $model.recipientSearchText,
            placement: .automatic,
            prompt: String(localized: "encrypt.search.prompt", defaultValue: "Recipients, tags, fingerprints")
        )
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
        .onChange(of: model.contactsAvailability) { previousAvailability, currentAvailability in
            model.handleContactsAvailabilityChange(
                from: previousAvailability,
                to: currentAvailability
            )
        }
        .onChange(of: protectedOrdinarySettings.state) { _, _ in
            model.refreshProtectedOrdinarySettings()
        }
        .onAppear {
            model.handleAppear()
        }
        .onDisappear {
            model.handleDisappear()
        }
        .onChange(of: appSessionOrchestrator.contentClearGeneration) {
            model.handleContentClearGenerationChange()
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

    private func compatibilityIndicator(for contact: ContactRecipientSummary) -> some View {
        Group {
            if model.defaultKeyVersion == 6 && contact.preferredKey.keyVersion == 4 {
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
        (120, 170, 240)
        #endif
    }

    private var runtimeSyncKey: EncryptView.RuntimeSyncKey {
        EncryptView.RuntimeSyncKey(configuration: configuration)
    }
}
