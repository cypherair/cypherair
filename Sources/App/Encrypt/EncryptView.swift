import SwiftUI

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
