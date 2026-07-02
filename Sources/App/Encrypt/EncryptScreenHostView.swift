import SwiftUI

struct EncryptScreenHostView: View {
    let configuration: EncryptView.Configuration
    let protectedOrdinarySettings: ProtectedOrdinarySettingsCoordinator
    let appSessionOrchestrator: AppSessionOrchestrator

    @Environment(\.horizontalSizeClass) private var horizontalSizeClass
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
        let usesToolbarModePicker = CypherModePickerPlacement.usesToolbar(
            horizontalSizeClass: horizontalSizeClass
        )

        EncryptScreenFormView(model: model, showsModePicker: !usesToolbarModePicker)
        .scrollDismissesKeyboardInteractivelyIfAvailable()
        #if os(macOS)
        .formStyle(.grouped)
        #endif
        .navigationTitle(String(localized: "encrypt.title", defaultValue: "Encrypt"))
        .toolbar {
            if usesToolbarModePicker {
                ToolbarItem(placement: .principal) {
                    CypherModePicker(
                        title: String(localized: "encrypt.mode", defaultValue: "Mode"),
                        selection: $model.encryptMode,
                        selectedValueLabel: model.encryptMode.label,
                        isDisabled: model.operation.isRunning,
                        accessibilityIdentifier: "encrypt.mode.picker"
                    ) {
                        ForEach(EncryptView.EncryptMode.allCases, id: \.self) { mode in
                            Text(mode.label).tag(mode)
                        }
                    }
                }
            }
        }
        .cypherSearchable(
            text: $model.recipientSearchText,
            placement: .automatic,
            prompt: String(localized: "encrypt.search.prompt", defaultValue: "Recipients, tags, fingerprints")
        )
        .encryptScreenPresentations(model: model)
        .onChange(of: runtimeSyncKey) { _, _ in
            model.updateConfiguration(configuration)
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

    private var runtimeSyncKey: EncryptView.RuntimeSyncKey {
        EncryptView.RuntimeSyncKey(configuration: configuration)
    }
}
