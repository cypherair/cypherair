import SwiftUI

struct EncryptScreenHostView: View {
    let configuration: EncryptView.Configuration
    let protectedOrdinarySettings: ProtectedOrdinarySettingsCoordinator
    let appSessionOrchestrator: AppSessionOrchestrator

    @State private var model: EncryptScreenModel
    @State private var isRecipientTagPickerPresented = false

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

        EncryptScreenFormView(
            model: model,
            isRecipientTagPickerPresented: $isRecipientTagPickerPresented
        )
        .scrollDismissesKeyboardInteractivelyIfAvailable()
        #if os(macOS)
        .formStyle(.grouped)
        #endif
        .cypherMacReadableContent(maxWidth: MacPresentationWidth.textHeavy)
        .navigationTitle(String(localized: "encrypt.title", defaultValue: "Encrypt"))
        .cypherSearchable(
            text: $model.recipientSearchText,
            placement: .automatic,
            prompt: String(localized: "encrypt.search.prompt", defaultValue: "Recipients, tags, fingerprints")
        )
        .encryptScreenPresentations(
            model: model,
            isRecipientTagPickerPresented: $isRecipientTagPickerPresented
        )
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

    private var runtimeSyncKey: EncryptView.RuntimeSyncKey {
        EncryptView.RuntimeSyncKey(configuration: configuration)
    }
}
