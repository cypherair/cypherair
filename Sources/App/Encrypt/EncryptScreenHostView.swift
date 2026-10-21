import SwiftUI

struct EncryptScreenHostView: View {
    let configuration: EncryptView.Configuration
    let appSettings: AppSettingsCoordinator
    let appSessionOrchestrator: AppSessionOrchestrator

    @State private var model: EncryptScreenModel

    init(
        encryptionService: EncryptionService,
        keyManagement: KeyManagementService,
        contactService: ContactService,
        appSettings: AppSettingsCoordinator,
        appSessionOrchestrator: AppSessionOrchestrator,
        configuration: EncryptView.Configuration
    ) {
        self.configuration = configuration
        self.appSettings = appSettings
        self.appSessionOrchestrator = appSessionOrchestrator
        _model = State(
            initialValue: EncryptScreenModel(
                encryptionService: encryptionService,
                keyManagement: keyManagement,
                contactService: contactService,
                appSettings: appSettings,
                configuration: configuration
            )
        )
    }

    var body: some View {
        @Bindable var model = model
        EncryptScreenFormView(model: model)
        .scrollDismissesKeyboardInteractivelyIfAvailable()
        #if os(macOS)
        .formStyle(.grouped)
        #endif
        .navigationTitle(String(localized: "encrypt.title", defaultValue: "Encrypt"))
        .cypherSearchable(
            text: $model.recipientSearchText,
            prompt: String(localized: "encrypt.search.prompt", defaultValue: "Search recipients")
        )
        .encryptScreenPresentations(model: model)
        .onChange(of: runtimeSyncKey) { _, _ in
            model.updateConfiguration(configuration)
        }
        .onChange(of: appSettings.snapshot) { _, _ in
            model.refreshSettings()
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
