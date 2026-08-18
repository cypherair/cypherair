import SwiftUI

struct SettingsScreenHostView: View {
    let contentClear: ContentClearSignal

    @State private var model: SettingsScreenModel

    init(
        config: AppConfiguration,
        protectedOrdinarySettings: ProtectedOrdinarySettingsCoordinator,
        authManager: AuthenticationManager,
        keyManagement: KeyManagementService,
        contentClear: ContentClearSignal,
        iosPresentationController: IOSPresentationController?,
        macPresentationController: MacPresentationController?,
        appAccessPolicySwitchAction: SettingsScreenModel.AppAccessPolicySwitchAction?,
        localDataResetService: LocalDataResetService?,
        localDataResetRestartCoordinator: LocalDataResetRestartCoordinator?,
        configuration: SettingsView.Configuration
    ) {
        self.contentClear = contentClear
        _model = State(
            initialValue: SettingsScreenModel(
                config: config,
                protectedOrdinarySettings: protectedOrdinarySettings,
                authManager: authManager,
                keyManagement: keyManagement,
                iosPresentationController: iosPresentationController,
                macPresentationController: macPresentationController,
                configuration: configuration,
                localDataResetService: localDataResetService,
                localDataResetRestartCoordinator: localDataResetRestartCoordinator,
                appAccessPolicySwitchAction: appAccessPolicySwitchAction
            )
        )
    }

    var body: some View {
        SettingsFormView(model: model)
            #if os(macOS)
            .formStyle(.grouped)
            #endif
            .cypherMacReadableContent()
            .accessibilityIdentifier("settings.root")
            .screenReady("settings.ready")
            .navigationTitle(String(localized: "settings.title", defaultValue: "Settings"))
            .settingsScreenPresentations(model: model)
            .task {
                await model.prepareProtectedSettingsSection()
            }
            .onChange(of: contentClear.generation) {
                model.clearTransientInput()
            }
    }
}
