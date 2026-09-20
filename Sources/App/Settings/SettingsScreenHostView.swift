import SwiftUI

struct SettingsScreenHostView: View {
    let appSessionOrchestrator: AppSessionOrchestrator
    @State private var model: SettingsScreenModel

    init(
        appSettings: AppSettingsCoordinator,
        appSessionOrchestrator: AppSessionOrchestrator,
        iosPresentationController: IOSPresentationController?,
        macPresentationController: MacPresentationController?,
        localDataResetService: LocalDataResetService?,
        localDataResetRestartCoordinator: LocalDataResetRestartCoordinator?,
        configuration: SettingsView.Configuration
    ) {
        self.appSessionOrchestrator = appSessionOrchestrator
        _model = State(
            initialValue: SettingsScreenModel(
                appSettings: appSettings,
                iosPresentationController: iosPresentationController,
                macPresentationController: macPresentationController,
                configuration: configuration,
                localDataResetService: localDataResetService,
                localDataResetRestartCoordinator: localDataResetRestartCoordinator
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
            .onChange(of: appSessionOrchestrator.contentClearGeneration) {
                model.clearTransientInput()
            }
    }
}
