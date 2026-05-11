import SwiftUI

extension View {
    func settingsScreenPresentations(model: SettingsScreenModel) -> some View {
        modifier(SettingsScreenPresentations(model: model))
    }
}

private struct SettingsScreenPresentations: ViewModifier {
    let model: SettingsScreenModel

    func body(content: Content) -> some View {
        @Bindable var model = model

        content
            .confirmationDialog(
                model.localModeTitle,
                isPresented: Binding(
                    get: { model.presentedAuthModeRequest != nil && !model.usesLocalModeSheet },
                    set: { if !$0 { model.dismissLocalModeRequest() } }
                ),
                titleVisibility: .visible
            ) {
                if let request = model.presentedAuthModeRequest {
                    Button(String(localized: "settings.mode.confirm", defaultValue: "Switch Mode"), role: .destructive) {
                        request.onConfirm()
                    }
                    Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .cancel) {
                        request.onCancel()
                    }
                }
            } message: {
                Text(model.localModeMessage)
            }
            .sheet(isPresented: Binding(
                get: { model.presentedAuthModeRequest != nil && model.usesLocalModeSheet },
                set: { if !$0 { model.dismissLocalModeRequest() } }
            )) {
                if let request = model.presentedAuthModeRequest {
                    NavigationStack {
                        SettingsAuthModeConfirmationSheetView(request: request)
                    }
                    #if os(macOS)
                    .frame(minWidth: 500, idealWidth: 540, minHeight: 360, idealHeight: 420)
                    #endif
                    #if canImport(UIKit)
                    .presentationDetents([.medium, .large])
                    #endif
                }
            }
            .alert(
                String(localized: "settings.mode.error.title", defaultValue: "Protection Change Failed"),
                isPresented: Binding(
                    get: { model.showSwitchError },
                    set: { if !$0 { model.dismissSwitchError() } }
                )
            ) {
                Button(String(localized: "error.ok", defaultValue: "OK")) {
                    model.dismissSwitchError()
                }
            } message: {
                if let switchError = model.switchError {
                    Text(switchError)
                }
            }
            .confirmationDialog(
                String(
                    localized: "protectedSettings.reset.title",
                    defaultValue: "Reset Preferences?"
                ),
                isPresented: Binding(
                    get: { model.showProtectedSettingsResetConfirmation },
                    set: { if !$0 { model.dismissProtectedSettingsResetConfirmation() } }
                ),
                titleVisibility: .visible
            ) {
                Button(
                    String(
                        localized: "protectedSettings.reset.confirm",
                        defaultValue: "Reset Preferences"
                    ),
                    role: .destructive
                ) {
                    model.confirmProtectedSettingsReset()
                }
                Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .cancel) { }
            } message: {
                Text(
                    String(
                        localized: "protectedSettings.reset.message",
                        defaultValue: "This will delete and rebuild the preferences domain. Only these preferences will be reset."
                    )
                )
            }
            .confirmationDialog(
                String(localized: "settings.resetAll.title", defaultValue: "Reset All Local Data?"),
                isPresented: Binding(
                    get: { model.showLocalDataResetWarning },
                    set: { if !$0 { model.dismissLocalDataResetWarning() } }
                ),
                titleVisibility: .visible
            ) {
                Button(
                    String(localized: "settings.resetAll.continue", defaultValue: "Continue"),
                    role: .destructive
                ) {
                    model.continueLocalDataReset()
                }
                Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .cancel) { }
            } message: {
                Text(
                    String(
                        localized: "settings.resetAll.warning",
                        defaultValue: "This permanently deletes CypherAir keys, contacts, preferences, app settings, and temporary files on this device."
                    )
                )
            }
            .sheet(isPresented: Binding(
                get: { model.showLocalDataResetPhraseSheet },
                set: { if !$0 { model.dismissLocalDataResetPhraseSheet() } }
            )) {
                NavigationStack {
                    SettingsLocalDataResetPhraseView(model: model)
                }
                #if os(macOS)
                .frame(minWidth: 500, idealWidth: 540, minHeight: 320, idealHeight: 360)
                #endif
            }
            .alert(
                model.localDataResetAlertTitle,
                isPresented: Binding(
                    get: { model.showLocalDataResetResultAlert },
                    set: { if !$0 { model.dismissLocalDataResetResultAlert() } }
                )
            ) {
                Button(String(localized: "error.ok", defaultValue: "OK")) {
                    model.dismissLocalDataResetResultAlert()
                }
            } message: {
                Text(model.localDataResetAlertMessage)
            }
            #if !os(iOS)
            .sheet(isPresented: $model.showOnboarding) {
                OnboardingView(presentationContext: .inApp)
            }
            .sheet(isPresented: $model.showTutorialOnboarding) {
                TutorialView(presentationContext: .inApp)
            }
            #endif
    }
}
