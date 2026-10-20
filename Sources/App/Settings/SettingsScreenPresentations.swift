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
            .sheet(isPresented: $model.showChangePassphrase) {
                NavigationStack {
                    ChangePassphraseView()
                }
                #if os(macOS)
                .frame(minWidth: 500, idealWidth: 540, minHeight: 420, idealHeight: 480)
                #endif
            }
            .localDataResetPresentations(flow: model.localDataReset)
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
