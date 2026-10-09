import SwiftUI

struct SettingsLocalDataResetSection: View {
    let model: SettingsScreenModel

    var body: some View {
        Section {
            Button(role: .destructive) {
                model.localDataReset.request()
            } label: {
                Label(
                    String(localized: "settings.resetAll.action", defaultValue: "Reset All Local Data"),
                    systemImage: "trash"
                )
            }
            .disabled(!model.isLocalDataResetControlEnabled)
            .accessibilityIdentifier("settings.resetAll")
        } header: {
            Text(String(localized: "settings.dangerZone", defaultValue: "Danger Zone"))
        } footer: {
            Text(model.localDataResetFooter)
        }
    }
}

struct SettingsLocalDataResetPhraseView: View {
    let flow: LocalDataResetFlow

    var body: some View {
        @Bindable var flow = flow
        Form {
            Section {
                Text(
                    String(
                        localized: "settings.resetAll.phraseInstructions",
                        defaultValue: "Type RESET to permanently delete all CypherAir X data on this device."
                    )
                )
                CypherSingleLineTextField(
                    String(localized: "settings.resetAll.phrasePlaceholder", defaultValue: "Confirmation phrase"),
                    text: $flow.confirmationPhrase,
                    profile: .confirmationPhrase,
                    submitLabel: .done,
                    onSubmit: flow.confirm
                )
                .accessibilityIdentifier("settings.resetAll.phrase")
            }
        }
        #if os(macOS)
        .formStyle(.grouped)
        #endif
        .cypherMacReadableContent()
        .navigationTitle(String(localized: "settings.resetAll.title", defaultValue: "Reset All Local Data?"))
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button(String(localized: "common.cancel", defaultValue: "Cancel")) {
                    flow.dismissPhraseSheet()
                }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button(
                    String(localized: "settings.resetAll.confirm", defaultValue: "Reset"),
                    role: .destructive
                ) {
                    flow.confirm()
                }
                .disabled(!flow.canConfirm || flow.isResetting)
            }
        }
    }
}
