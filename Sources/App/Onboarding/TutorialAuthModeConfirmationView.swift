import SwiftUI

@MainActor
struct TutorialAuthModeConfirmationView: View {
    @Environment(TutorialSessionStore.self) private var tutorialStore

    let request: AuthModeChangeConfirmationRequest
    @State private var riskAcknowledged = false

    var body: some View {
        Form {
            Section {
                Text(request.message)
                    .font(.callout)
            }

            if request.requiresRiskAcknowledgement {
                Section {
                    Toggle(isOn: $riskAcknowledged) {
                        Text(String(localized: "settings.mode.riskAck", defaultValue: "I understand that if biometrics become unavailable, I will lose access to my private keys"))
                            .font(.callout)
                    }
                }
            }

            Section {
                Button(String(localized: "settings.mode.confirm", defaultValue: "Switch Mode"), role: .destructive) {
                    tutorialStore.dismissModal()
                    request.onConfirm()
                }
                .disabled(request.requiresRiskAcknowledgement && !riskAcknowledged)
                .frame(maxWidth: .infinity)
            }
        }
        .navigationTitle(request.title)
        #if canImport(UIKit)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button(String(localized: "common.cancel", defaultValue: "Cancel")) {
                    tutorialStore.dismissModal()
                    request.onCancel()
                }
            }
        }
    }
}
