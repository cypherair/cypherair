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
                    .accessibilityIdentifier(TutorialAutomationContract.authModeRiskAcknowledgementIdentifier)
                }
            }

            Section {
                Button(String(localized: "settings.mode.confirm", defaultValue: "Switch Mode"), role: .destructive) {
                    tutorialStore.dismissModal()
                    request.onConfirm()
                }
                .disabled(request.requiresRiskAcknowledgement && !riskAcknowledged)
                .frame(maxWidth: .infinity)
                .accessibilityIdentifier(TutorialAutomationContract.authModeConfirmIdentifier)
                .tutorialAnchor(.settingsModeConfirmButton)
            }
        }
        .navigationTitle(request.title)
        .screenReady(TutorialAutomationContract.authModeConfirmationReadyMarker)
        #if canImport(UIKit)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button(String(localized: "common.cancel", defaultValue: "Cancel")) {
                    tutorialStore.dismissModal()
                    request.onCancel()
                }
                .accessibilityIdentifier(TutorialAutomationContract.authModeCancelIdentifier)
            }
        }
    }
}

struct TutorialLeaveConfirmationView: View {
    let request: TutorialLeaveConfirmationRequest

    var body: some View {
        Form {
            Section {
                Text(String(
                    localized: "guidedTutorial.leave.body",
                    defaultValue: "Leave the guided tutorial now? Your progress will stay available until this app run ends, but the tutorial will close."
                ))
                .font(.callout)
            }

            Section {
                Button(String(localized: "guidedTutorial.leave.continue", defaultValue: "Continue Tutorial")) {
                    request.onContinue()
                }
                .frame(maxWidth: .infinity)
                .accessibilityIdentifier(TutorialAutomationContract.leaveContinueIdentifier)

                Button(String(localized: "guidedTutorial.leave.confirm", defaultValue: "Leave Tutorial"), role: .destructive) {
                    request.onLeave()
                }
                .frame(maxWidth: .infinity)
                .accessibilityIdentifier(TutorialAutomationContract.leaveConfirmIdentifier)
            }
        }
        .navigationTitle(String(localized: "guidedTutorial.leave.title", defaultValue: "Leave Tutorial"))
        .screenReady(TutorialAutomationContract.leaveConfirmationReadyMarker)
        #if canImport(UIKit)
        .navigationBarTitleDisplayMode(.inline)
        #endif
    }
}
