import SwiftUI

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
                .cypherPrimaryActionLabelFrame()
                .accessibilityIdentifier(TutorialAutomationContract.leaveContinueIdentifier)

                Button(String(localized: "guidedTutorial.leave.confirm", defaultValue: "Leave Tutorial"), role: .destructive) {
                    request.onLeave()
                }
                .cypherPrimaryActionLabelFrame()
                .accessibilityIdentifier(TutorialAutomationContract.leaveConfirmIdentifier)
            }
        }
        #if os(macOS)
        .formStyle(.grouped)
        #endif
        .cypherMacReadableContent()
        .navigationTitle(String(localized: "guidedTutorial.leave.title", defaultValue: "Leave Tutorial"))
        .screenReady(TutorialAutomationContract.leaveConfirmationReadyMarker)
        #if canImport(UIKit)
        .navigationBarTitleDisplayMode(.inline)
        #endif
    }
}
