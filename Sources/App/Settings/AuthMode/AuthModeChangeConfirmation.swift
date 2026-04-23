import SwiftUI

@MainActor
struct AuthModeChangeConfirmationRequest: Identifiable {
    let id: UUID
    let pendingMode: AuthenticationMode
    let title: String
    let message: String
    let requiresRiskAcknowledgement: Bool
    let onConfirm: @MainActor () -> Void
    let onCancel: @MainActor () -> Void

    init(
        id: UUID = UUID(),
        pendingMode: AuthenticationMode,
        title: String,
        message: String,
        requiresRiskAcknowledgement: Bool,
        onConfirm: @escaping @MainActor () -> Void,
        onCancel: @escaping @MainActor () -> Void
    ) {
        self.id = id
        self.pendingMode = pendingMode
        self.title = title
        self.message = message
        self.requiresRiskAcknowledgement = requiresRiskAcknowledgement
        self.onConfirm = onConfirm
        self.onCancel = onCancel
    }
}

struct SettingsAuthModeConfirmationSheetView: View {
    let request: AuthModeChangeConfirmationRequest

    @State private var riskAcknowledged = false
    @Environment(\.dismiss) private var dismiss

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
                    dismiss()
                    request.onConfirm()
                }
                .accessibilityIdentifier("settings.mode.confirm")
                .tutorialAnchor(.settingsModeConfirmButton)
                .disabled(request.requiresRiskAcknowledgement && !riskAcknowledged)
                .frame(maxWidth: .infinity)
            }
        }
        .screenReady("settings.authmode.ready")
        .navigationTitle(request.title)
        #if canImport(UIKit)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button(String(localized: "common.cancel", defaultValue: "Cancel")) {
                    dismiss()
                    request.onCancel()
                }
            }
        }
        .authenticationShieldHost()
    }
}
