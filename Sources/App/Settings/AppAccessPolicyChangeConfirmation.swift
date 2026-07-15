import SwiftUI

/// Confirmation request for switching App Access Protection to "Biometrics
/// Only". That policy re-wraps the root secret with `[.biometryAny]` and no
/// passcode fallback, so if biometrics later become unavailable the
/// protected-data layer is irrecoverable — the same class of lockout the High
/// Security key switch warns about. The risk-acknowledgement is always
/// required (unlike the key switch, no key backup mitigates loss of the root
/// secret).
@MainActor
struct AppAccessPolicyChangeConfirmationRequest: Identifiable {
    let id: UUID
    let title: String
    let message: String
    let onConfirm: @MainActor () -> Void
    let onCancel: @MainActor () -> Void

    init(
        id: UUID = UUID(),
        title: String,
        message: String,
        onConfirm: @escaping @MainActor () -> Void,
        onCancel: @escaping @MainActor () -> Void
    ) {
        self.id = id
        self.title = title
        self.message = message
        self.onConfirm = onConfirm
        self.onCancel = onCancel
    }
}

enum SettingsAppAccessPolicyRequestBuilder {
    @MainActor
    static func makeBiometricsOnlyRequest(
        id: UUID = UUID(),
        onConfirm: @escaping @MainActor () -> Void,
        onCancel: @escaping @MainActor () -> Void
    ) -> AppAccessPolicyChangeConfirmationRequest {
        AppAccessPolicyChangeConfirmationRequest(
            id: id,
            title: String(
                localized: "settings.appAccessPolicy.biometricsOnlyWarning.title",
                defaultValue: "Enable Biometrics Only"
            ),
            message: {
                #if os(macOS)
                return String(
                    localized: "settings.appAccessPolicy.biometricsOnlyWarning.message.mac",
                    defaultValue: "WARNING: With Biometrics Only, the app unlocks with Touch ID and no passcode fallback. If Touch ID becomes unavailable, you will be locked out of all protected data, and switching back, opening the app, and resetting local data all require Touch ID. There is no recovery. Proceed at your own risk."
                )
                #else
                return String(
                    localized: "settings.appAccessPolicy.biometricsOnlyWarning.message",
                    defaultValue: "WARNING: With Biometrics Only, the app unlocks with Face ID / Touch ID and no passcode fallback. If biometrics become unavailable, you will be locked out of all protected data, and switching back, opening the app, and resetting local data all require biometrics. There is no recovery. Proceed at your own risk."
                )
                #endif
            }(),
            onConfirm: onConfirm,
            onCancel: onCancel
        )
    }
}

struct SettingsAppAccessPolicyConfirmationSheetView: View {
    let request: AppAccessPolicyChangeConfirmationRequest

    @State private var riskAcknowledged = false
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Form {
            Section {
                Text(request.message)
                    .font(.callout)
            }

            Section {
                Toggle(isOn: $riskAcknowledged) {
                    Text(String(
                        localized: "settings.appAccessPolicy.biometricsOnlyWarning.riskAck",
                        defaultValue: "I understand that if biometrics become unavailable, I will be locked out of my protected data with no recovery"
                    ))
                    .font(.callout)
                }
            }

            Section {
                Button(
                    String(
                        localized: "settings.appAccessPolicy.biometricsOnlyWarning.confirm",
                        defaultValue: "Switch Protection"
                    ),
                    role: .destructive
                ) {
                    dismiss()
                    request.onConfirm()
                }
                .accessibilityIdentifier("settings.appAccessPolicy.confirm")
                .disabled(!riskAcknowledged)
                .cypherPrimaryActionLabelFrame()
            }
        }
        #if os(macOS)
        .formStyle(.grouped)
        #endif
        .cypherMacReadableContent()
        .screenReady("settings.appAccessPolicy.ready")
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
    }
}
