import Foundation

/// Shared request shaping for the settings auth-mode confirmation flow.
enum SettingsAuthModeRequestBuilder {
    @MainActor
    static func makeRequest(
        id: UUID = UUID(),
        for mode: AuthenticationMode,
        hasBackup: Bool,
        onConfirm: @escaping @MainActor () -> Void,
        onCancel: @escaping @MainActor () -> Void
    ) -> AuthModeChangeConfirmationRequest {
        AuthModeChangeConfirmationRequest(
            id: id,
            pendingMode: mode,
            title: warningTitle(for: mode),
            message: warningMessage(for: mode, hasBackup: hasBackup),
            requiresRiskAcknowledgement: mode == .highSecurity && !hasBackup,
            onConfirm: onConfirm,
            onCancel: onCancel
        )
    }

    @MainActor
    static func makeLaunchPreviewRequest(
        onConfirm: @escaping @MainActor () -> Void = {},
        onCancel: @escaping @MainActor () -> Void = {}
    ) -> AuthModeChangeConfirmationRequest {
        makeRequest(
            id: UUID(),
            for: .highSecurity,
            hasBackup: true,
            onConfirm: onConfirm,
            onCancel: onCancel
        )
    }

    private static func warningTitle(for mode: AuthenticationMode) -> String {
        if mode == .highSecurity {
            return String(localized: "settings.mode.highWarning.title", defaultValue: "Enable High Security Mode")
        }

        return String(localized: "settings.mode.standardWarning.title", defaultValue: "Switch to Standard Mode")
    }

    private static func warningMessage(
        for mode: AuthenticationMode,
        hasBackup: Bool
    ) -> String {
        if mode == .highSecurity {
            if !hasBackup {
                #if os(macOS)
                return String(localized: "settings.mode.highWarning.noBackup.mac", defaultValue: "WARNING: In High Security mode, if Touch ID becomes unavailable, you will be unable to access your private keys. You have NOT backed up any keys. If biometrics fail, your keys will be permanently inaccessible. Back up your keys first, or proceed at your own risk.")
                #else
                return String(localized: "settings.mode.highWarning.noBackup", defaultValue: "WARNING: In High Security mode, if Face ID / Touch ID becomes unavailable, you will be unable to access your private keys. You have NOT backed up any keys. If biometrics fail, your keys will be permanently inaccessible. Back up your keys first, or proceed at your own risk.")
                #endif
            }

            #if os(macOS)
            return String(localized: "settings.mode.highWarning.message.mac", defaultValue: "In High Security mode, if Touch ID becomes unavailable, you will be unable to access your private keys. Ensure you have a current backup. Biometric authentication is required to confirm this change.")
            #else
            return String(localized: "settings.mode.highWarning.message", defaultValue: "In High Security mode, if Face ID / Touch ID becomes unavailable, you will be unable to access your private keys. Ensure you have a current backup. Biometric authentication is required to confirm this change.")
            #endif
        }

        return String(localized: "settings.mode.standardWarning.message", defaultValue: "Switching to Standard Mode will allow device passcode as a fallback for authentication. Biometric authentication is required to confirm this change.")
    }
}
