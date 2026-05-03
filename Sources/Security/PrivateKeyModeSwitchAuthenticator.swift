import Foundation
import LocalAuthentication

private enum PrivateKeyModeSwitchAuthStrings {
    static let reason = String(
        localized: "auth.switchMode.reason",
        defaultValue: "Authenticate to change security mode"
    )
}

final class PrivateKeyModeSwitchAuthenticator {
    private let traceStore: AuthLifecycleTraceStore?

    init(traceStore: AuthLifecycleTraceStore? = nil) {
        self.traceStore = traceStore
    }

    func authenticateCurrentMode(
        _ currentMode: AuthenticationMode,
        targetMode: AuthenticationMode,
        authenticator: any AuthenticationEvaluable
    ) async throws {
        traceStore?.record(
            category: .prompt,
            name: "privateKeyProtection.switch.auth.start",
            metadata: [
                "mode": currentMode.rawValue,
                "targetMode": targetMode.rawValue,
                "source": "privateKeyProtection.switch"
            ]
        )

        let authenticated: Bool
        do {
            if let tracedAuthenticator = authenticator as? AuthenticationManager {
                authenticated = try await tracedAuthenticator.evaluate(
                    mode: currentMode,
                    reason: PrivateKeyModeSwitchAuthStrings.reason,
                    source: "privateKeyProtection.switch"
                )
            } else {
                authenticated = try await authenticator.evaluate(
                    mode: currentMode,
                    reason: PrivateKeyModeSwitchAuthStrings.reason
                )
            }
            traceStore?.record(
                category: .prompt,
                name: "privateKeyProtection.switch.auth.finish",
                metadata: [
                    "result": authenticated ? "success" : "failed",
                    "mode": currentMode.rawValue,
                    "source": "privateKeyProtection.switch"
                ]
            )
        } catch {
            traceStore?.record(
                category: .prompt,
                name: "privateKeyProtection.switch.auth.finish",
                metadata: traceErrorMetadata(
                    error,
                    extra: [
                        "result": "error",
                        "mode": currentMode.rawValue,
                        "source": "privateKeyProtection.switch"
                    ]
                )
            )
            traceStore?.record(
                category: .operation,
                name: "privateKeyProtection.switch.finish",
                metadata: traceErrorMetadata(
                    error,
                    extra: ["result": "authError", "targetMode": targetMode.rawValue]
                )
            )
            throw error
        }

        guard authenticated else {
            traceStore?.record(
                category: .operation,
                name: "privateKeyProtection.switch.finish",
                metadata: ["result": "authFailed", "targetMode": targetMode.rawValue]
            )
            throw AuthenticationError.failed
        }
    }

    private func traceErrorMetadata(
        _ error: Error,
        extra: [String: String] = [:]
    ) -> [String: String] {
        var metadata = extra
        metadata["errorType"] = String(describing: type(of: error))
        if let laError = error as? LAError {
            metadata["laCode"] = String(laError.errorCode)
            metadata["laCodeName"] = String(describing: laError.code)
        }
        return metadata
    }
}
