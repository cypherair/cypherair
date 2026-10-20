import Foundation
import LocalAuthentication

/// The presence checks the vault takes: the system sheet in production, nothing
/// in the sandbox.
public protocol Authenticator: Sendable {
    /// Presence for unlock, bootstrap and passphrase change: biometrics with
    /// the device passcode or Mac password as the system's own fallback.
    func authenticate(context: LAContext, reason: String) async throws(VaultError)
    /// Biometrics alone, the constraint every device-bound key carries. The
    /// caller runs it inside the operation-prompt window and then disallows
    /// interaction on the context, so the enclave never prompts on its own.
    func authenticateBiometrics(context: LAContext, reason: String) async throws(VaultError)
}

/// The system sheet.
public struct SystemAuthenticator: Authenticator {
    public init() {}

    public func authenticate(context: LAContext, reason: String) async throws(VaultError) {
        try await Self.evaluate(.deviceOwnerAuthentication, context: context, reason: reason)
    }

    public func authenticateBiometrics(context: LAContext, reason: String) async throws(VaultError) {
        try await Self.evaluate(.deviceOwnerAuthenticationWithBiometrics, context: context, reason: reason)
    }

    private static func evaluate(_ policy: LAPolicy, context: LAContext, reason: String) async throws(VaultError) {
        do {
            let ok = try await context.evaluatePolicy(policy, localizedReason: reason)
            guard ok else { throw VaultError.authenticationFailed }
        } catch let error as VaultError {
            throw error
        } catch let error as LAError {
            throw VaultError.fromLocalAuthentication(error.code)
        } catch {
            throw VaultError.authenticationFailed
        }
    }
}
