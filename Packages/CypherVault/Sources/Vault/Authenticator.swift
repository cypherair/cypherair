import Foundation
import LocalAuthentication

/// Runs the one presence check of an unlock on a context, so the vault decides
/// when to prompt and tests can decide not to.
public protocol Authenticator: Sendable {
    func authenticate(context: LAContext, reason: String) async throws(VaultError)
}

/// The system sheet: biometrics with the device passcode or Mac password as the
/// system's own fallback.
public struct SystemAuthenticator: Authenticator {
    public init() {}

    public func authenticate(context: LAContext, reason: String) async throws(VaultError) {
        do {
            let ok = try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
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
