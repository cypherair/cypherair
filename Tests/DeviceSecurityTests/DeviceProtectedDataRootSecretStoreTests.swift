import LocalAuthentication
import XCTest
@testable import CypherAir

#if os(iOS)
final class DeviceProtectedDataRootSecretStoreTests: XCTestCase {
    private var rootSecretStore: KeychainProtectedDataRootSecretStore!
    private var trackedIdentifiers: [String] = []

    override func setUp() async throws {
        try await super.setUp()
        rootSecretStore = KeychainProtectedDataRootSecretStore(
            account: "DeviceProtectedDataRootSecretStoreTests"
        )
    }

    override func tearDown() async throws {
        try cleanupTrackedRootSecrets()
        rootSecretStore = nil
        try await super.tearDown()
    }

    func test_unauthenticatedInteractionDisallowedContext_cannotReadRootSecret() throws {
        let identifier = try makeTestRootSecretIdentifier(functionName: #function)
        try rootSecretStore.saveRootSecret(
            Data(repeating: 0x5A, count: 32),
            identifier: identifier,
            policy: .userPresence
        )

        let lockedContext = LAContext()
        lockedContext.interactionNotAllowed = true

        XCTAssertThrowsError(
            try rootSecretStore.loadRootSecret(
                identifier: identifier,
                authenticationContext: lockedContext
            )
        ) { error in
            guard let keychainError = error as? KeychainError else {
                return XCTFail("Expected KeychainError, got \(error)")
            }
            XCTAssertTrue(
                keychainError == .interactionNotAllowed || keychainError == .authenticationFailed,
                "Expected fail-closed keychain authentication error, got \(keychainError)"
            )
        }
    }

    func test_authenticatedUserPresenceContext_canReadRootSecretWithoutSecondInteraction() async throws {
        let identifier = try makeTestRootSecretIdentifier(functionName: #function)
        let secret = Data(repeating: 0xA5, count: 32)
        try rootSecretStore.saveRootSecret(secret, identifier: identifier, policy: .userPresence)

        let authenticatedContext = try await authenticateContext(
            policy: .deviceOwnerAuthentication,
            reason: "Authenticate to validate CypherAir protected app data access."
        )
        authenticatedContext.interactionNotAllowed = true

        var loadedSecret = try rootSecretStore.loadRootSecret(
            identifier: identifier,
            authenticationContext: authenticatedContext
        )
        defer {
            loadedSecret.protectedDataZeroize()
            authenticatedContext.invalidate()
        }

        XCTAssertEqual(loadedSecret, secret)
    }

    func test_authenticatedBiometricsOnlyContext_canReadBiometricRootSecret() async throws {
        let probeContext = LAContext()
        var probeError: NSError?
        guard probeContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &probeError) else {
            throw XCTSkip(
                "Biometric authentication is unavailable on this device: \(probeError?.localizedDescription ?? "unknown")"
            )
        }

        let identifier = try makeTestRootSecretIdentifier(functionName: #function)
        let secret = Data(repeating: 0xC3, count: 32)
        try rootSecretStore.saveRootSecret(secret, identifier: identifier, policy: .biometricsOnly)

        let authenticatedContext = try await authenticateContext(
            policy: .deviceOwnerAuthenticationWithBiometrics,
            reason: "Authenticate with biometrics to validate CypherAir protected app data access."
        )
        authenticatedContext.interactionNotAllowed = true

        var loadedSecret = try rootSecretStore.loadRootSecret(
            identifier: identifier,
            authenticationContext: authenticatedContext
        )
        defer {
            loadedSecret.protectedDataZeroize()
            authenticatedContext.invalidate()
        }

        XCTAssertEqual(loadedSecret, secret)
    }

    private func authenticateContext(policy: LAPolicy, reason: String) async throws -> LAContext {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(policy, error: &error) else {
            throw XCTSkip(
                "Required LocalAuthentication policy is unavailable: \(error?.localizedDescription ?? "unknown")"
            )
        }

        try await settleAuthenticationSession()
        let didAuthenticate = try await context.evaluatePolicy(policy, localizedReason: reason)
        XCTAssertTrue(didAuthenticate)
        return context
    }

    private func makeTestRootSecretIdentifier(functionName: String) throws -> String {
        let sanitizedFunctionName = functionName
            .replacingOccurrences(of: "[^A-Za-z0-9]+", with: "-", options: .regularExpression)
            .trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        let identifier = "com.cypherair.tests.protected-data.root-secret.\(sanitizedFunctionName).\(UUID().uuidString)"

        try? rootSecretStore.deleteRootSecret(identifier: identifier)
        trackedIdentifiers.append(identifier)
        return identifier
    }

    private func cleanupTrackedRootSecrets() throws {
        for identifier in trackedIdentifiers {
            do {
                try rootSecretStore.deleteRootSecret(identifier: identifier)
            } catch KeychainError.itemNotFound {
                continue
            } catch {
                XCTFail("Failed to clean up protected-data root secret \(identifier): \(error)")
            }
        }

        trackedIdentifiers.removeAll()
    }

    private func settleAuthenticationSession() async throws {
        try await Task.sleep(for: .seconds(2))
    }
}
#endif
