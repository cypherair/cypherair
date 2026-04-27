import XCTest
import CryptoKit
import Security
import LocalAuthentication
@testable import CypherAir

/// Shared base class for device-only security tests.
///
/// These tests exercise real Secure Enclave hardware, real Keychain,
/// and real biometric authentication. They MUST run on a
/// physical device (iPhone 17 Pro Max or any device with Secure Enclave).
///
/// Run with: CypherAir-DeviceTests test plan on a connected device.
class DeviceSecurityTestCase: XCTestCase {
    // MARK: - Properties

    private(set) var keychain: SystemKeychain!
    private(set) var secureEnclave: HardwareSecureEnclave!
    /// Fingerprints created during the test, cleaned up in tearDown.
    private var createdFingerprints: [String] = []
    /// Raw Keychain service keys created during the test, cleaned up in tearDown.
    private var createdKeychainServices: [(service: String, account: String)] = []

    // MARK: - Setup / Teardown

    final override func setUp() {
        super.setUp()
        keychain = SystemKeychain()
        secureEnclave = HardwareSecureEnclave()
    }

    final override func tearDown() {
        // Clean up all Keychain items created during the test.
        let account = KeychainConstants.defaultAccount
        for fingerprint in createdFingerprints {
            // Permanent items
            try? keychain.delete(service: KeychainConstants.seKeyService(fingerprint: fingerprint), account: account)
            try? keychain.delete(service: KeychainConstants.saltService(fingerprint: fingerprint), account: account)
            try? keychain.delete(service: KeychainConstants.sealedKeyService(fingerprint: fingerprint), account: account)
            // Pending items (mode switch)
            try? keychain.delete(service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint), account: account)
            try? keychain.delete(service: KeychainConstants.pendingSaltService(fingerprint: fingerprint), account: account)
            try? keychain.delete(service: KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint), account: account)
        }
        for entry in createdKeychainServices {
            try? keychain.delete(service: entry.service, account: entry.account)
        }
        // Clean up UserDefaults flags
        UserDefaults.standard.removeObject(forKey: AuthPreferences.rewrapInProgressKey)
        UserDefaults.standard.removeObject(forKey: AuthPreferences.authModeKey)
        UserDefaults.standard.removeObject(forKey: AuthPreferences.rewrapTargetModeKey)
        UserDefaults.standard.removeObject(forKey: AuthPreferences.modifyExpiryInProgressKey)
        UserDefaults.standard.removeObject(forKey: AuthPreferences.modifyExpiryFingerprintKey)

        createdFingerprints = []
        createdKeychainServices = []
        keychain = nil
        secureEnclave = nil
        super.tearDown()
    }

    /// Generate a unique test fingerprint to avoid Keychain collisions between tests.
    final func uniqueFingerprint() -> String {
        let fp = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        createdFingerprints.append(fp)
        return fp
    }

    /// Track a Keychain service for cleanup.
    final func trackKeychain(
        service: String,
        account: String = KeychainConstants.defaultAccount
    ) {
        createdKeychainServices.append((service: service, account: account))
    }

    final func waitForAuthenticationSessionToSettle() async throws {
        // Sequential device tests can leave LAContext activity in flight for a moment.
        // Give the system prompt time to fully dismiss before starting the next auth-bound step.
        try await Task.sleep(for: .seconds(2))
    }

    final func makeAuthenticationManager(
        secureEnclave: any SecureEnclaveManageable,
        keychain: any KeychainManageable,
        defaults: UserDefaults = .standard,
        privateKeyControlStore: InMemoryPrivateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
    ) -> AuthenticationManager {
        let authManager = AuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain,
            defaults: defaults
        )
        authManager.configurePrivateKeyControlStore(privateKeyControlStore)
        return authManager
    }

    final func storePermanentBundle(_ bundle: WrappedKeyBundle, fingerprint: String) throws {
        let account = KeychainConstants.defaultAccount
        try keychain.save(
            bundle.seKeyData,
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
        try keychain.save(
            bundle.salt,
            service: KeychainConstants.saltService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
        try keychain.save(
            bundle.sealedBox,
            service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
    }

    final func createWrappedBundle(
        privateKey: Data,
        fingerprint: String,
        mode: AuthenticationMode
    ) throws -> WrappedKeyBundle {
        let accessControl = try mode.createAccessControl()
        let handle = try secureEnclave.generateWrappingKey(accessControl: accessControl)
        return try secureEnclave.wrap(privateKey: privateKey, using: handle, fingerprint: fingerprint)
    }
}
