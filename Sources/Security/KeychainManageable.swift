import Foundation
import LocalAuthentication
import Security

/// Protocol for Keychain operations.
/// Production: Security.framework (kSecClassGenericPassword).
/// Test: In-memory dictionary.
///
/// SECURITY-CRITICAL: Changes to this protocol require human review.
/// See SECURITY.md Section 10.
protocol KeychainManageable {
    /// Save data to the Keychain.
    ///
    /// - Parameters:
    ///   - data: The data to store.
    ///   - service: The Keychain service identifier (e.g., "com.cypherair.v5.privkey-envelope.{fingerprint}").
    ///   - account: The Keychain account identifier.
    ///   - accessControl: Optional SecAccessControl for biometric/passcode protection.
    func save(_ data: Data, service: String, account: String, accessControl: SecAccessControl?) throws

    /// Load data from the Keychain.
    ///
    /// - Parameters:
    ///   - service: The Keychain service identifier.
    ///   - account: The Keychain account identifier.
    /// - Returns: The stored data.
    /// - Throws: If the item is not found or access is denied.
    func load(service: String, account: String, authenticationContext: LAContext?) throws -> Data

    /// Update an existing Keychain item's data.
    ///
    /// - Parameters:
    ///   - data: The replacement data.
    ///   - service: The Keychain service identifier.
    ///   - account: The Keychain account identifier.
    /// - Throws: If the item is not found or the update fails.
    func update(_ data: Data, service: String, account: String, authenticationContext: LAContext?) throws

    /// Delete an item from the Keychain.
    ///
    /// - Parameters:
    ///   - service: The Keychain service identifier.
    ///   - account: The Keychain account identifier.
    func delete(service: String, account: String, authenticationContext: LAContext?) throws

    /// Check if an item exists in the Keychain without loading it.
    func exists(service: String, account: String, authenticationContext: LAContext?) -> Bool

    /// List all service names matching a given prefix.
    /// Used by reset cleanup.
    ///
    /// - Parameters:
    ///   - servicePrefix: The prefix to filter by (e.g., "com.cypherair.v5.").
    ///   - account: The Keychain account identifier.
    /// - Returns: Array of full service names matching the prefix.
    func listItems(servicePrefix: String, account: String, authenticationContext: LAContext?) throws -> [String]
}

extension KeychainManageable {
    func load(service: String, account: String) throws -> Data {
        try load(service: service, account: account, authenticationContext: nil)
    }

    func update(_ data: Data, service: String, account: String) throws {
        try update(data, service: service, account: account, authenticationContext: nil)
    }

    func delete(service: String, account: String) throws {
        try delete(service: service, account: account, authenticationContext: nil)
    }

    func exists(service: String, account: String) -> Bool {
        exists(service: service, account: account, authenticationContext: nil)
    }

    func listItems(servicePrefix: String, account: String) throws -> [String] {
        try listItems(servicePrefix: servicePrefix, account: account, authenticationContext: nil)
    }
}

/// Keychain service name constants.
/// See ARCHITECTURE.md Section 5 for the full storage layout.
enum KeychainConstants {
    /// Prefix for all Keychain items. The version segment is the schema
    /// generation of the persisted format family, nothing more.
    static let prefix = "com.cypherair.v5"

    /// Single self-contained private-key envelope row (`PrivateKeyEnvelope`).
    static func privateKeyEnvelopeService(fingerprint: String) -> String {
        "\(prefix).privkey-envelope.\(fingerprint)"
    }

    /// Temporary private-key envelope row during mode-switch / modify-expiry rewrap.
    static func pendingPrivateKeyEnvelopeService(fingerprint: String) -> String {
        "\(prefix).pending-privkey-envelope.\(fingerprint)"
    }

    /// Stable ProtectedData CAPDSEV5 device-binding label; not a persisted Keychain item.
    static let protectedDataDeviceBindingKeyService = "\(prefix).protected-data.device-binding-key"

    /// Prefix for ProtectedData wrapped domain master key rows.
    static let protectedDataDomainKeyServicePrefix = "\(prefix).protected-data.domain-key."

    /// ProtectedData committed wrapped domain master key record.
    static func protectedDataDomainKeyService(domainID: ProtectedDataDomainID) -> String {
        "\(protectedDataDomainKeyServicePrefix)\(domainID.rawValue)"
    }

    /// ProtectedData staged wrapped domain master key record.
    static func stagedProtectedDataDomainKeyService(domainID: ProtectedDataDomainID) -> String {
        "\(protectedDataDomainKeyServicePrefix)staged.\(domainID.rawValue)"
    }

    /// Default Keychain account identifier.
    static let defaultAccount = "com.cypherair"
}
