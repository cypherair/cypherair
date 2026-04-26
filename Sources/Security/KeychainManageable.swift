import Foundation
import LocalAuthentication
import Security

/// Protocol for Keychain operations.
/// Production: Security.framework (kSecClassGenericPassword).
/// Test: In-memory dictionary.
///
/// SECURITY-CRITICAL: Changes to this protocol require human review.
/// See SECURITY.md Section 7.
protocol KeychainManageable {
    /// Save data to the Keychain.
    ///
    /// - Parameters:
    ///   - data: The data to store.
    ///   - service: The Keychain service identifier (e.g., "com.cypherair.v1.se-key.{fingerprint}").
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

    /// Delete an item from the Keychain.
    ///
    /// - Parameters:
    ///   - service: The Keychain service identifier.
    ///   - account: The Keychain account identifier.
    func delete(service: String, account: String, authenticationContext: LAContext?) throws

    /// Check if an item exists in the Keychain without loading it.
    func exists(service: String, account: String, authenticationContext: LAContext?) -> Bool

    /// List all service names matching a given prefix.
    /// Used for key enumeration on cold launch.
    ///
    /// - Parameters:
    ///   - servicePrefix: The prefix to filter by (e.g., "com.cypherair.v1.metadata.").
    ///   - account: The Keychain account identifier.
    /// - Returns: Array of full service names matching the prefix.
    func listItems(servicePrefix: String, account: String, authenticationContext: LAContext?) throws -> [String]
}

extension KeychainManageable {
    func load(service: String, account: String) throws -> Data {
        try load(service: service, account: account, authenticationContext: nil)
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
    /// Prefix for all Keychain items. The "v1" segment enables future migration.
    static let prefix = "com.cypherair.v1"

    /// SE key data representation.
    static func seKeyService(fingerprint: String) -> String {
        "\(prefix).se-key.\(fingerprint)"
    }

    /// HKDF salt.
    static func saltService(fingerprint: String) -> String {
        "\(prefix).salt.\(fingerprint)"
    }

    /// AES-GCM sealed private key.
    static func sealedKeyService(fingerprint: String) -> String {
        "\(prefix).sealed-key.\(fingerprint)"
    }

    /// Temporary SE key during mode switch.
    static func pendingSeKeyService(fingerprint: String) -> String {
        "\(prefix).pending-se-key.\(fingerprint)"
    }

    /// Temporary salt during mode switch.
    static func pendingSaltService(fingerprint: String) -> String {
        "\(prefix).pending-salt.\(fingerprint)"
    }

    /// Temporary sealed key during mode switch.
    static func pendingSealedKeyService(fingerprint: String) -> String {
        "\(prefix).pending-sealed-key.\(fingerprint)"
    }

    /// Key identity metadata (Codable JSON, no sensitive data).
    /// Used for cold-launch key enumeration without SE authentication.
    static func metadataService(fingerprint: String) -> String {
        "\(prefix).metadata.\(fingerprint)"
    }

    /// Service prefix for metadata items (used for enumeration).
    static let metadataPrefix = "\(prefix).metadata."

    /// Default Keychain account identifier.
    static let defaultAccount = "com.cypherair"

    /// Dedicated account for non-sensitive metadata cold-launch enumeration.
    static let metadataAccount = "\(defaultAccount).metadata"
}
