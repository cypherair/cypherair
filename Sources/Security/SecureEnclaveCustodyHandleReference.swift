import Foundation
import Security

/// Identity of one Secure Enclave custody private-key blob in the
/// data-protection keychain: service encodes tier and role, account is the
/// handle-set identifier. One set identifier binds the signing and
/// key-agreement keys of a single device-bound identity.
struct SecureEnclaveCustodyHandleReference: Hashable, Sendable {
    static let servicePrefix = "\(KeychainConstants.prefix).secure-enclave-custody"

    let handleSetIdentifier: String
    let role: PGPPrivateOperationRole
    let tier: SecureEnclaveCustodyTier

    init(
        handleSetIdentifier: String,
        role: PGPPrivateOperationRole,
        tier: SecureEnclaveCustodyTier
    ) throws {
        guard Self.isValidHandleSetIdentifier(handleSetIdentifier) else {
            throw SecureEnclaveCustodyHandleError.invalidHandleSetIdentifier
        }
        self.handleSetIdentifier = handleSetIdentifier
        self.role = role
        self.tier = tier
    }

    /// The service name for one tier/role namespace — the single place it is
    /// spelled, used for per-reference rows and namespace-wide queries alike.
    static func serviceString(tier: SecureEnclaveCustodyTier, role: PGPPrivateOperationRole) -> String {
        "\(servicePrefix).\(tier.serviceNamespaceSegment).\(role.rawValue)"
    }

    var serviceString: String {
        Self.serviceString(tier: tier, role: role)
    }

    var accountString: String {
        handleSetIdentifier
    }

    static func generateHandleSetIdentifier(byteCount: Int = 16) throws -> String {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    /// Reject: a handle-set identifier is only ever app-generated lowercase
    /// hex, so anything else is a malformed row, never normalized.
    static func isValidHandleSetIdentifier(_ value: String) -> Bool {
        HexIdentifier.isValid(value, letterCase: .lowercase, maximumLength: 64)
    }
}
