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

    var serviceString: String {
        "\(Self.servicePrefix).\(tier.serviceNamespaceSegment).\(role.rawValue)"
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

    static func isValidHandleSetIdentifier(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 64 else {
            return false
        }
        return value.utf8.allSatisfy { byte in
            (byte >= 0x30 && byte <= 0x39) || (byte >= 0x61 && byte <= 0x66)
        }
    }
}
