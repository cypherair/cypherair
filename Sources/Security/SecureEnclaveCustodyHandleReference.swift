import Foundation
import Security

struct SecureEnclaveCustodyHandleReference: Hashable, Sendable {
    static let applicationTagPrefix = "\(KeychainConstants.prefix).secure-enclave-custody"

    let handleSetIdentifier: String
    let role: PGPPrivateOperationRole

    init(handleSetIdentifier: String, role: PGPPrivateOperationRole) throws {
        guard Self.isValidHandleSetIdentifier(handleSetIdentifier) else {
            throw SecureEnclaveCustodyHandleError.invalidHandleSetIdentifier
        }
        self.handleSetIdentifier = handleSetIdentifier
        self.role = role
    }

    init(applicationTagString: String) throws {
        let prefix = "\(Self.applicationTagPrefix)."
        guard applicationTagString.hasPrefix(prefix) else {
            throw SecureEnclaveCustodyHandleError.invalidApplicationTag
        }
        let remainder = String(applicationTagString.dropFirst(prefix.count))
        let components = remainder.split(separator: ".", omittingEmptySubsequences: false)
        guard components.count == 2,
              let role = PGPPrivateOperationRole(rawValue: String(components[1])) else {
            throw SecureEnclaveCustodyHandleError.invalidApplicationTag
        }
        try self.init(handleSetIdentifier: String(components[0]), role: role)
    }

    var applicationTagString: String {
        "\(Self.applicationTagPrefix).\(handleSetIdentifier).\(role.rawValue)"
    }

    var applicationTagData: Data {
        Data(applicationTagString.utf8)
    }

    static func generateHandleSetIdentifier(byteCount: Int = 16) throws -> String {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    private static func isValidHandleSetIdentifier(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 64 else {
            return false
        }
        return value.utf8.allSatisfy { byte in
            (byte >= 0x30 && byte <= 0x39)
                || (byte >= 0x61 && byte <= 0x7A)
                || byte == 0x2D
                || byte == 0x5F
        }
    }
}
