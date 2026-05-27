import Foundation

struct SecureEnclaveCustodyHandlePublicBinding: Equatable, Sendable {
    static let p256X963PublicKeyByteCount = 65

    let reference: SecureEnclaveCustodyHandleReference
    let publicKeyX963: Data

    init(reference: SecureEnclaveCustodyHandleReference, publicKeyX963: Data) throws {
        guard Self.hasUncompressedP256X963PublicKeyShape(publicKeyX963) else {
            throw SecureEnclaveCustodyHandleError.invalidPublicKey(reference.role)
        }
        self.reference = reference
        self.publicKeyX963 = publicKeyX963
    }

    var role: PGPPrivateOperationRole {
        reference.role
    }

    static func hasUncompressedP256X963PublicKeyShape(_ data: Data) -> Bool {
        guard data.count == p256X963PublicKeyByteCount,
              data.first == 0x04 else {
            return false
        }
        return data.dropFirst().contains { $0 != 0 }
    }
}
