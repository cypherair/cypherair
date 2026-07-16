import Foundation

/// Public binding of one custody handle: the raw public key the certificate
/// carries for this role — an uncompressed X9.63 P-256 point for the classical
/// tier, the FIPS 204/203 raw component key for the post-quantum tiers — used
/// to locate and verify handles without touching the private blob.
struct SecureEnclaveCustodyHandlePublicBinding: Hashable, Sendable {
    static let p256X963PublicKeyByteCount = 65

    let reference: SecureEnclaveCustodyHandleReference
    let publicKeyRaw: Data

    init(reference: SecureEnclaveCustodyHandleReference, publicKeyRaw: Data) throws {
        guard Self.hasExpectedPublicKeyShape(
            publicKeyRaw,
            role: reference.role,
            tier: reference.tier
        ) else {
            throw SecureEnclaveCustodyHandleError.invalidPublicKey(reference.role)
        }
        self.reference = reference
        self.publicKeyRaw = publicKeyRaw
    }

    var role: PGPPrivateOperationRole {
        reference.role
    }

    static func hasExpectedPublicKeyShape(
        _ publicKeyRaw: Data,
        role: PGPPrivateOperationRole,
        tier: SecureEnclaveCustodyTier
    ) -> Bool {
        switch tier {
        case .classicalP256:
            return hasUncompressedP256X963PublicKeyShape(publicKeyRaw)
        case .postQuantum, .postQuantumHigh:
            switch role {
            case .signing:
                return publicKeyRaw.count == tier.signingPublicKeyLength
            case .keyAgreement:
                return publicKeyRaw.count == tier.keyAgreementPublicKeyLength
            }
        }
    }

    static func hasUncompressedP256X963PublicKeyShape(_ data: Data) -> Bool {
        guard data.count == p256X963PublicKeyByteCount,
              data.first == 0x04 else {
            return false
        }
        return data.dropFirst().contains { $0 != 0 }
    }
}
