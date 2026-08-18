import CryptoKit
import Foundation

/// A P-256 ECDH shared secret that has been checked for the two shapes an
/// enclave key agreement must never hand onward: a wrong length, and an
/// all-zero point that would silently key everything downstream with nothing.
/// Holding the bytes in a `SensitiveBuffer` is what keeps the validated secret
/// the only copy in existence.
struct SecureEnclaveP256RawSharedSecret: ~Copyable {
    static let rawLength = 32

    let raw: SensitiveBuffer

    init(raw: consuming SensitiveBuffer) throws {
        guard raw.count == Self.rawLength,
              raw.withUnsafeBytes({ $0.contains { $0 != 0 } }) else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.keyAgreement)
        }
        self.raw = raw
    }
}

protocol SecureEnclaveCustodyKeyAgreement: Sendable {
    func deriveSharedSecret(
        request: ExternalP256KeyAgreementRequest,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> SecureEnclaveP256RawSharedSecret
}

struct SystemSecureEnclaveCustodyKeyAgreement: SecureEnclaveCustodyKeyAgreement {
    func deriveSharedSecret(
        request: ExternalP256KeyAgreementRequest,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> SecureEnclaveP256RawSharedSecret {
        guard handle.role == .keyAgreement else {
            throw SecureEnclaveCustodyHandleError.privateOperationRoleMismatch(
                expected: .keyAgreement,
                actual: handle.role
            )
        }
        guard request.recipientPublicKey == handle.binding.publicKeyRaw else {
            throw SecureEnclaveCustodyHandleError.handlePublicKeyBindingMismatch(.keyAgreement)
        }
        guard SecureEnclaveCustodyHandlePublicBinding
            .hasUncompressedP256X963PublicKeyShape(request.ephemeralPublicKey) else {
            // The ephemeral point is untrusted peer input from the PKESK packet,
            // not a fault of the local key-agreement handle.
            throw SecureEnclaveCustodyHandleError.invalidPeerPublicKey(.keyAgreement)
        }
        guard case .p256KeyAgreement(let privateKey)? = handle.privateKey else {
            throw SecureEnclaveCustodyHandleError.privateHandleMissing(.keyAgreement)
        }

        let peerPublicKey: P256.KeyAgreement.PublicKey
        do {
            // The x963 initializer rejects malformed and off-curve points.
            peerPublicKey = try P256.KeyAgreement.PublicKey(
                x963Representation: request.ephemeralPublicKey
            )
        } catch {
            throw SecureEnclaveCustodyHandleError.invalidPeerPublicKey(.keyAgreement)
        }

        let sharedSecret: SharedSecret
        do {
            sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
        } catch {
            throw Self.mapEnclaveOperationError(error)
        }

        // Two passes over the CryptoKit secret — one for the length, one for the
        // bytes — rather than one pass through a `Data` the extraction would
        // then have to scrub. CryptoKit clears the `SharedSecret` backing itself.
        let count = sharedSecret.withUnsafeBytes { $0.count }
        let raw = SensitiveBuffer(count: count) { destination in
            sharedSecret.withUnsafeBytes { destination.copyMemory(from: $0) }
        }
        return try SecureEnclaveP256RawSharedSecret(raw: raw)
    }

    private static func mapEnclaveOperationError(_ error: Error) -> SecureEnclaveCustodyHandleError {
        switch SecureEnclaveCustodyAuthenticationErrorNormalizer.normalize(error) {
        case .operationCancelled:
            return .localAuthenticationCancelled(.keyAgreement)
        case .authenticationFailed:
            return .localAuthenticationFailed(.keyAgreement)
        default:
            return .privateHandleUnauthorized(.keyAgreement)
        }
    }
}
