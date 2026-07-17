import CryptoKit
import Foundation

struct SecureEnclaveP256RawSharedSecret: Equatable, Sendable {
    private var rawStorage: Data

    var raw: Data {
        rawStorage
    }

    init(raw: Data) throws {
        guard raw.count == 32,
              raw.contains(where: { $0 != 0 }) else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.keyAgreement)
        }
        self.rawStorage = Self.copy(raw)
    }

    func rawCopy() -> Data {
        Self.copy(rawStorage)
    }

    mutating func zeroize() {
        rawStorage.resetBytes(in: 0..<rawStorage.count)
    }

    private static func copy(_ data: Data) -> Data {
        data.withUnsafeBytes { buffer in
            Data(buffer)
        }
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

        var raw = sharedSecret.withUnsafeBytes { Data($0) }
        // The validated carrier below copies; this transient extraction buffer
        // is ours to scrub. CryptoKit zeroizes the SharedSecret backing itself.
        defer { raw.resetBytes(in: 0..<raw.count) }
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
