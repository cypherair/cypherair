import Foundation
import Security

struct SecureEnclaveP256RawSharedSecret: Equatable, Sendable {
    let raw: Data

    init(raw: Data) throws {
        guard raw.count == 32,
              raw.contains(where: { $0 != 0 }) else {
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
        guard request.recipientPublicKey == handle.binding.publicKeyX963 else {
            throw SecureEnclaveCustodyHandleError.handlePublicKeyBindingMismatch(.keyAgreement)
        }
        guard SecureEnclaveCustodyHandlePublicBinding
            .hasUncompressedP256X963PublicKeyShape(request.ephemeralPublicKey) else {
            throw SecureEnclaveCustodyHandleError.invalidPublicKey(.keyAgreement)
        }
        guard let privateKey = handle.privateKey else {
            throw SecureEnclaveCustodyHandleError.privateHandleMissing(.keyAgreement)
        }

        let peerPublicKey = try Self.importP256PublicKey(request.ephemeralPublicKey)
        let algorithm = SecKeyAlgorithm.ecdhKeyExchangeStandard
        guard SecKeyIsAlgorithmSupported(privateKey, .keyExchange, algorithm) else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.keyAgreement)
        }

        var error: Unmanaged<CFError>?
        guard let sharedSecret = SecKeyCopyKeyExchangeResult(
            privateKey,
            algorithm,
            peerPublicKey,
            [:] as CFDictionary,
            &error
        ) as Data? else {
            throw Self.mapCFError(error)
        }
        return try SecureEnclaveP256RawSharedSecret(raw: sharedSecret)
    }

    private static func importP256PublicKey(_ publicKeyX963: Data) throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        guard let publicKey = SecKeyCreateWithData(
            publicKeyX963 as CFData,
            attributes as CFDictionary,
            &error
        ) else {
            throw mapCFError(error)
        }
        return publicKey
    }

    private static func mapCFError(
        _ error: Unmanaged<CFError>?
    ) -> SecureEnclaveCustodyHandleError {
        guard let error else {
            return .privateHandleInaccessible(.keyAgreement)
        }
        let code = OSStatus(CFErrorGetCode(error.takeRetainedValue()))
        switch code {
        case errSecUserCanceled:
            return .localAuthenticationCancelled(.keyAgreement)
        case errSecAuthFailed:
            return .localAuthenticationFailed(.keyAgreement)
        case errSecInteractionNotAllowed:
            return .privateHandleUnauthorized(.keyAgreement)
        case errSecItemNotFound:
            return .privateHandleMissing(.keyAgreement)
        case errSecNotAvailable:
            return .hardwareUnavailable
        default:
            return .privateHandleInaccessible(.keyAgreement)
        }
    }
}
