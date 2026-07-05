import Foundation
import Security

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
        guard request.recipientPublicKey == handle.binding.publicKeyX963 else {
            throw SecureEnclaveCustodyHandleError.handlePublicKeyBindingMismatch(.keyAgreement)
        }
        guard SecureEnclaveCustodyHandlePublicBinding
            .hasUncompressedP256X963PublicKeyShape(request.ephemeralPublicKey) else {
            // The ephemeral point is untrusted peer input from the PKESK packet,
            // not a fault of the local key-agreement handle.
            throw SecureEnclaveCustodyHandleError.invalidPeerPublicKey(.keyAgreement)
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
        guard var sharedSecret = SecKeyCopyKeyExchangeResult(
            privateKey,
            algorithm,
            peerPublicKey,
            [:] as CFDictionary,
            &error
        ) as Data? else {
            throw Self.mapCFError(error)
        }
        // KNOWN LIMITATION: SecKeyCopyKeyExchangeResult returns the shared secret
        // as an immutable CFData bridged to Data. `resetBytes` triggers Data's
        // copy-on-write, so it may zero a fresh copy while the original CFData
        // backing lingers until ARC releases it. The SecKey-backed custody handle
        // leaves no zeroizable alternative here (cf. SECURITY.md §9 on String);
        // exposure is bounded by the short lifetime, ASLR, and MIE. The validated
        // SecureEnclaveP256RawSharedSecret copy below is the carrier; this defer is
        // best-effort scrubbing of the transient bridged buffer.
        defer { sharedSecret.resetBytes(in: 0..<sharedSecret.count) }
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
            // SecKeyCreateWithData rejects malformed/off-curve peer points. This
            // is invalid peer input, not a local handle fault — release the CFError
            // to balance its +1 retain, then surface an invalid-request category.
            _ = error?.takeRetainedValue()
            throw SecureEnclaveCustodyHandleError.invalidPeerPublicKey(.keyAgreement)
        }
        return publicKey
    }

    private static func mapCFError(
        _ error: Unmanaged<CFError>?
    ) -> SecureEnclaveCustodyHandleError {
        SecureEnclaveCustodyOSStatusMapper.handleError(for: error, role: .keyAgreement)
    }
}
