import CryptoKit
import Foundation

/// The two Secure Enclave primitives of the split-custody composite family,
/// mirroring `SecureEnclaveCustodyDigestSigning` / `SecureEnclaveCustodyKeyAgreement`
/// for the post-quantum components. Rust owns everything else: the Ed25519 and
/// X25519 classical halves, the RFC 9980 KEM combiner, key unwrap, packet
/// assembly, and composite signature verification (docs/POST_QUANTUM.md §4).
protocol SecureEnclaveCompositeSigning: Sendable {
    /// Produce the 3309-byte pure ML-DSA-65 signature over an OpenPGP
    /// signature digest with the Secure Enclave-resident signing component.
    func signMlDsa65Digest(
        _ digest: Data,
        using handle: SecureEnclaveCompositeLoadedHandle
    ) throws -> Data

    /// Produce the 4627-byte pure ML-DSA-87 signature over an OpenPGP
    /// signature digest with the Secure Enclave-resident signing component
    /// (Device-Bound Post-Quantum · High).
    func signMlDsa87Digest(
        _ digest: Data,
        using handle: SecureEnclaveCompositeLoadedHandle
    ) throws -> Data
}

protocol SecureEnclaveCompositeDecapsulating: Sendable {
    /// Decapsulate the 1088-byte ML-KEM-768 ciphertext into the raw 32-byte
    /// key share with the Secure Enclave-resident key-agreement component.
    func decapsulateMlKem768(
        request: ExternalMlKem768DecapsulationRequest,
        using handle: SecureEnclaveCompositeLoadedHandle
    ) throws -> Data

    /// Decapsulate the 1568-byte ML-KEM-1024 ciphertext into the raw 32-byte
    /// key share with the Secure Enclave-resident key-agreement component
    /// (Device-Bound Post-Quantum · High).
    func decapsulateMlKem1024(
        request: ExternalMlKem1024DecapsulationRequest,
        using handle: SecureEnclaveCompositeLoadedHandle
    ) throws -> Data
}

struct SystemSecureEnclaveCompositeOperations: SecureEnclaveCompositeSigning,
    SecureEnclaveCompositeDecapsulating {
    static let mldsa65SignatureLength = 3309
    static let mlkem768CiphertextLength = 1088
    static let mlkem768KeyShareLength = 32
    static let mldsa87SignatureLength = 4627
    static let mlkem1024CiphertextLength = 1568
    static let mlkem1024KeyShareLength = 32

    func signMlDsa65Digest(
        _ digest: Data,
        using handle: SecureEnclaveCompositeLoadedHandle
    ) throws -> Data {
        guard handle.role == .signing else {
            throw SecureEnclaveCustodyHandleError.privateOperationRoleMismatch(
                expected: .signing,
                actual: handle.role
            )
        }
        // OpenPGP signature digests: SHA-256/384/512 and the SHA3 sizes.
        guard (32...64).contains(digest.count) else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
        }
        guard case .mldsa65Signing(let privateKey) = handle.privateKey else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
        }

        let signature: Data
        do {
            signature = try privateKey.signature(for: digest)
        } catch {
            throw Self.mapEnclaveOperationError(error, role: .signing)
        }
        guard signature.count == Self.mldsa65SignatureLength else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
        }
        return signature
    }

    func decapsulateMlKem768(
        request: ExternalMlKem768DecapsulationRequest,
        using handle: SecureEnclaveCompositeLoadedHandle
    ) throws -> Data {
        guard handle.role == .keyAgreement else {
            throw SecureEnclaveCustodyHandleError.privateOperationRoleMismatch(
                expected: .keyAgreement,
                actual: handle.role
            )
        }
        guard request.recipientMlkemPublicKey == handle.binding.publicKeyRaw else {
            throw SecureEnclaveCustodyHandleError.handlePublicKeyBindingMismatch(.keyAgreement)
        }
        guard request.mlkemCiphertext.count == Self.mlkem768CiphertextLength else {
            throw SecureEnclaveCustodyHandleError.invalidPeerPublicKey(.keyAgreement)
        }
        guard case .mlkem768KeyAgreement(let privateKey) = handle.privateKey else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.keyAgreement)
        }

        let sharedSecret: SymmetricKey
        do {
            sharedSecret = try privateKey.decapsulate(request.mlkemCiphertext)
        } catch {
            throw Self.mapEnclaveOperationError(error, role: .keyAgreement)
        }

        var keyShare = sharedSecret.withUnsafeBytes { Data($0) }
        guard keyShare.count == Self.mlkem768KeyShareLength else {
            keyShare.resetBytes(in: 0..<keyShare.count)
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.keyAgreement)
        }
        return keyShare
    }

    func signMlDsa87Digest(
        _ digest: Data,
        using handle: SecureEnclaveCompositeLoadedHandle
    ) throws -> Data {
        guard handle.role == .signing else {
            throw SecureEnclaveCustodyHandleError.privateOperationRoleMismatch(
                expected: .signing,
                actual: handle.role
            )
        }
        // OpenPGP signature digests: SHA-256/384/512 and the SHA3 sizes.
        guard (32...64).contains(digest.count) else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
        }
        guard case .mldsa87Signing(let privateKey) = handle.privateKey else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
        }

        let signature: Data
        do {
            signature = try privateKey.signature(for: digest)
        } catch {
            throw Self.mapEnclaveOperationError(error, role: .signing)
        }
        guard signature.count == Self.mldsa87SignatureLength else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
        }
        return signature
    }

    func decapsulateMlKem1024(
        request: ExternalMlKem1024DecapsulationRequest,
        using handle: SecureEnclaveCompositeLoadedHandle
    ) throws -> Data {
        guard handle.role == .keyAgreement else {
            throw SecureEnclaveCustodyHandleError.privateOperationRoleMismatch(
                expected: .keyAgreement,
                actual: handle.role
            )
        }
        guard request.recipientMlkemPublicKey == handle.binding.publicKeyRaw else {
            throw SecureEnclaveCustodyHandleError.handlePublicKeyBindingMismatch(.keyAgreement)
        }
        guard request.mlkemCiphertext.count == Self.mlkem1024CiphertextLength else {
            throw SecureEnclaveCustodyHandleError.invalidPeerPublicKey(.keyAgreement)
        }
        guard case .mlkem1024KeyAgreement(let privateKey) = handle.privateKey else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.keyAgreement)
        }

        let sharedSecret: SymmetricKey
        do {
            sharedSecret = try privateKey.decapsulate(request.mlkemCiphertext)
        } catch {
            throw Self.mapEnclaveOperationError(error, role: .keyAgreement)
        }

        var keyShare = sharedSecret.withUnsafeBytes { Data($0) }
        guard keyShare.count == Self.mlkem1024KeyShareLength else {
            keyShare.resetBytes(in: 0..<keyShare.count)
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.keyAgreement)
        }
        return keyShare
    }

    private static func mapEnclaveOperationError(
        _ error: Error,
        role: PGPPrivateOperationRole
    ) -> SecureEnclaveCustodyHandleError {
        switch SecureEnclaveCustodyAuthenticationErrorNormalizer.normalize(error) {
        case .operationCancelled:
            return .localAuthenticationCancelled(role)
        case .authenticationFailed:
            return .localAuthenticationFailed(role)
        default:
            return .privateHandleUnauthorized(role)
        }
    }
}
