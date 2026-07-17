import CryptoKit
import Foundation
@testable import CypherAir

/// Software P-256 stand-ins for the Secure Enclave custody operation seams.
/// Enclave key types cannot exist off-hardware, so unit tests register software
/// CryptoKit keys here, hand services binding-only loaded handles, and inject
/// the provider's signer/key-agreement doubles — which enforce the same
/// role/binding/shape guards as the production operations and then produce
/// real ECDSA signatures and ECDH secrets the Rust engine accepts.
final class SoftwareP256CustodyProvider: @unchecked Sendable {
    /// One registry shared across a test process: materials register unique
    /// key pairs, so cross-test lookups cannot collide.
    static let shared = SoftwareP256CustodyProvider()

    struct Material {
        let signingPrivateKey: P256.Signing.PrivateKey
        let keyAgreementPrivateKey: P256.KeyAgreement.PrivateKey

        var signingPublicKeyX963: Data {
            signingPrivateKey.publicKey.x963Representation
        }

        var keyAgreementPublicKeyX963: Data {
            keyAgreementPrivateKey.publicKey.x963Representation
        }
    }

    private let lock = NSLock()
    private var signingKeys: [Data: P256.Signing.PrivateKey] = [:]
    private var keyAgreementKeys: [Data: P256.KeyAgreement.PrivateKey] = [:]

    @discardableResult
    func makeMaterial() -> Material {
        let material = Material(
            signingPrivateKey: P256.Signing.PrivateKey(),
            keyAgreementPrivateKey: P256.KeyAgreement.PrivateKey()
        )
        register(material)
        return material
    }

    func register(_ material: Material) {
        lock.lock()
        defer { lock.unlock() }
        signingKeys[material.signingPublicKeyX963] = material.signingPrivateKey
        keyAgreementKeys[material.keyAgreementPublicKeyX963] = material.keyAgreementPrivateKey
    }

    func signingKey(forPublicKeyX963 publicKey: Data) -> P256.Signing.PrivateKey? {
        lock.lock()
        defer { lock.unlock() }
        return signingKeys[publicKey]
    }

    func keyAgreementKey(forPublicKeyX963 publicKey: Data) -> P256.KeyAgreement.PrivateKey? {
        lock.lock()
        defer { lock.unlock() }
        return keyAgreementKeys[publicKey]
    }

    var digestSigner: SoftwareP256CustodyDigestSigner {
        SoftwareP256CustodyDigestSigner(provider: self)
    }

    var keyAgreement: SoftwareP256CustodyKeyAgreement {
        SoftwareP256CustodyKeyAgreement(provider: self)
    }

    func loadedHandle(
        role: PGPPrivateOperationRole,
        publicKeyX963: Data,
        handleSetIdentifier: String? = nil
    ) throws -> SecureEnclaveCustodyLoadedHandle {
        let reference = try SecureEnclaveCustodyHandleReference(
            handleSetIdentifier: handleSetIdentifier
                ?? SecureEnclaveCustodyHandleReference.generateHandleSetIdentifier(),
            role: role,
            tier: .classicalP256
        )
        return SecureEnclaveCustodyLoadedHandle(
            binding: try SecureEnclaveCustodyHandlePublicBinding(
                reference: reference,
                publicKeyRaw: publicKeyX963
            ),
            privateKey: nil
        )
    }

    func loadedHandlePair(
        for material: Material,
        handleSetIdentifier: String? = nil
    ) throws -> SecureEnclaveCustodyLoadedHandlePair {
        let identifier = try handleSetIdentifier
            ?? SecureEnclaveCustodyHandleReference.generateHandleSetIdentifier()
        return try SecureEnclaveCustodyLoadedHandlePair(
            signing: loadedHandle(
                role: .signing,
                publicKeyX963: material.signingPublicKeyX963,
                handleSetIdentifier: identifier
            ),
            keyAgreement: loadedHandle(
                role: .keyAgreement,
                publicKeyX963: material.keyAgreementPublicKeyX963,
                handleSetIdentifier: identifier
            )
        )
    }
}

struct SoftwareP256CustodyDigestSigner: SecureEnclaveCustodyDigestSigning {
    let provider: SoftwareP256CustodyProvider

    func signSHA256Digest(
        _ digest: Data,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> SecureEnclaveP256RawSignature {
        guard handle.role == .signing else {
            throw SecureEnclaveCustodyHandleError.privateOperationRoleMismatch(
                expected: .signing,
                actual: handle.role
            )
        }
        guard let rawDigest = SecureEnclaveP256SHA256Digest(digest) else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
        }
        guard let privateKey = provider.signingKey(
            forPublicKeyX963: handle.binding.publicKeyRaw
        ) else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
        }

        let signature = try privateKey.signature(for: rawDigest)
        let raw = signature.rawRepresentation
        return try SecureEnclaveP256RawSignature(
            r: raw.prefix(32),
            s: raw.suffix(32)
        )
    }
}

struct SoftwareP256CustodyKeyAgreement: SecureEnclaveCustodyKeyAgreement {
    let provider: SoftwareP256CustodyProvider

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
            throw SecureEnclaveCustodyHandleError.invalidPeerPublicKey(.keyAgreement)
        }
        guard let privateKey = provider.keyAgreementKey(
            forPublicKeyX963: handle.binding.publicKeyRaw
        ) else {
            throw SecureEnclaveCustodyHandleError.privateHandleMissing(.keyAgreement)
        }

        let peerPublicKey: P256.KeyAgreement.PublicKey
        do {
            peerPublicKey = try P256.KeyAgreement.PublicKey(
                x963Representation: request.ephemeralPublicKey
            )
        } catch {
            throw SecureEnclaveCustodyHandleError.invalidPeerPublicKey(.keyAgreement)
        }

        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
        return try SecureEnclaveP256RawSharedSecret(
            raw: sharedSecret.withUnsafeBytes { Data($0) }
        )
    }
}
