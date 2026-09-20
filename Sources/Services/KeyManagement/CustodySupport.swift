import CryptoKit
import Foundation
import LocalAuthentication
import Sealing
import Stores
import Vault

extension PGPKeyFamily {
    var deviceBoundCustodyTier: CustodyTier? {
        switch self {
        case .deviceBoundEcdsaNistP256EcdhNistP256V4, .deviceBoundEcdsaNistP256EcdhNistP256:
            .classicalP256
        case .deviceBoundMlDsa65Ed25519MlKem768X25519:
            .postQuantum
        case .deviceBoundMlDsa87Ed448MlKem1024X448:
            .postQuantumHigh
        case .portableEd25519LegacyCurve25519Legacy, .portableEd25519X25519,
             .portableEd448X448, .portableMlDsa65Ed25519MlKem768X25519,
             .portableMlDsa87Ed448MlKem1024X448:
            nil
        }
    }
}

extension PGPPrivateOperationRole {
    var custodyRole: CustodyRole {
        switch self {
        case .signing: .signing
        case .keyAgreement: .keyAgreement
        }
    }
}

extension CustodyRole {
    var operationRole: PGPPrivateOperationRole {
        switch self {
        case .signing: .signing
        case .keyAgreement: .keyAgreement
        }
    }
}

extension CustodyError {
    var failureCategory: PGPKeyOperationFailureCategory {
        switch self {
        case .invalidHandleSetIdentifier, .invalidPublicKey, .privateHandleInaccessible, .ambiguousPrivateHandle, .storage:
            .privateHandleInaccessible
        case .invalidPeerPublicKey:
            .externalOperationInvalidRequest
        case .hardwareUnavailable:
            .hardwareUnavailable
        case .locked, .privateHandleUnauthorized:
            .privateHandleUnauthorized
        case .localAuthenticationCancelled:
            .localAuthenticationCancelled
        case .localAuthenticationFailed:
            .localAuthenticationFailed
        case .localAuthenticationUnavailable:
            .localAuthenticationUnavailable
        case .privateHandleMissing:
            .privateHandleMissing
        case .privateOperationRoleMismatch:
            .privateOperationRoleMismatch
        case .handlePublicKeyBindingMismatch:
            .handlePublicKeyBindingMismatch
        case .partialHandlePair:
            .recoveryRequired
        case .cleanupOrRollbackFailed:
            .cleanupOrRollbackFailure
        }
    }

    var isMissing: Bool {
        if case .privateHandleMissing = self { return true }
        return false
    }
}

/// Maps a store or vault failure on the software-key path to the app's error
/// vocabulary, keeping a refused passphrase, a failed presence check, and a
/// damaged row distinct.
extension CypherAirError {
    static func fromStore(_ error: any Error) -> CypherAirError {
        if let error = error as? CypherAirError { return error }
        if let error = error as? StoreError { return fromStore(error) }
        if let error = error as? VaultError { return fromVault(error) }
        return .keychainError(error.localizedDescription)
    }

    static func fromStore(_ error: StoreError) -> CypherAirError {
        switch error {
        case .vault(let inner): fromVault(inner)
        case .missing: .keyMetadataUnavailable
        case .damaged: .keyOperationUnavailable(category: .privateHandleInaccessible)
        case .invalidFingerprint: .invalidKeyData(reason: "Fingerprint is not hex.")
        case .fileProtectionUnsupported, .fileProtectionVerificationFailed: .keychainError("file protection unavailable")
        case .io(let reason), .internalFailure(let reason): .keychainError(reason)
        }
    }

    static func fromVault(_ error: VaultError) -> CypherAirError {
        switch error {
        case .authenticationCancelled: .operationCancelled
        case .authenticationFailed: .authenticationFailed
        case .authenticationUnavailable: .biometricsUnavailable
        case .locked: .keyOperationUnavailable(category: .privateHandleUnauthorized)
        case .enclaveUnavailable: .keyOperationUnavailable(category: .hardwareUnavailable)
        case .passphraseRejected: .wrongPassphrase
        case .noSealedRoot, .sealedRootCorrupt: .keyOperationUnavailable(category: .recoveryRequired)
        case .storage(let reason), .internalFailure(let reason): .keychainError(reason)
        }
    }
}

/// The two custody keys of one identity, loaded together.
struct LoadedCustodyHandlePair {
    let signing: LoadedCustodyHandle
    let keyAgreement: LoadedCustodyHandle

    init(signing: LoadedCustodyHandle, keyAgreement: LoadedCustodyHandle) throws {
        _ = try CustodyHandlePair(signing: signing.binding, keyAgreement: keyAgreement.binding)
        self.signing = signing
        self.keyAgreement = keyAgreement
    }

    var pair: CustodyHandlePair {
        try! CustodyHandlePair(signing: signing.binding, keyAgreement: keyAgreement.binding)
    }
}

/// The classical half of a split-custody identity, opened for one operation
/// and zeroized when the route ends.
final class SplitCustodyClassicalComponent {
    private(set) var eddsaSecret: Data
    private(set) var ecdhSecret: Data

    init(concatenated: borrowing SensitiveBuffer, tier: CustodyTier) throws {
        guard let lengths = tier.splitCustodyClassicalSecretLengths,
              concatenated.count == lengths.signing + lengths.keyAgreement else {
            throw CypherAirError.invalidKeyData(reason: "Composite classical component has an unexpected length.")
        }
        (eddsaSecret, ecdhSecret) = concatenated.withUnsafeBytes { raw in
            (Data(UnsafeRawBufferPointer(rebasing: raw[..<lengths.signing])),
             Data(UnsafeRawBufferPointer(rebasing: raw[lengths.signing...])))
        }
    }

    /// The scalars the engine returned at generation, joined for sealing.
    static func concatenate(eddsaSecret: borrowing SensitiveBuffer, ecdhSecret: borrowing SensitiveBuffer, tier: CustodyTier) throws -> SensitiveBuffer {
        guard let lengths = tier.splitCustodyClassicalSecretLengths,
              eddsaSecret.count == lengths.signing, ecdhSecret.count == lengths.keyAgreement else {
            throw CypherAirError.invalidKeyData(reason: "Composite classical component secrets have an unexpected length.")
        }
        return eddsaSecret.withUnsafeBytes { eddsa in
            ecdhSecret.withUnsafeBytes { ecdh in
                SensitiveBuffer(count: eddsa.count + ecdh.count) { destination in
                    UnsafeMutableRawBufferPointer(rebasing: destination[..<eddsa.count]).copyMemory(from: eddsa)
                    UnsafeMutableRawBufferPointer(rebasing: destination[eddsa.count...]).copyMemory(from: ecdh)
                }
            }
        }
    }

    func zeroize() {
        eddsaSecret.resetBytes(in: 0..<eddsaSecret.count)
        ecdhSecret.resetBytes(in: 0..<ecdhSecret.count)
    }

    deinit { zeroize() }
}

struct SecureEnclaveP256RawSignature: Equatable, Sendable {
    let r: Data
    let s: Data

    init(r: Data, s: Data) throws {
        guard r.count == 32, s.count == 32, r.contains(where: { $0 != 0 }), s.contains(where: { $0 != 0 }) else {
            throw CustodyError.privateHandleInaccessible(.signing)
        }
        self.r = r
        self.s = s
    }
}

struct SecureEnclaveP256RawSharedSecret: ~Copyable {
    static let rawLength = 32
    let raw: SensitiveBuffer

    init(raw: consuming SensitiveBuffer) throws {
        guard raw.count == Self.rawLength, raw.withUnsafeBytes({ $0.contains { $0 != 0 } }) else {
            throw CustodyError.privateHandleInaccessible(.keyAgreement)
        }
        self.raw = raw
    }
}

/// The seam between a loaded custody handle and the engine's external-signer
/// callbacks. The checks live on the handle; these keep the request shapes.
protocol SecureEnclaveCustodyDigestSigning: Sendable {
    func signSHA256Digest(_ digest: Data, using handle: LoadedCustodyHandle) throws -> SecureEnclaveP256RawSignature
}

protocol SecureEnclaveCustodyKeyAgreement: Sendable {
    func deriveSharedSecret(request: ExternalP256KeyAgreementRequest, using handle: LoadedCustodyHandle) throws -> SecureEnclaveP256RawSharedSecret
}

protocol SecureEnclaveCompositeSigning: Sendable {
    func signMlDsa65Digest(_ digest: Data, using handle: LoadedCustodyHandle) throws -> Data
    func signMlDsa87Digest(_ digest: Data, using handle: LoadedCustodyHandle) throws -> Data
}

protocol SecureEnclaveCompositeDecapsulating: Sendable {
    func decapsulateMlKem768(request: ExternalMlKem768DecapsulationRequest, using handle: LoadedCustodyHandle) throws -> SensitiveBuffer
    func decapsulateMlKem1024(request: ExternalMlKem1024DecapsulationRequest, using handle: LoadedCustodyHandle) throws -> SensitiveBuffer
}

struct CustodyOperations: SecureEnclaveCustodyDigestSigning, SecureEnclaveCustodyKeyAgreement,
    SecureEnclaveCompositeSigning, SecureEnclaveCompositeDecapsulating {
    static let mldsa65SignatureLength = 3309
    static let mldsa87SignatureLength = 4627
    static let mlkem768CiphertextLength = 1088
    static let mlkem1024CiphertextLength = 1568

    func signSHA256Digest(_ digest: Data, using handle: LoadedCustodyHandle) throws -> SecureEnclaveP256RawSignature {
        let (r, s) = try handle.signDigest(digest)
        return try SecureEnclaveP256RawSignature(r: r, s: s)
    }

    func deriveSharedSecret(request: ExternalP256KeyAgreementRequest, using handle: LoadedCustodyHandle) throws -> SecureEnclaveP256RawSharedSecret {
        try SecureEnclaveP256RawSharedSecret(raw: try handle.sharedSecret(
            recipientPublicKeyX963: request.recipientPublicKey,
            ephemeralPublicKeyX963: request.ephemeralPublicKey
        ))
    }

    func signMlDsa65Digest(_ digest: Data, using handle: LoadedCustodyHandle) throws -> Data {
        try compositeSignature(digest, using: handle, tier: .postQuantum, length: Self.mldsa65SignatureLength)
    }

    func signMlDsa87Digest(_ digest: Data, using handle: LoadedCustodyHandle) throws -> Data {
        try compositeSignature(digest, using: handle, tier: .postQuantumHigh, length: Self.mldsa87SignatureLength)
    }

    private func compositeSignature(_ digest: Data, using handle: LoadedCustodyHandle, tier: CustodyTier, length: Int) throws -> Data {
        guard handle.reference.tier == tier else { throw CustodyError.privateHandleInaccessible(.signing) }
        guard (32...64).contains(digest.count) else { throw CustodyError.privateHandleInaccessible(.signing) }
        let signature = try handle.signMessage(digest)
        guard signature.count == length else { throw CustodyError.privateHandleInaccessible(.signing) }
        return signature
    }

    func decapsulateMlKem768(request: ExternalMlKem768DecapsulationRequest, using handle: LoadedCustodyHandle) throws -> SensitiveBuffer {
        try decapsulate(ciphertext: request.mlkemCiphertext, recipientPublicKey: request.recipientMlkemPublicKey, using: handle, tier: .postQuantum, ciphertextLength: Self.mlkem768CiphertextLength)
    }

    func decapsulateMlKem1024(request: ExternalMlKem1024DecapsulationRequest, using handle: LoadedCustodyHandle) throws -> SensitiveBuffer {
        try decapsulate(ciphertext: request.mlkemCiphertext, recipientPublicKey: request.recipientMlkemPublicKey, using: handle, tier: .postQuantumHigh, ciphertextLength: Self.mlkem1024CiphertextLength)
    }

    private func decapsulate(ciphertext: Data, recipientPublicKey: Data, using handle: LoadedCustodyHandle, tier: CustodyTier, ciphertextLength: Int) throws -> SensitiveBuffer {
        guard handle.reference.tier == tier else { throw CustodyError.privateHandleInaccessible(.keyAgreement) }
        guard recipientPublicKey == handle.binding.publicKeyRaw else { throw CustodyError.handlePublicKeyBindingMismatch(.keyAgreement) }
        guard ciphertext.count == ciphertextLength else { throw CustodyError.invalidPeerPublicKey(.keyAgreement) }
        let secret = try handle.decapsulate(ciphertext)
        guard secret.count == 32 else { throw CustodyError.privateHandleInaccessible(.keyAgreement) }
        return secret
    }
}

/// One biometric system-sheet evaluation per custody private operation, whose
/// context then covers the enclave loads that follow.
enum SecureEnclaveCustodyHandleAvailability: Equatable, Sendable {
    case available
    case unavailable(PGPKeyOperationFailureCategory)
}

struct SecureEnclaveCustodyHandleInventorySummary: Equatable, Sendable {
    let totalHandleCount: Int
    let completeSetCount: Int
    let partialSetCount: Int
    let malformedHandleCount: Int

    static let empty = SecureEnclaveCustodyHandleInventorySummary(totalHandleCount: 0, completeSetCount: 0, partialSetCount: 0, malformedHandleCount: 0)

    init(totalHandleCount: Int, completeSetCount: Int, partialSetCount: Int, malformedHandleCount: Int) {
        self.totalHandleCount = totalHandleCount
        self.completeSetCount = completeSetCount
        self.partialSetCount = partialSetCount
        self.malformedHandleCount = malformedHandleCount
    }

    init(inventory: CustodyInventory) {
        let groups = Dictionary(grouping: inventory.bindings, by: \.reference.handleSetIdentifier)
        let complete = groups.values.filter { group in group.contains { $0.role == .signing } && group.contains { $0.role == .keyAgreement } }.count
        self.init(
            totalHandleCount: inventory.totalRowCount,
            completeSetCount: complete,
            partialSetCount: groups.count - complete,
            malformedHandleCount: inventory.malformedRowCount
        )
    }
}
