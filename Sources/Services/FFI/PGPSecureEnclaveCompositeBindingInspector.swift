import Foundation

/// Component public keys parsed from a Device-Bound Post-Quantum certificate,
/// used to locate and verify the split-custody handles. `signingComponentPublicKey`
/// and `keyAgreementComponentPublicKey` carry the post-quantum component keys
/// whose byte length is tier-dependent (ML-DSA-65 / ML-KEM-768 for `.postQuantum`,
/// ML-DSA-87 / ML-KEM-1024 for `.postQuantumHigh`); the enclave handle store
/// validates their shape against the tier.
struct PGPSecureEnclaveCompositeBindingInspection: Equatable, Sendable {
    let fingerprint: String
    let keyVersion: UInt8
    let signingKeyFingerprint: String
    let keyAgreementSubkeyFingerprint: String
    let signingComponentPublicKey: Data
    let keyAgreementComponentPublicKey: Data
}

protocol SecureEnclaveCompositeBindingInspecting: Sendable {
    func inspectCompositeBindings(
        publicKeyData: Data,
        tier: SecureEnclaveCustodyTier
    ) throws -> PGPSecureEnclaveCompositeBindingInspection
}

final class PGPSecureEnclaveCompositeBindingInspector: SecureEnclaveCompositeBindingInspecting,
    @unchecked Sendable {
    private let engine: PgpEngine

    init(engine: PgpEngine) {
        self.engine = engine
    }

    func inspectCompositeBindings(
        publicKeyData: Data,
        tier: SecureEnclaveCustodyTier
    ) throws -> PGPSecureEnclaveCompositeBindingInspection {
        do {
            switch tier {
            case .classicalP256:
                throw CypherAirError.invalidKeyData(
                    reason: "The classical custody tier carries no composite bindings."
                )
            case .postQuantum:
                return try Self.performInspect(
                    engine: engine,
                    publicKeyData: publicKeyData
                )
            case .postQuantumHigh:
                return try Self.performInspectHigh(
                    engine: engine,
                    publicKeyData: publicKeyData
                )
            }
        } catch {
            throw PGPErrorMapper.map(error) { .invalidKeyData(reason: $0) }
        }
    }

    private static func performInspect(
        engine: PgpEngine,
        publicKeyData: Data
    ) throws -> PGPSecureEnclaveCompositeBindingInspection {
        let inspection = try engine.inspectSecureEnclaveCompositeBindings(
            publicKeyData: publicKeyData
        )
        return PGPSecureEnclaveCompositeBindingInspection(
            fingerprint: inspection.fingerprint,
            keyVersion: UInt8(inspection.keyVersion),
            signingKeyFingerprint: inspection.signingKeyFingerprint,
            keyAgreementSubkeyFingerprint: inspection.keyAgreementSubkeyFingerprint,
            signingComponentPublicKey: inspection.mldsa65SigningPublicKey,
            keyAgreementComponentPublicKey: inspection.mlkem768KeyAgreementPublicKey
        )
    }

    private static func performInspectHigh(
        engine: PgpEngine,
        publicKeyData: Data
    ) throws -> PGPSecureEnclaveCompositeBindingInspection {
        let inspection = try engine.inspectSecureEnclaveCompositeHighBindings(
            publicKeyData: publicKeyData
        )
        return PGPSecureEnclaveCompositeBindingInspection(
            fingerprint: inspection.fingerprint,
            keyVersion: UInt8(inspection.keyVersion),
            signingKeyFingerprint: inspection.signingKeyFingerprint,
            keyAgreementSubkeyFingerprint: inspection.keyAgreementSubkeyFingerprint,
            signingComponentPublicKey: inspection.mldsa87SigningPublicKey,
            keyAgreementComponentPublicKey: inspection.mlkem1024KeyAgreementPublicKey
        )
    }
}
