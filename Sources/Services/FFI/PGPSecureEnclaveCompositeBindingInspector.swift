import Foundation

struct PGPSecureEnclaveCompositeBindingInspection: Equatable, Sendable {
    let fingerprint: String
    let keyVersion: UInt8
    let signingKeyFingerprint: String
    let keyAgreementSubkeyFingerprint: String
    let mldsa65SigningPublicKey: Data
    let mlkem768KeyAgreementPublicKey: Data
    let eddsaSigningPublicKey: Data
    let ecdhKeyAgreementPublicKey: Data
}

protocol SecureEnclaveCompositeBindingInspecting: Sendable {
    func inspectCompositeBindings(
        publicKeyData: Data
    ) throws -> PGPSecureEnclaveCompositeBindingInspection
}

final class PGPSecureEnclaveCompositeBindingInspector: SecureEnclaveCompositeBindingInspecting,
    @unchecked Sendable {
    private let engine: PgpEngine

    init(engine: PgpEngine) {
        self.engine = engine
    }

    func inspectCompositeBindings(
        publicKeyData: Data
    ) throws -> PGPSecureEnclaveCompositeBindingInspection {
        do {
            return try Self.performInspect(
                engine: engine,
                publicKeyData: publicKeyData
            )
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
            mldsa65SigningPublicKey: inspection.mldsa65SigningPublicKey,
            mlkem768KeyAgreementPublicKey: inspection.mlkem768KeyAgreementPublicKey,
            eddsaSigningPublicKey: inspection.eddsaSigningPublicKey,
            ecdhKeyAgreementPublicKey: inspection.ecdhKeyAgreementPublicKey
        )
    }
}
