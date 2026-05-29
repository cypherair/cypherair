import Foundation

struct PGPSecureEnclaveCustodyPublicBindingInspection: Equatable, Sendable {
    let fingerprint: String
    let keyVersion: UInt8
    let signingKeyFingerprint: String
    let keyAgreementSubkeyFingerprint: String
    let signingPublicKeyX963: Data
    let keyAgreementPublicKeyX963: Data
}

protocol SecureEnclaveCustodyPublicBindingInspecting: Sendable {
    func inspectPublicBindings(
        publicKeyData: Data
    ) throws -> PGPSecureEnclaveCustodyPublicBindingInspection
}

final class PGPSecureEnclaveCustodyPublicBindingInspector: SecureEnclaveCustodyPublicBindingInspecting, @unchecked Sendable {
    private let engine: PgpEngine

    init(engine: PgpEngine) {
        self.engine = engine
    }

    func inspectPublicBindings(
        publicKeyData: Data
    ) throws -> PGPSecureEnclaveCustodyPublicBindingInspection {
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
    ) throws -> PGPSecureEnclaveCustodyPublicBindingInspection {
        let inspection = try engine.inspectSecureEnclavePublicBindings(
            publicKeyData: publicKeyData
        )
        return PGPSecureEnclaveCustodyPublicBindingInspection(
            fingerprint: inspection.fingerprint,
            keyVersion: UInt8(inspection.keyVersion),
            signingKeyFingerprint: inspection.signingKeyFingerprint,
            keyAgreementSubkeyFingerprint: inspection.keyAgreementSubkeyFingerprint,
            signingPublicKeyX963: inspection.signingPublicKeyX963,
            keyAgreementPublicKeyX963: inspection.keyAgreementPublicKeyX963
        )
    }
}
