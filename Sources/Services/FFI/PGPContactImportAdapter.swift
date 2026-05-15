import Foundation

struct PGPValidatedPublicCertificate: Equatable, Sendable {
    let publicCertData: Data
    let metadata: PGPKeyMetadata
}

enum PGPPublicCertificateMergeOutcome: Equatable, Sendable {
    case noOp
    case updated
}

struct PGPPublicCertificateMergeResult: Equatable, Sendable {
    let mergedCertData: Data
    let outcome: PGPPublicCertificateMergeOutcome
}

/// FFI-owned QR URL and public-certificate import operations.
final class PGPContactImportAdapter: @unchecked Sendable {
    static let publicOnlyReasonToken = "contact_import_public_only"

    private let engine: PgpEngine

    init(engine: PgpEngine) {
        self.engine = engine
    }

    func encodeQrUrl(publicKeyData: Data) throws -> String {
        do {
            return try engine.encodeQrUrl(publicKeyData: publicKeyData)
        } catch {
            throw PGPErrorMapper.map(error) { .invalidKeyData(reason: $0) }
        }
    }

    func decodeQrUrl(_ urlString: String) throws -> Data {
        do {
            return try engine.decodeQrUrl(url: urlString)
        } catch {
            throw CypherAirError.invalidQRCode
        }
    }

    func validateImportablePublicCertificate(
        _ keyData: Data
    ) throws -> PGPValidatedPublicCertificate {
        do {
            let normalizedData = try normalize(keyData)
            let validation = try engine.validatePublicCertificate(certData: normalizedData)
            return PGPValidatedPublicCertificate(
                publicCertData: validation.publicCertData,
                metadata: PGPKeyMetadataAdapter.metadata(from: validation)
            )
        } catch {
            throw mapContactImportError(error)
        }
    }

    func mergePublicCertificateUpdate(
        existingCert: Data,
        incomingCertOrUpdate: Data
    ) throws -> PGPPublicCertificateMergeResult {
        do {
            let result = try engine.mergePublicCertificateUpdate(
                existingCert: existingCert,
                incomingCertOrUpdate: incomingCertOrUpdate
            )
            return PGPPublicCertificateMergeResult(
                mergedCertData: result.mergedCertData,
                outcome: PGPPublicCertificateMergeOutcome(from: result.outcome)
            )
        } catch {
            throw mapContactImportError(error)
        }
    }

    func metadata(forKeyData keyData: Data) throws -> PGPKeyMetadata {
        do {
            let keyInfo = try engine.parseKeyInfo(keyData: keyData)
            let profile = try engine.detectProfile(certData: keyData)
            return PGPKeyMetadataAdapter.metadata(from: keyInfo, profile: profile)
        } catch {
            throw mapContactImportError(error)
        }
    }

    func mapContactImportError(_ error: Error) -> CypherAirError {
        if let cypherAirError = error as? CypherAirError {
            return cypherAirError
        }

        if let pgpError = error as? PgpError,
           case .InvalidKeyData(let reason) = pgpError,
           reason == Self.publicOnlyReasonToken {
            return .contactImportRequiresPublicCertificate
        }

        return PGPErrorMapper.map(error) { .invalidKeyData(reason: $0) }
    }

    private func normalize(_ keyData: Data) throws -> Data {
        guard let firstByte = keyData.first, firstByte == 0x2D else {
            return keyData
        }

        return try engine.dearmor(armored: keyData)
    }
}

private extension PGPPublicCertificateMergeOutcome {
    init(from outcome: CertificateMergeOutcome) {
        switch outcome {
        case .noOp:
            self = .noOp
        case .updated:
            self = .updated
        }
    }
}
