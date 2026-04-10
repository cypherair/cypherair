import Foundation

enum ContactImportPublicCertificateValidator {
    static let publicOnlyReasonToken = "contact_import_public_only"

    static func validate(
        _ keyData: Data,
        using engine: PgpEngine
    ) throws -> PublicCertificateValidationResult {
        let normalizedData: Data
        do {
            normalizedData = try normalize(keyData, using: engine)
            return try engine.validatePublicCertificate(certData: normalizedData)
        } catch {
            throw mapError(error)
        }
    }

    static func mapError(_ error: Error) -> CypherAirError {
        if let cypherAirError = error as? CypherAirError {
            return cypherAirError
        }

        if let pgpError = error as? PgpError {
            switch pgpError {
            case .InvalidKeyData(let reason) where reason == publicOnlyReasonToken:
                return .contactImportRequiresPublicCertificate
            default:
                return CypherAirError(pgpError: pgpError)
            }
        }

        return .invalidKeyData(reason: error.localizedDescription)
    }

    private static func normalize(_ keyData: Data, using engine: PgpEngine) throws -> Data {
        guard let firstByte = keyData.first, firstByte == 0x2D else {
            return keyData
        }

        return try engine.dearmor(armored: keyData)
    }
}
