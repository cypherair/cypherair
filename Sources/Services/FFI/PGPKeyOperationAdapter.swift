import Foundation

struct PGPGeneratedKeyMaterial {
    var certData: Data
    let publicKeyData: Data
    let revocationCert: Data
    let metadata: PGPKeyMetadata
}

struct PGPImportedSecretKeyMaterial {
    var secretKeyData: Data
    let metadata: PGPKeyMetadata
    let publicKeyData: Data
    let revocationCert: Data
}

struct PGPModifiedExpiryKeyMaterial {
    var certData: Data
    let publicKeyData: Data
    let metadata: PGPKeyMetadata
}

/// FFI-owned key generation, import/export, and key-mutation operations.
final class PGPKeyOperationAdapter: @unchecked Sendable {
    private let engine: PgpEngine

    init(engine: PgpEngine) {
        self.engine = engine
    }

    func generateKey(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        profile: PGPKeyProfile
    ) async throws -> PGPGeneratedKeyMaterial {
        do {
            return try await Self.performGenerateKey(
                engine: engine,
                name: name,
                email: email,
                expirySeconds: expirySeconds,
                profile: profile
            )
        } catch {
            throw PGPErrorMapper.map(error) { .keyGenerationFailed(reason: $0) }
        }
    }

    func importProtectionInfo(armoredData: Data) throws -> PGPKeyImportS2KInfo {
        do {
            let s2kInfo = try engine.parseS2kParams(armoredData: armoredData)
            return PGPKeyImportS2KInfo(
                s2kType: s2kInfo.s2kType,
                memoryKib: s2kInfo.memoryKib
            )
        } catch {
            throw PGPErrorMapper.map(error) { .invalidKeyData(reason: $0) }
        }
    }

    func importSecretKey(
        armoredData: Data,
        passphrase: String
    ) async throws -> PGPImportedSecretKeyMaterial {
        do {
            return try await Self.performImportSecretKey(
                engine: engine,
                armoredData: armoredData,
                passphrase: passphrase
            )
        } catch {
            throw PGPErrorMapper.map(error) { .invalidKeyData(reason: $0) }
        }
    }

    func exportSecretKey(
        certData: Data,
        passphrase: String,
        profile: PGPKeyProfile
    ) async throws -> Data {
        do {
            return try await Self.performExportSecretKey(
                engine: engine,
                certData: certData,
                passphrase: passphrase,
                profile: profile
            )
        } catch {
            throw PGPErrorMapper.map(error) { .s2kError(reason: $0) }
        }
    }

    func armorPublicKey(certData: Data) throws -> Data {
        do {
            return try engine.armorPublicKey(certData: certData)
        } catch {
            throw PGPErrorMapper.map(error) { .armorError(reason: $0) }
        }
    }

    func modifyExpiry(
        certData: Data,
        newExpirySeconds: UInt64?
    ) async throws -> PGPModifiedExpiryKeyMaterial {
        do {
            return try await Self.performModifyExpiry(
                engine: engine,
                certData: certData,
                newExpirySeconds: newExpirySeconds
            )
        } catch {
            throw PGPErrorMapper.map(error) { .keyGenerationFailed(reason: $0) }
        }
    }

    @concurrent
    private static func performGenerateKey(
        engine: PgpEngine,
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        profile: PGPKeyProfile
    ) async throws -> PGPGeneratedKeyMaterial {
        let generated = try engine.generateKey(
            name: name,
            email: email,
            expirySeconds: expirySeconds,
            profile: profile.ffiValue
        )
        let keyInfo = try engine.parseKeyInfo(keyData: generated.publicKeyData)
        let metadata = PGPKeyMetadataAdapter.metadata(
            from: keyInfo,
            profile: profile.ffiValue
        )
        return PGPGeneratedKeyMaterial(
            certData: generated.certData,
            publicKeyData: generated.publicKeyData,
            revocationCert: generated.revocationCert,
            metadata: metadata
        )
    }

    @concurrent
    private static func performImportSecretKey(
        engine: PgpEngine,
        armoredData: Data,
        passphrase: String
    ) async throws -> PGPImportedSecretKeyMaterial {
        let secretKeyData = try engine.importSecretKey(
            armoredData: armoredData,
            passphrase: passphrase
        )
        let keyInfo = try engine.parseKeyInfo(keyData: secretKeyData)
        let profile = try engine.detectProfile(certData: secretKeyData)
        let metadata = PGPKeyMetadataAdapter.metadata(
            from: keyInfo,
            profile: profile
        )
        let armoredPublicKey = try engine.armorPublicKey(certData: secretKeyData)
        let publicKeyData = try engine.dearmor(armored: armoredPublicKey)
        let revocationCert = try engine.generateKeyRevocation(secretCert: secretKeyData)
        return PGPImportedSecretKeyMaterial(
            secretKeyData: secretKeyData,
            metadata: metadata,
            publicKeyData: publicKeyData,
            revocationCert: revocationCert
        )
    }

    @concurrent
    private static func performExportSecretKey(
        engine: PgpEngine,
        certData: Data,
        passphrase: String,
        profile: PGPKeyProfile
    ) async throws -> Data {
        try engine.exportSecretKey(
            certData: certData,
            passphrase: passphrase,
            profile: profile.ffiValue
        )
    }

    @concurrent
    private static func performModifyExpiry(
        engine: PgpEngine,
        certData: Data,
        newExpirySeconds: UInt64?
    ) async throws -> PGPModifiedExpiryKeyMaterial {
        let result = try engine.modifyExpiry(
            certData: certData,
            newExpirySeconds: newExpirySeconds
        )
        return PGPModifiedExpiryKeyMaterial(
            certData: result.certData,
            publicKeyData: result.publicKeyData,
            metadata: PGPKeyMetadataAdapter.metadata(from: result.keyInfo)
        )
    }
}
