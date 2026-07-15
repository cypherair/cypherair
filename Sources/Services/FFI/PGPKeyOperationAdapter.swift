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

struct PGPPublicModifiedExpiryKeyMaterial {
    let publicKeyData: Data
    let metadata: PGPKeyMetadata
}

typealias PGPSecretDataZeroizer = @Sendable (inout Data) -> Void

/// FFI-owned key generation, import/export, and key-mutation operations.
final class PGPKeyOperationAdapter: @unchecked Sendable {
    private let engine: PgpEngine
    private let zeroizeSecretData: PGPSecretDataZeroizer

    init(
        engine: PgpEngine,
        zeroizeSecretData: @escaping PGPSecretDataZeroizer = { data in
            data.zeroize()
        }
    ) {
        self.engine = engine
        self.zeroizeSecretData = zeroizeSecretData
    }

    /// A `@Sendable` inspector that returns the primary-key fingerprint
    /// (lowercase hex) of a certificate. The private-key unwrap chokepoint
    /// uses it off the main actor to bind unwrapped secret-certificate material
    /// to the requested identity before any consumer signs, decrypts, or
    /// exports with it. Parsing an unwrapped secret cert here reuses the same
    /// `parseKeyInfo` FFI the adapter already relies on, so the access service
    /// stays FFI-free and mock-testable.
    func certificatePrimaryFingerprintInspector() -> @Sendable (Data) throws -> String {
        let engine = self.engine
        return { certificateData in
            try engine.parseKeyInfo(keyData: certificateData).fingerprint
        }
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
                profile: profile,
                zeroizeSecretData: zeroizeSecretData
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
                passphrase: passphrase,
                zeroizeSecretData: zeroizeSecretData
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
                newExpirySeconds: newExpirySeconds,
                zeroizeSecretData: zeroizeSecretData
            )
        } catch {
            throw PGPErrorMapper.map(error) { .keyGenerationFailed(reason: $0) }
        }
    }

    func modifyExpiryWithExternalP256Signer(
        publicCert: Data,
        signingKeyFingerprint: String,
        signingProvider: ExternalP256SigningProvider,
        newExpirySeconds: UInt64?
    ) async throws -> PGPPublicModifiedExpiryKeyMaterial {
        do {
            return try await Self.performModifyExpiryWithExternalP256Signer(
                engine: engine,
                publicCert: publicCert,
                signingKeyFingerprint: signingKeyFingerprint,
                signingProvider: signingProvider,
                newExpirySeconds: newExpirySeconds
            )
        } catch {
            throw PGPErrorMapper.mapExternalP256Signing(error)
        }
    }

    func modifyExpiryWithExternalCompositeSigner(
        publicCert: Data,
        signingKeyFingerprint: String,
        classicalEddsaSecret: Data,
        signingProvider: ExternalMlDsa65SigningProvider,
        newExpirySeconds: UInt64?
    ) async throws -> PGPPublicModifiedExpiryKeyMaterial {
        do {
            return try await Self.performModifyExpiryWithExternalCompositeSigner(
                engine: engine,
                publicCert: publicCert,
                signingKeyFingerprint: signingKeyFingerprint,
                classicalEddsaSecret: classicalEddsaSecret,
                signingProvider: signingProvider,
                newExpirySeconds: newExpirySeconds
            )
        } catch {
            throw PGPErrorMapper.mapExternalCompositeSigning(error)
        }
    }

    @concurrent
    private static func performGenerateKey(
        engine: PgpEngine,
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        profile: PGPKeyProfile,
        zeroizeSecretData: PGPSecretDataZeroizer
    ) async throws -> PGPGeneratedKeyMaterial {
        var generated = try engine.generateKey(
            name: name,
            email: email,
            expirySeconds: expirySeconds,
            profile: profile.ffiValue
        )
        var shouldZeroizeSecret = true
        defer {
            if shouldZeroizeSecret {
                zeroizeSecretData(&generated.certData)
            }
        }

        let keyInfo = try engine.parseKeyInfo(keyData: generated.publicKeyData)
        let metadata = PGPKeyMetadataAdapter.metadata(
            from: keyInfo,
            profile: profile.ffiValue
        )
        let material = PGPGeneratedKeyMaterial(
            certData: generated.certData,
            publicKeyData: generated.publicKeyData,
            revocationCert: generated.revocationCert,
            metadata: metadata
        )
        shouldZeroizeSecret = false
        return material
    }

    @concurrent
    private static func performImportSecretKey(
        engine: PgpEngine,
        armoredData: Data,
        passphrase: String,
        zeroizeSecretData: PGPSecretDataZeroizer
    ) async throws -> PGPImportedSecretKeyMaterial {
        var secretKeyData = try engine.importSecretKey(
            armoredData: armoredData,
            passphrase: passphrase
        )
        var shouldZeroizeSecret = true
        defer {
            if shouldZeroizeSecret {
                zeroizeSecretData(&secretKeyData)
            }
        }

        let keyInfo = try engine.parseKeyInfo(keyData: secretKeyData)
        let profile = try engine.detectProfile(certData: secretKeyData)
        let metadata = PGPKeyMetadataAdapter.metadata(
            from: keyInfo,
            profile: profile
        )
        let armoredPublicKey = try engine.armorPublicKey(certData: secretKeyData)
        let publicKeyData = try engine.dearmor(armored: armoredPublicKey)
        let revocationCert = try engine.generateKeyRevocation(secretCert: secretKeyData)
        let material = PGPImportedSecretKeyMaterial(
            secretKeyData: secretKeyData,
            metadata: metadata,
            publicKeyData: publicKeyData,
            revocationCert: revocationCert
        )
        shouldZeroizeSecret = false
        return material
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
        newExpirySeconds: UInt64?,
        zeroizeSecretData: PGPSecretDataZeroizer
    ) async throws -> PGPModifiedExpiryKeyMaterial {
        var result = try engine.modifyExpiry(
            certData: certData,
            newExpirySeconds: newExpirySeconds
        )
        var shouldZeroizeSecret = true
        defer {
            if shouldZeroizeSecret {
                zeroizeSecretData(&result.certData)
            }
        }

        let material = PGPModifiedExpiryKeyMaterial(
            certData: result.certData,
            publicKeyData: result.publicKeyData,
            metadata: PGPKeyMetadataAdapter.metadata(from: result.keyInfo)
        )
        shouldZeroizeSecret = false
        return material
    }

    @concurrent
    private static func performModifyExpiryWithExternalP256Signer(
        engine: PgpEngine,
        publicCert: Data,
        signingKeyFingerprint: String,
        signingProvider: ExternalP256SigningProvider,
        newExpirySeconds: UInt64?
    ) async throws -> PGPPublicModifiedExpiryKeyMaterial {
        let result = try engine.modifyExpiryWithExternalP256Signer(
            publicCertData: publicCert,
            signingKeyFingerprint: signingKeyFingerprint,
            signer: signingProvider,
            newExpirySeconds: newExpirySeconds
        )
        return PGPPublicModifiedExpiryKeyMaterial(
            publicKeyData: result.publicKeyData,
            metadata: PGPKeyMetadataAdapter.metadata(from: result.keyInfo)
        )
    }

    @concurrent
    private static func performModifyExpiryWithExternalCompositeSigner(
        engine: PgpEngine,
        publicCert: Data,
        signingKeyFingerprint: String,
        classicalEddsaSecret: Data,
        signingProvider: ExternalMlDsa65SigningProvider,
        newExpirySeconds: UInt64?
    ) async throws -> PGPPublicModifiedExpiryKeyMaterial {
        let result = try engine.modifyExpiryWithExternalCompositeSigner(
            publicCertData: publicCert,
            signingKeyFingerprint: signingKeyFingerprint,
            classicalEddsaSecret: classicalEddsaSecret,
            signer: signingProvider,
            newExpirySeconds: newExpirySeconds
        )
        return PGPPublicModifiedExpiryKeyMaterial(
            publicKeyData: result.publicKeyData,
            metadata: PGPKeyMetadataAdapter.metadata(from: result.keyInfo)
        )
    }

    // MARK: - Device-Bound Post-Quantum · High twin (ML-DSA-87 + Ed448)

    func modifyExpiryWithExternalCompositeHighSigner(
        publicCert: Data,
        signingKeyFingerprint: String,
        classicalEddsaSecret: Data,
        signingProvider: ExternalMlDsa87SigningProvider,
        newExpirySeconds: UInt64?
    ) async throws -> PGPPublicModifiedExpiryKeyMaterial {
        do {
            return try await Self.performModifyExpiryWithExternalCompositeHighSigner(
                engine: engine,
                publicCert: publicCert,
                signingKeyFingerprint: signingKeyFingerprint,
                classicalEddsaSecret: classicalEddsaSecret,
                signingProvider: signingProvider,
                newExpirySeconds: newExpirySeconds
            )
        } catch {
            throw PGPErrorMapper.mapExternalCompositeSigning(error)
        }
    }

    @concurrent
    private static func performModifyExpiryWithExternalCompositeHighSigner(
        engine: PgpEngine,
        publicCert: Data,
        signingKeyFingerprint: String,
        classicalEddsaSecret: Data,
        signingProvider: ExternalMlDsa87SigningProvider,
        newExpirySeconds: UInt64?
    ) async throws -> PGPPublicModifiedExpiryKeyMaterial {
        let result = try engine.modifyExpiryWithExternalCompositeHighSigner(
            publicCertData: publicCert,
            signingKeyFingerprint: signingKeyFingerprint,
            classicalEddsaSecret: classicalEddsaSecret,
            signer: signingProvider,
            newExpirySeconds: newExpirySeconds
        )
        return PGPPublicModifiedExpiryKeyMaterial(
            publicKeyData: result.publicKeyData,
            metadata: PGPKeyMetadataAdapter.metadata(from: result.keyInfo)
        )
    }
}
