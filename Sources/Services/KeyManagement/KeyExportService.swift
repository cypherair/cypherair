import Foundation

/// Owns key export and revocation-export workflows behind the key-management facade.
final class KeyExportService {
    private let keyAdapter: PGPKeyOperationAdapter
    private let certificateAdapter: PGPCertificateOperationAdapter
    private let catalogStore: KeyCatalogStore
    private let privateKeyAccessService: PrivateKeyAccessService
    private let memoryInfo: any MemoryInfoProvidable

    init(
        keyAdapter: PGPKeyOperationAdapter,
        certificateAdapter: PGPCertificateOperationAdapter,
        catalogStore: KeyCatalogStore,
        privateKeyAccessService: PrivateKeyAccessService,
        memoryInfo: any MemoryInfoProvidable
    ) {
        self.keyAdapter = keyAdapter
        self.certificateAdapter = certificateAdapter
        self.catalogStore = catalogStore
        self.privateKeyAccessService = privateKeyAccessService
        self.memoryInfo = memoryInfo
    }

    func exportKey(
        fingerprint: String,
        passphrase: String
    ) async throws -> Data {
        guard let identity = catalogStore.identity(for: fingerprint) else {
            throw CypherAirError.keyMetadataUnavailable
        }
        guard identity.custody == .portable else {
            throw CypherAirError.keyOperationUnavailable(category: .operationUnsupportedForCustody)
        }
        // Every portable family has a software suite; guard before unwrapping
        // any secret. The engine derives the export S2K mode from the
        // certificate itself, so the suite here only has to agree with that
        // classification for the memory check below to describe the real cost.
        guard let suite = identity.softwareSuite else {
            throw CypherAirError.internalError(
                reason: "Secret-key export requires a portable family."
            )
        }

        // The export derivation is as memory-hard as an import and just as
        // capable of getting the process terminated part-way through. Refusing
        // here — before the authentication prompt and before the private key
        // leaves the enclave — is the whole point of checking from the suite
        // rather than from the certificate.
        try Argon2idMemoryGuard(memoryInfo: memoryInfo).validate(
            protectionInfo: keyAdapter.exportProtectionInfo(suite: suite)
        )

        var secretKey = try await privateKeyAccessService.unwrapPrivateKey(fingerprint: fingerprint)
        defer {
            secretKey.resetBytes(in: 0..<secretKey.count)
        }

        return try await keyAdapter.exportSecretKey(
            certData: secretKey,
            passphrase: passphrase
        )
    }

    func exportRevocationCertificate(fingerprint: String) async throws -> Data {
        guard let identity = catalogStore.identity(for: fingerprint) else {
            throw CypherAirError.keyMetadataUnavailable
        }
        guard !identity.revocationCert.isEmpty else {
            throw CypherAirError.keyOperationUnavailable(category: .revocationArtifactUnavailable)
        }

        return try await certificateAdapter.armorSignature(identity.revocationCert)
    }

    func exportPublicKey(fingerprint: String) throws -> Data {
        guard let identity = catalogStore.identity(for: fingerprint) else {
            throw CypherAirError.keyMetadataUnavailable
        }

        return try keyAdapter.armorPublicKey(certData: identity.publicKeyData)
    }

}
