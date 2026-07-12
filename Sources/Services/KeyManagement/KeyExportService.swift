import Foundation

/// Owns key export and revocation-export workflows behind the key-management facade.
final class KeyExportService {
    private let keyAdapter: PGPKeyOperationAdapter
    private let certificateAdapter: PGPCertificateOperationAdapter
    private let catalogStore: KeyCatalogStore
    private let privateKeyAccessService: PrivateKeyAccessService

    init(
        keyAdapter: PGPKeyOperationAdapter,
        certificateAdapter: PGPCertificateOperationAdapter,
        catalogStore: KeyCatalogStore,
        privateKeyAccessService: PrivateKeyAccessService
    ) {
        self.keyAdapter = keyAdapter
        self.certificateAdapter = certificateAdapter
        self.catalogStore = catalogStore
        self.privateKeyAccessService = privateKeyAccessService
    }

    func exportKey(
        fingerprint: String,
        passphrase: String,
        markBackedUp: Bool = true
    ) async throws -> Data {
        guard let identity = catalogStore.identity(for: fingerprint) else {
            throw CypherAirError.keyMetadataUnavailable
        }
        guard identity.privateKeyCustodyKind == .softwareSecretCertificate else {
            throw CypherAirError.keyOperationUnavailable(category: .operationUnsupportedForCustody)
        }
        // Software custody implies a portable software family (enforced by the
        // key-metadata domain contract); guard before unwrapping any secret.
        guard let softwareProfile = identity.softwareProfile else {
            throw CypherAirError.internalError(
                reason: "Secret-key export requires a portable software profile."
            )
        }

        var secretKey = try await privateKeyAccessService.unwrapPrivateKey(fingerprint: fingerprint)
        defer {
            secretKey.resetBytes(in: 0..<secretKey.count)
        }

        let exported = try await keyAdapter.exportSecretKey(
            certData: secretKey,
            passphrase: passphrase,
            profile: softwareProfile
        )

        if markBackedUp {
            catalogStore.markBackedUp(fingerprint: fingerprint)
        }
        return exported
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
