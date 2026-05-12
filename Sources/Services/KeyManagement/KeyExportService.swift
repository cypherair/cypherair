import Foundation

/// Owns key export and revocation-export workflows behind the key-management facade.
final class KeyExportService {
    private let engine: PgpEngine
    private let catalogStore: KeyCatalogStore
    private let privateKeyAccessService: PrivateKeyAccessService

    init(
        engine: PgpEngine,
        catalogStore: KeyCatalogStore,
        privateKeyAccessService: PrivateKeyAccessService
    ) {
        self.engine = engine
        self.catalogStore = catalogStore
        self.privateKeyAccessService = privateKeyAccessService
    }

    func exportKey(
        fingerprint: String,
        passphrase: String,
        markBackedUp: Bool = true
    ) async throws -> Data {
        var secretKey = try await privateKeyAccessService.unwrapPrivateKey(fingerprint: fingerprint)
        defer {
            secretKey.resetBytes(in: 0..<secretKey.count)
        }

        guard let identity = catalogStore.identity(for: fingerprint) else {
            throw CypherAirError.noMatchingKey
        }

        let exported = try await Self.exportKeyOffMainActor(
            engine: engine,
            certData: secretKey,
            passphrase: passphrase,
            profile: identity.profile
        )

        if markBackedUp {
            catalogStore.markBackedUp(fingerprint: fingerprint)
        }
        return exported
    }

    func exportRevocationCertificate(fingerprint: String) async throws -> Data {
        guard let identity = catalogStore.identity(for: fingerprint) else {
            throw CypherAirError.noMatchingKey
        }

        if !identity.revocationCert.isEmpty {
            return try await Self.armorRevocationOffMainActor(
                engine: engine,
                revocationData: identity.revocationCert
            )
        }

        var secretKey = try await privateKeyAccessService.unwrapPrivateKey(fingerprint: fingerprint)
        defer {
            secretKey.resetBytes(in: 0..<secretKey.count)
        }

        let generatedRevocation = try await Self.generateKeyRevocationOffMainActor(
            engine: engine,
            certData: secretKey
        )
        let armoredRevocation = try await Self.armorRevocationOffMainActor(
            engine: engine,
            revocationData: generatedRevocation
        )

        catalogStore.updateRevocation(
            fingerprint: fingerprint,
            revocationCert: generatedRevocation
        )

        return armoredRevocation
    }

    func exportPublicKey(fingerprint: String) throws -> Data {
        guard let identity = catalogStore.identity(for: fingerprint) else {
            throw CypherAirError.noMatchingKey
        }

        do {
            return try engine.armorPublicKey(certData: identity.publicKeyData)
        } catch {
            throw CypherAirError.from(error) { .armorError(reason: $0) }
        }
    }

    @concurrent
    private static func exportKeyOffMainActor(
        engine: PgpEngine,
        certData: Data,
        passphrase: String,
        profile: KeyProfile
    ) async throws -> Data {
        do {
            return try engine.exportSecretKey(
                certData: certData,
                passphrase: passphrase,
                profile: profile
            )
        } catch {
            throw CypherAirError.from(error) { .s2kError(reason: $0) }
        }
    }

    @concurrent
    private static func generateKeyRevocationOffMainActor(
        engine: PgpEngine,
        certData: Data
    ) async throws -> Data {
        do {
            return try engine.generateKeyRevocation(secretCert: certData)
        } catch {
            throw CypherAirError.from(error) { .revocationError(reason: $0) }
        }
    }

    @concurrent
    private static func armorRevocationOffMainActor(
        engine: PgpEngine,
        revocationData: Data
    ) async throws -> Data {
        do {
            return try engine.armor(data: revocationData, kind: .signature)
        } catch {
            throw CypherAirError.from(error) { .armorError(reason: $0) }
        }
    }
}
