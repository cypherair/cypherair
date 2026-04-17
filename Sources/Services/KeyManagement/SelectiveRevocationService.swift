import Foundation

/// Owns selective (subkey and User ID) revocation-export workflows behind the key-management facade.
///
/// Consumes selector-bearing carrier options (`SubkeySelectionOption`, `UserIdSelectionOption`)
/// produced by the Workstream 3.1 discovery surface and re-validates them against the stored
/// public certificate *before* any Secure Enclave unwrap. This validation includes both
/// selector membership and metadata/public-certificate fingerprint consistency, guaranteeing
/// that a bogus, stale, cross-certificate, or metadata-corrupted selector path fails fast with
/// `CypherAirError.invalidKeyData(...)` without triggering a Face ID / passcode prompt.
///
/// v1 policy (plan §3.4): selective revocations are generated on demand and returned armored.
/// They are not persisted; `KeyCatalogStore` state is not mutated by this service.
final class SelectiveRevocationService {
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

    /// Generate and armor a subkey-scoped revocation signature for the given subkey selection.
    ///
    /// Selector validation precedes SE unwrap: if the stored metadata fingerprint does not
    /// match the discovered certificate fingerprint, or if `subkeySelection.fingerprint`
    /// does not belong to the stored certificate's discovered subkey set, this throws
    /// `CypherAirError.invalidKeyData(...)` without unwrapping any secret material.
    func exportSubkeyRevocationCertificate(
        fingerprint: String,
        subkeySelection: SubkeySelectionOption
    ) async throws -> Data {
        guard let identity = catalogStore.identity(for: fingerprint) else {
            throw CypherAirError.noMatchingKey
        }

        let validatedSubkeyFingerprint = try validatedSubkeyFingerprint(
            certData: identity.publicKeyData,
            expectedFingerprint: identity.fingerprint,
            subkeySelection: subkeySelection
        )

        var secretKey = try privateKeyAccessService.unwrapPrivateKey(fingerprint: fingerprint)
        defer {
            secretKey.resetBytes(in: 0..<secretKey.count)
        }

        let binaryRevocation = try await Self.generateSubkeyRevocationOffMainActor(
            engine: engine,
            certData: secretKey,
            subkeyFingerprint: validatedSubkeyFingerprint
        )

        return try await Self.armorRevocationOffMainActor(
            engine: engine,
            revocationData: binaryRevocation
        )
    }

    /// Generate and armor a User ID-scoped revocation signature for the given User ID selection.
    ///
    /// Selector validation precedes SE unwrap: if the stored metadata fingerprint does not
    /// match the discovered certificate fingerprint, or if `userIdSelection.occurrenceIndex` /
    /// `userIdSelection.userIdData` does not match an entry on the stored certificate's
    /// discovered User ID set, this throws `CypherAirError.invalidKeyData(...)` without
    /// unwrapping any secret material.
    func exportUserIdRevocationCertificate(
        fingerprint: String,
        userIdSelection: UserIdSelectionOption
    ) async throws -> Data {
        guard let identity = catalogStore.identity(for: fingerprint) else {
            throw CypherAirError.noMatchingKey
        }

        let validatedSelectorInput = try validatedUserIdSelectorInput(
            certData: identity.publicKeyData,
            expectedFingerprint: identity.fingerprint,
            userIdSelection: userIdSelection
        )

        var secretKey = try privateKeyAccessService.unwrapPrivateKey(fingerprint: fingerprint)
        defer {
            secretKey.resetBytes(in: 0..<secretKey.count)
        }

        let binaryRevocation = try await Self.generateUserIdRevocationOffMainActor(
            engine: engine,
            certData: secretKey,
            userIdSelector: validatedSelectorInput
        )

        return try await Self.armorRevocationOffMainActor(
            engine: engine,
            revocationData: binaryRevocation
        )
    }

    // MARK: - Selector Validation (public-only, no unwrap)

    private func validatedCatalog(
        certData: Data,
        expectedFingerprint: String
    ) throws -> CertificateSelectionCatalog {
        let discovery = try CertificateSelectionCatalogDiscovery.discover(
            engine: engine,
            certData: certData
        )

        guard discovery.raw.certificateFingerprint == expectedFingerprint else {
            throw CypherAirError.invalidKeyData(
                reason: "Stored key metadata fingerprint does not match certificate data"
            )
        }

        return discovery.catalog
    }

    private func validatedSubkeyFingerprint(
        certData: Data,
        expectedFingerprint: String,
        subkeySelection: SubkeySelectionOption
    ) throws -> String {
        let catalog = try validatedCatalog(
            certData: certData,
            expectedFingerprint: expectedFingerprint
        )

        guard catalog.subkeys.contains(where: { $0.fingerprint == subkeySelection.fingerprint }) else {
            throw CypherAirError.invalidKeyData(
                reason: "Selected subkey does not match the target certificate."
            )
        }

        return subkeySelection.fingerprint
    }

    private func validatedUserIdSelectorInput(
        certData: Data,
        expectedFingerprint: String,
        userIdSelection: UserIdSelectionOption
    ) throws -> UserIdSelectorInput {
        let catalog = try validatedCatalog(
            certData: certData,
            expectedFingerprint: expectedFingerprint
        )

        guard catalog.userIds.contains(where: {
            $0.occurrenceIndex == userIdSelection.occurrenceIndex
                && $0.userIdData == userIdSelection.userIdData
        }) else {
            throw CypherAirError.invalidKeyData(
                reason: "Selected User ID does not match the target certificate."
            )
        }

        return userIdSelection.selectorInput
    }

    // MARK: - Off-Main-Actor Engine Helpers

    @concurrent
    private static func generateSubkeyRevocationOffMainActor(
        engine: PgpEngine,
        certData: Data,
        subkeyFingerprint: String
    ) async throws -> Data {
        do {
            return try engine.generateSubkeyRevocation(
                secretCert: certData,
                subkeyFingerprint: subkeyFingerprint
            )
        } catch {
            throw CypherAirError.from(error) { .revocationError(reason: $0) }
        }
    }

    @concurrent
    private static func generateUserIdRevocationOffMainActor(
        engine: PgpEngine,
        certData: Data,
        userIdSelector: UserIdSelectorInput
    ) async throws -> Data {
        do {
            return try engine.generateUserIdRevocationBySelector(
                secretCert: certData,
                userIdSelector: userIdSelector
            )
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
