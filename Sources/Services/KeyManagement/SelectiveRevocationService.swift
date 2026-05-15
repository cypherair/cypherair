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
    private let certificateAdapter: PGPCertificateOperationAdapter
    private let catalogStore: KeyCatalogStore
    private let privateKeyAccessService: PrivateKeyAccessService

    init(
        certificateAdapter: PGPCertificateOperationAdapter,
        catalogStore: KeyCatalogStore,
        privateKeyAccessService: PrivateKeyAccessService
    ) {
        self.certificateAdapter = certificateAdapter
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

        // Once selector validation succeeds, SE unwrap may trigger a system auth prompt
        // before the caller can observe task cancellation. Callers should treat dismissal
        // as suppressing late results, not as a guarantee that auth never begins.
        var secretKey = try await privateKeyAccessService.unwrapPrivateKey(fingerprint: fingerprint)
        defer {
            secretKey.resetBytes(in: 0..<secretKey.count)
        }

        let binaryRevocation = try await certificateAdapter.generateSubkeyRevocation(
            secretCert: secretKey,
            subkeyFingerprint: validatedSubkeyFingerprint
        )

        return try await certificateAdapter.armorSignature(binaryRevocation)
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

        let validatedUserIdSelection = try validatedUserIdSelection(
            certData: identity.publicKeyData,
            expectedFingerprint: identity.fingerprint,
            userIdSelection: userIdSelection
        )

        // Once selector validation succeeds, SE unwrap may trigger a system auth prompt
        // before the caller can observe task cancellation. Callers should treat dismissal
        // as suppressing late results, not as a guarantee that auth never begins.
        var secretKey = try await privateKeyAccessService.unwrapPrivateKey(fingerprint: fingerprint)
        defer {
            secretKey.resetBytes(in: 0..<secretKey.count)
        }

        let binaryRevocation = try await certificateAdapter.generateUserIdRevocation(
            secretCert: secretKey,
            selectedUserId: validatedUserIdSelection
        )

        return try await certificateAdapter.armorSignature(binaryRevocation)
    }

    // MARK: - Selector Validation (public-only, no unwrap)

    private func validatedCatalog(
        certData: Data,
        expectedFingerprint: String
    ) throws -> CertificateSelectionCatalog {
        try certificateAdapter.validatedCatalog(
            certData: certData,
            expectedFingerprint: expectedFingerprint
        )
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

    private func validatedUserIdSelection(
        certData: Data,
        expectedFingerprint: String,
        userIdSelection: UserIdSelectionOption
    ) throws -> UserIdSelectionOption {
        let catalog = try validatedCatalog(
            certData: certData,
            expectedFingerprint: expectedFingerprint
        )

        return try certificateAdapter.validateUserIdSelection(
            userIdSelection,
            in: catalog
        )
    }
}
