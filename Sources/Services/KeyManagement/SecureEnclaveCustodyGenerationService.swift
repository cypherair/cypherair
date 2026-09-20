import Foundation
import LocalAuthentication
import Sealing
import Stores
import Vault

/// Generates device-bound identities: a fresh custody key pair in the enclave
/// under one approval, the certificate built through the engine's external
/// signer, and for the post-quantum families the classical half sealed against
/// the identity wrapping key. Any failure undoes what was created.
final class SecureEnclaveCustodyGenerationService: @unchecked Sendable {
    typealias GenerationCheckpoint = @Sendable () async throws -> Void

    private let certificateBuilder: any SecureEnclaveCustodyCertificateBuilding
    private let vault: AppVault
    private let digestSigner: any SecureEnclaveCustodyDigestSigning
    private let compositeCertificateBuilder: (any SecureEnclaveCompositeCertificateBuilding)?
    private let compositeSigner: (any SecureEnclaveCompositeSigning)?
    private let catalogStore: KeyCatalogStore
    private let resolver: PGPKeyCapabilityResolver
    private let invalidationGate: KeyProvisioningInvalidationGate
    private let commitCoordinator: KeyProvisioningCommitCoordinator
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator?
    private let afterIdentityCommitCheckpoint: GenerationCheckpoint?

    init(
        certificateBuilder: any SecureEnclaveCustodyCertificateBuilding,
        vault: AppVault,
        digestSigner: any SecureEnclaveCustodyDigestSigning,
        compositeCertificateBuilder: (any SecureEnclaveCompositeCertificateBuilding)? = nil,
        compositeSigner: (any SecureEnclaveCompositeSigning)? = nil,
        catalogStore: KeyCatalogStore,
        resolver: PGPKeyCapabilityResolver,
        invalidationGate: KeyProvisioningInvalidationGate,
        commitCoordinator: KeyProvisioningCommitCoordinator,
        authenticationPromptCoordinator: AuthenticationPromptCoordinator? = nil,
        afterIdentityCommitCheckpoint: GenerationCheckpoint? = nil
    ) {
        self.certificateBuilder = certificateBuilder
        self.vault = vault
        self.digestSigner = digestSigner
        self.compositeCertificateBuilder = compositeCertificateBuilder
        self.compositeSigner = compositeSigner
        self.catalogStore = catalogStore
        self.resolver = resolver
        self.invalidationGate = invalidationGate
        self.commitCoordinator = commitCoordinator
        self.authenticationPromptCoordinator = authenticationPromptCoordinator
        self.afterIdentityCommitCheckpoint = afterIdentityCommitCheckpoint
    }

    func generateKey(
        name: String,
        email: String?,
        validity: PGPKeyValidity,
        family: PGPKeyFamily,
        invalidationToken token: KeyProvisioningInvalidationGate.Token
    ) async throws -> PGPKeyIdentity {
        guard let tier = family.deviceBoundCustodyTier else {
            throw CypherAirError.invalidKeyData(reason: "Secure Enclave custody generation requires a device-bound family.")
        }
        let resolution = resolver.resolution(for: .generate, family: family, custody: .appleSecureEnclavePrivateOperations)
        guard resolution.support == .supported else {
            throw CypherAirError.keyOperationUnavailable(category: resolution.failureCategory ?? .operationUnavailableByPolicy)
        }
        try Task.checkCancellation()
        try invalidationGate.checkValid(token)
        switch tier {
        case .classicalP256:
            return try await generateClassical(name: name, email: email, validity: validity, family: family, token: token)
        case .postQuantum, .postQuantumHigh:
            return try await generateComposite(name: name, email: email, validity: validity, family: family, tier: tier, token: token)
        }
    }

    private func generateClassical(
        name: String, email: String?, validity: PGPKeyValidity, family: PGPKeyFamily,
        token: KeyProvisioningInvalidationGate.Token
    ) async throws -> PGPKeyIdentity {
        let authorized = try await createAuthorizedHandlePair(tier: .classicalP256)
        defer { authorized.context.invalidate() }
        var storedFingerprint: String?
        do {
            try Task.checkCancellation()
            try invalidationGate.checkValid(token)
            let generated = try await certificateBuilder.generatePublicCertificate(
                name: name, email: email, validity: validity, family: family,
                handlePair: authorized.pair, digestSigner: digestSigner
            )
            try Task.checkCancellation()
            try invalidationGate.checkValid(token)
            return try await commit(
                metadata: generated.metadata, publicKeyData: generated.publicKeyData, revocationCert: generated.revocationCert,
                family: family, token: token
            ) { storedFingerprint = $0 }
        } catch {
            do {
                try rollback(pair: authorized.pair.pair, splitCustodyFingerprint: nil, storedFingerprint: storedFingerprint)
            } catch {
                throw CustodyError.cleanupOrRollbackFailed
            }
            throw error
        }
    }

    private func generateComposite(
        name: String, email: String?, validity: PGPKeyValidity, family: PGPKeyFamily, tier: CustodyTier,
        token: KeyProvisioningInvalidationGate.Token
    ) async throws -> PGPKeyIdentity {
        guard let compositeCertificateBuilder, let compositeSigner else {
            throw CypherAirError.keyOperationUnavailable(category: .operationUnavailableByPolicy)
        }
        let authorized = try await createAuthorizedHandlePair(tier: tier)
        defer { authorized.context.invalidate() }
        var storedFingerprint: String?
        var sealedFingerprint: String?
        do {
            try Task.checkCancellation()
            try invalidationGate.checkValid(token)
            var generated = try await compositeCertificateBuilder.generateCompositeCertificate(
                name: name, email: email, validity: validity,
                handlePair: authorized.pair, compositeSigner: compositeSigner
            )
            let eddsa = SensitiveBuffer(consuming: &generated.classicalEddsaSecret)
            let ecdh = SensitiveBuffer(consuming: &generated.classicalEcdhSecret)
            let concatenated = try SplitCustodyClassicalComponent.concatenate(eddsaSecret: eddsa, ecdhSecret: ecdh, tier: tier)
            try Task.checkCancellation()
            try invalidationGate.checkValid(token)
            do {
                try vault.splitCustody.seal(concatenated, fingerprint: generated.metadata.fingerprint, session: try vault.requireSession())
            } catch {
                throw CypherAirError.fromStore(error)
            }
            sealedFingerprint = generated.metadata.fingerprint
            return try await commit(
                metadata: generated.metadata, publicKeyData: generated.publicKeyData, revocationCert: generated.revocationCert,
                family: family, token: token
            ) { storedFingerprint = $0 }
        } catch {
            do {
                try rollback(pair: authorized.pair.pair, splitCustodyFingerprint: sealedFingerprint, storedFingerprint: storedFingerprint)
            } catch {
                throw CustodyError.cleanupOrRollbackFailed
            }
            throw error
        }
    }

    private func commit(
        metadata: PGPKeyMetadata,
        publicKeyData: Data,
        revocationCert: Data,
        family: PGPKeyFamily,
        token: KeyProvisioningInvalidationGate.Token,
        didStore: (String) -> Void
    ) async throws -> PGPKeyIdentity {
        try await commitCoordinator.performCommit {
            try Task.checkCancellation()
            try invalidationGate.checkValid(token)
            guard !catalogStore.containsKey(fingerprint: metadata.fingerprint) else {
                throw CypherAirError.duplicateKey
            }
            let identity = PGPKeyIdentity(
                fingerprint: metadata.fingerprint,
                userId: metadata.userId,
                hasEncryptionSubkey: metadata.hasEncryptionSubkey,
                isRevoked: false,
                isExpired: metadata.isExpired,
                isDefault: catalogStore.keys.isEmpty,
                isBackedUp: false,
                publicKeyData: publicKeyData,
                revocationCert: revocationCert,
                primaryAlgo: metadata.primaryAlgo,
                subkeyAlgo: metadata.subkeyAlgo,
                expiryDate: metadata.expiryDate,
                keyFamily: family,
                privateKeyCustodyKind: .appleSecureEnclavePrivateOperations
            )
            try catalogStore.storeNewIdentity(identity)
            didStore(identity.fingerprint)
            if let afterIdentityCommitCheckpoint {
                try await afterIdentityCommitCheckpoint()
            }
            try Task.checkCancellation()
            try invalidationGate.checkValid(token)
            return identity
        }
    }

    private struct AuthorizedPair {
        let pair: LoadedCustodyHandlePair
        let context: LAContext
    }

    /// One approval covers both enclave key creations: the enclave prompts on
    /// the session's operation context when the first key is created.
    private func createAuthorizedHandlePair(tier: CustodyTier) async throws -> AuthorizedPair {
        try await withOperationPromptIfConfigured {
            let session: UnlockedSession
            do { session = try vault.requireSession() } catch { throw CypherAirError.fromStore(error) }
            let context = session.operationContext(
                reason: String(localized: "keygen.custody.auth.reason", defaultValue: "Authenticate to create your device-bound key.")
            )
            do {
                let created = try vault.custody.createPair(tier: tier, session: session, context: context)
                return AuthorizedPair(pair: try LoadedCustodyHandlePair(signing: created.signing, keyAgreement: created.keyAgreement), context: context)
            } catch {
                context.invalidate()
                throw error
            }
        }
    }

    private func rollback(pair: CustodyHandlePair, splitCustodyFingerprint: String?, storedFingerprint: String?) throws {
        if let storedFingerprint {
            try catalogStore.discardCommittedIdentity(fingerprint: storedFingerprint)
        }
        if let splitCustodyFingerprint {
            try vault.splitCustody.delete(fingerprint: splitCustodyFingerprint)
        }
        try vault.custody.deletePair(pair)
    }

    private func withOperationPromptIfConfigured<T>(operation: () async throws -> T) async throws -> T {
        guard let authenticationPromptCoordinator else {
            return try await operation()
        }
        return try await authenticationPromptCoordinator.withOperationPrompt {
            try await operation()
        }
    }
}
