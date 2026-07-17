import Foundation
import LocalAuthentication

/// Generation path for Secure Enclave custody public-only keys (device-bound
/// families).
final class SecureEnclaveCustodyGenerationService: @unchecked Sendable {
    typealias GenerationCheckpoint = @Sendable () async throws -> Void

    private let certificateBuilder: any SecureEnclaveCustodyCertificateBuilding
    private let handleStore: SecureEnclaveCustodyHandleStore
    private let digestSigner: any SecureEnclaveCustodyDigestSigning
    private let compositeCertificateBuilder: (any SecureEnclaveCompositeCertificateBuilding)?
    private let compositeHandleStore: SecureEnclaveCustodyHandleStore?
    private let compositeHighHandleStore: SecureEnclaveCustodyHandleStore?
    private let compositeSigner: (any SecureEnclaveCompositeSigning)?
    private let compositeClassicalComponentStore: SecureEnclaveCompositeClassicalComponentStore?
    private let catalogStore: KeyCatalogStore
    private let resolver: PGPKeyCapabilityResolver
    private let invalidationGate: KeyProvisioningInvalidationGate
    private let commitCoordinator: KeyProvisioningCommitCoordinator
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator?
    private let custodyOperationAuthenticator: SecureEnclaveCustodyOperationAuthenticator?
    private let afterIdentityCommitCheckpoint: GenerationCheckpoint?

    init(
        certificateBuilder: any SecureEnclaveCustodyCertificateBuilding,
        handleStore: SecureEnclaveCustodyHandleStore,
        digestSigner: any SecureEnclaveCustodyDigestSigning,
        compositeCertificateBuilder: (any SecureEnclaveCompositeCertificateBuilding)? = nil,
        compositeHandleStore: SecureEnclaveCustodyHandleStore? = nil,
        compositeHighHandleStore: SecureEnclaveCustodyHandleStore? = nil,
        compositeSigner: (any SecureEnclaveCompositeSigning)? = nil,
        compositeClassicalComponentStore: SecureEnclaveCompositeClassicalComponentStore? = nil,
        catalogStore: KeyCatalogStore,
        resolver: PGPKeyCapabilityResolver,
        invalidationGate: KeyProvisioningInvalidationGate,
        commitCoordinator: KeyProvisioningCommitCoordinator,
        authenticationPromptCoordinator: AuthenticationPromptCoordinator? = nil,
        custodyOperationAuthenticator: SecureEnclaveCustodyOperationAuthenticator? = nil,
        afterIdentityCommitCheckpoint: GenerationCheckpoint? = nil
    ) {
        self.certificateBuilder = certificateBuilder
        self.handleStore = handleStore
        self.digestSigner = digestSigner
        self.compositeCertificateBuilder = compositeCertificateBuilder
        self.compositeHandleStore = compositeHandleStore
        self.compositeHighHandleStore = compositeHighHandleStore
        self.compositeSigner = compositeSigner
        self.compositeClassicalComponentStore = compositeClassicalComponentStore
        self.catalogStore = catalogStore
        self.resolver = resolver
        self.invalidationGate = invalidationGate
        self.commitCoordinator = commitCoordinator
        self.authenticationPromptCoordinator = authenticationPromptCoordinator
        self.custodyOperationAuthenticator = custodyOperationAuthenticator
        self.afterIdentityCommitCheckpoint = afterIdentityCommitCheckpoint
    }

    /// Only the custody authorization and immediately authorized handle-creation
    /// window is enrolled in an operation-prompt session. Certificate building
    /// and durable metadata commit stay outside that window so a genuine macOS
    /// away still locks immediately when grace period is 0.
    func generateKey(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        family: PGPKeyFamily,
        invalidationToken token: KeyProvisioningInvalidationGate.Token
    ) async throws -> PGPKeyIdentity {
        guard let tier = family.deviceBoundCustodyTier else {
            throw CypherAirError.invalidKeyData(
                reason: "Secure Enclave custody generation requires a device-bound family."
            )
        }
        switch tier {
        case .classicalP256:
            return try await performGenerateClassicalKey(
                name: name,
                email: email,
                expirySeconds: expirySeconds,
                family: family,
                invalidationToken: token
            )
        case .postQuantum, .postQuantumHigh:
            return try await performGenerateCompositeKey(
                name: name,
                email: email,
                expirySeconds: expirySeconds,
                family: family,
                tier: tier,
                invalidationToken: token
            )
        }
    }

    /// Classical (P-256) generation: create the two Secure Enclave keys under
    /// one authorized window, build the public-only v4/v6 certificate through
    /// the external P-256 signer, then commit the identity. Every failure path
    /// tears down the enclave keys and any committed identity.
    private func performGenerateClassicalKey(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        family: PGPKeyFamily,
        invalidationToken token: KeyProvisioningInvalidationGate.Token
    ) async throws -> PGPKeyIdentity {
        let resolution = resolver.resolution(
            for: .generate,
            family: family,
            custody: .appleSecureEnclavePrivateOperations
        )
        guard resolution.support == .supported else {
            throw CypherAirError.keyOperationUnavailable(
                category: resolution.failureCategory ?? .operationUnavailableByPolicy
            )
        }

        try Task.checkCancellation()
        try invalidationGate.checkValid(token)

        let authorizedPair = try await createAuthorizedHandlePair(handleStore: handleStore)
        let authorizedContext = authorizedPair.authenticationContext
        defer {
            authorizedContext?.invalidate()
        }

        let loadedPair = authorizedPair.loadedPair
        let handlePair = try SecureEnclaveCustodyHandlePair(
            signing: loadedPair.signing.binding,
            keyAgreement: loadedPair.keyAgreement.binding
        )
        var storedFingerprint: String?
        var didRollbackGeneratedState = false
        do {
            try Task.checkCancellation()
            try invalidationGate.checkValid(token)

            let generated = try await certificateBuilder.generatePublicCertificate(
                name: name,
                email: email,
                expirySeconds: expirySeconds,
                family: family,
                handlePair: loadedPair,
                digestSigner: digestSigner
            )
            try Task.checkCancellation()
            try invalidationGate.checkValid(token)

            return try await commitCoordinator.performCommit {
                do {
                    try Task.checkCancellation()
                    try invalidationGate.checkValid(token)
                    guard !catalogStore.containsKey(fingerprint: generated.metadata.fingerprint) else {
                        throw CypherAirError.duplicateKey
                    }

                    let identity = PGPKeyIdentity(
                        fingerprint: generated.metadata.fingerprint,
                        userId: generated.metadata.userId,
                        hasEncryptionSubkey: generated.metadata.hasEncryptionSubkey,
                        isRevoked: false,
                        isExpired: generated.metadata.isExpired,
                        isDefault: catalogStore.keys.isEmpty,
                        isBackedUp: false,
                        publicKeyData: generated.publicKeyData,
                        revocationCert: generated.revocationCert,
                        primaryAlgo: generated.metadata.primaryAlgo,
                        subkeyAlgo: generated.metadata.subkeyAlgo,
                        expiryDate: generated.metadata.expiryDate,
                        keyFamily: family,
                        privateKeyCustodyKind: .appleSecureEnclavePrivateOperations
                    )
                    try catalogStore.storeNewIdentity(identity)
                    storedFingerprint = identity.fingerprint
                    if let afterIdentityCommitCheckpoint {
                        try await afterIdentityCommitCheckpoint()
                    }
                    try Task.checkCancellation()
                    try invalidationGate.checkValid(token)
                    return identity
                } catch {
                    do {
                        didRollbackGeneratedState = true
                        try rollbackGeneratedClassicalState(
                            handlePair: handlePair,
                            storedFingerprint: storedFingerprint
                        )
                    } catch {
                        throw SecureEnclaveCustodyHandleError.cleanupOrRollbackFailed
                    }
                    throw error
                }
            }
        } catch {
            if !didRollbackGeneratedState {
                do {
                    try rollbackGeneratedClassicalState(
                        handlePair: handlePair,
                        storedFingerprint: storedFingerprint
                    )
                } catch {
                    throw SecureEnclaveCustodyHandleError.cleanupOrRollbackFailed
                }
            }
            throw error
        }
    }

    /// Device-Bound Post-Quantum split-custody generation: create the two
    /// Secure Enclave composite keys under one authorized window, build the
    /// certificate through the external ML-DSA signer (the Ed25519/X25519
    /// classical components are generated inside Rust), seal the returned
    /// classical component under the fixed-access envelope, then commit the
    /// identity. Every failure path tears down the enclave keys, the classical
    /// envelope, and any committed identity.
    private func performGenerateCompositeKey(
        name: String,
        email: String?,
        expirySeconds: UInt64?,
        family: PGPKeyFamily,
        tier: SecureEnclaveCustodyTier,
        invalidationToken token: KeyProvisioningInvalidationGate.Token
    ) async throws -> PGPKeyIdentity {
        // Each tier creates and shape-checks its handles against its own
        // parameter set, so the enclave handle store is selected by tier
        // (exhaustive: a new tier fails to compile until it is wired here).
        let tierHandleStore: SecureEnclaveCustodyHandleStore?
        switch tier {
        case .classicalP256:
            // generateKey dispatches classical tiers to the classical path
            // before this function; reaching here is a wiring bug. Fail loudly
            // in debug; the guard below still fails closed in release.
            assertionFailure("Classical P-256 tier routed to composite generation")
            tierHandleStore = nil
        case .postQuantum:
            tierHandleStore = compositeHandleStore
        case .postQuantumHigh:
            tierHandleStore = compositeHighHandleStore
        }
        guard let compositeCertificateBuilder,
              let compositeSigner,
              let compositeClassicalComponentStore,
              let compositeHandleStore = tierHandleStore else {
            throw CypherAirError.keyOperationUnavailable(category: .operationUnavailableByPolicy)
        }
        let resolution = resolver.resolution(
            for: .generate,
            family: family,
            custody: .appleSecureEnclavePrivateOperations
        )
        guard resolution.support == .supported else {
            throw CypherAirError.keyOperationUnavailable(
                category: resolution.failureCategory ?? .operationUnavailableByPolicy
            )
        }

        try Task.checkCancellation()
        try invalidationGate.checkValid(token)

        let authorizedPair = try await createAuthorizedHandlePair(
            handleStore: compositeHandleStore
        )
        let authorizedContext = authorizedPair.authenticationContext
        defer {
            authorizedContext?.invalidate()
        }

        let handlePair = authorizedPair.loadedPair
        var storedFingerprint: String?
        var classicalReceipt: KeyBundleWriteReceipt?
        var didRollbackGeneratedState = false
        do {
            try Task.checkCancellation()
            try invalidationGate.checkValid(token)

            var generated = try await compositeCertificateBuilder.generateCompositeCertificate(
                name: name,
                email: email,
                expirySeconds: expirySeconds,
                handlePair: handlePair,
                compositeSigner: compositeSigner
            )
            // Zeroize the raw classical component secrets on every exit from
            // this scope. `store` also zeroizes them (idempotent), but a
            // cancellation/invalidation throw between receipt and seal must not
            // free them intact. The commit closure below reads only public
            // metadata, so the secrets stay valid until it returns.
            defer {
                generated.classicalEddsaSecret.resetBytes(
                    in: 0..<generated.classicalEddsaSecret.count
                )
                generated.classicalEcdhSecret.resetBytes(
                    in: 0..<generated.classicalEcdhSecret.count
                )
            }
            try Task.checkCancellation()
            try invalidationGate.checkValid(token)

            // Seal the classical component before the durable identity commit
            // so a committed identity never exists without its component;
            // `store` zeroizes the secret buffers.
            classicalReceipt = try compositeClassicalComponentStore.store(
                fingerprint: generated.metadata.fingerprint,
                eddsaSecret: &generated.classicalEddsaSecret,
                ecdhSecret: &generated.classicalEcdhSecret,
                tier: tier
            )

            return try await commitCoordinator.performCommit {
                do {
                    try Task.checkCancellation()
                    try invalidationGate.checkValid(token)
                    guard !catalogStore.containsKey(fingerprint: generated.metadata.fingerprint) else {
                        throw CypherAirError.duplicateKey
                    }

                    let identity = PGPKeyIdentity(
                        fingerprint: generated.metadata.fingerprint,
                        userId: generated.metadata.userId,
                        hasEncryptionSubkey: generated.metadata.hasEncryptionSubkey,
                        isRevoked: false,
                        isExpired: generated.metadata.isExpired,
                        isDefault: catalogStore.keys.isEmpty,
                        isBackedUp: false,
                        publicKeyData: generated.publicKeyData,
                        revocationCert: generated.revocationCert,
                        primaryAlgo: generated.metadata.primaryAlgo,
                        subkeyAlgo: generated.metadata.subkeyAlgo,
                        expiryDate: generated.metadata.expiryDate,
                        keyFamily: family,
                        privateKeyCustodyKind: .appleSecureEnclavePrivateOperations
                    )
                    try catalogStore.storeNewIdentity(identity)
                    storedFingerprint = identity.fingerprint
                    if let afterIdentityCommitCheckpoint {
                        try await afterIdentityCommitCheckpoint()
                    }
                    try Task.checkCancellation()
                    try invalidationGate.checkValid(token)
                    return identity
                } catch {
                    do {
                        didRollbackGeneratedState = true
                        try rollbackGeneratedCompositeState(
                            compositeHandleStore: compositeHandleStore,
                            compositeClassicalComponentStore: compositeClassicalComponentStore,
                            loadedPair: handlePair,
                            classicalReceipt: classicalReceipt,
                            storedFingerprint: storedFingerprint
                        )
                    } catch {
                        throw SecureEnclaveCustodyHandleError.cleanupOrRollbackFailed
                    }
                    throw error
                }
            }
        } catch {
            if !didRollbackGeneratedState {
                do {
                    try rollbackGeneratedCompositeState(
                        compositeHandleStore: compositeHandleStore,
                        compositeClassicalComponentStore: compositeClassicalComponentStore,
                        loadedPair: handlePair,
                        classicalReceipt: classicalReceipt,
                        storedFingerprint: storedFingerprint
                    )
                } catch {
                    throw SecureEnclaveCustodyHandleError.cleanupOrRollbackFailed
                }
            }
            throw error
        }
    }

    private func createAuthorizedHandlePair(
        handleStore: SecureEnclaveCustodyHandleStore
    ) async throws -> AuthorizedCustodyGenerationHandlePair {
        try await withOperationPromptIfConfigured(
            source: "keyProvisioning.generateSecureEnclaveCustody.authorize"
        ) {
            var authorizedContext: LAContext?
            if let custodyOperationAuthenticator {
                do {
                    authorizedContext = try await custodyOperationAuthenticator(
                        String(
                            localized: "keygen.custody.auth.reason",
                            defaultValue: "Authenticate to create your device-bound key."
                        )
                    )
                } catch {
                    authorizedContext?.invalidate()
                    let normalized = SecureEnclaveCustodyAuthenticationErrorNormalizer.normalize(error)
                    throw CypherAirError.keyOperationUnavailable(
                        category: PGPKeyOperationFailureMapper.category(
                            for: normalized,
                            fallback: .localAuthenticationFailed
                        )
                    )
                }
            }

            do {
                let loadedPair = try handleStore.createLoadedHandlePair(
                    authenticationContext: authorizedContext
                )
                return AuthorizedCustodyGenerationHandlePair(
                    loadedPair: loadedPair,
                    authenticationContext: authorizedContext
                )
            } catch {
                authorizedContext?.invalidate()
                throw error
            }
        }
    }

    private func rollbackGeneratedClassicalState(
        handlePair: SecureEnclaveCustodyHandlePair,
        storedFingerprint: String?
    ) throws {
        if let storedFingerprint {
            try catalogStore.discardCommittedIdentity(fingerprint: storedFingerprint)
        }
        try handleStore.deleteHandlePair(handlePair)
    }

    private func rollbackGeneratedCompositeState(
        compositeHandleStore: SecureEnclaveCustodyHandleStore,
        compositeClassicalComponentStore: SecureEnclaveCompositeClassicalComponentStore,
        loadedPair: SecureEnclaveCustodyLoadedHandlePair,
        classicalReceipt: KeyBundleWriteReceipt?,
        storedFingerprint: String?
    ) throws {
        if let storedFingerprint {
            try catalogStore.discardCommittedIdentity(fingerprint: storedFingerprint)
        }
        if let classicalReceipt {
            compositeClassicalComponentStore.rollback(classicalReceipt)
        }
        let pair = try SecureEnclaveCustodyHandlePair(
            signing: loadedPair.signing.binding,
            keyAgreement: loadedPair.keyAgreement.binding
        )
        try compositeHandleStore.deleteHandlePair(pair)
    }

    private func withOperationPromptIfConfigured<T>(
        source: String,
        operation: () async throws -> T
    ) async throws -> T {
        guard let authenticationPromptCoordinator else {
            return try await operation()
        }
        return try await authenticationPromptCoordinator.withOperationPrompt(source: source) {
            try await operation()
        }
    }
}

private struct AuthorizedCustodyGenerationHandlePair {
    let loadedPair: SecureEnclaveCustodyLoadedHandlePair
    let authenticationContext: LAContext?
}
