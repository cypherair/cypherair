import Foundation
import LocalAuthentication
import Sealing
import Stores
import Vault

struct SecureEnclaveCustodyDeletionContext {
    let publicBindingInspector: any SecureEnclaveCustodyPublicBindingInspecting
    let compositeBindingInspector: (any SecureEnclaveCompositeBindingInspecting)?

    init(
        publicBindingInspector: any SecureEnclaveCustodyPublicBindingInspecting,
        compositeBindingInspector: (any SecureEnclaveCompositeBindingInspecting)? = nil
    ) {
        self.publicBindingInspector = publicBindingInspector
        self.compositeBindingInspector = compositeBindingInspector
    }
}

/// Expiry changes, deletion, and the default flag. A portable key's expiry
/// change is one approval: the unwrap prompts, the reseal is software and
/// replaces the row in place.
final class KeyMutationService {
    private let keyAdapter: PGPKeyOperationAdapter
    private let vault: AppVault
    private let catalogStore: KeyCatalogStore
    private let privateKeyAccessService: PrivateKeyAccessService
    private let secureEnclaveCustodyDeletionContext: SecureEnclaveCustodyDeletionContext?
    private var expiryMutationService: (any PrivateKeyExpiryMutationRouting)?

    init(
        keyAdapter: PGPKeyOperationAdapter,
        vault: AppVault,
        catalogStore: KeyCatalogStore,
        privateKeyAccessService: PrivateKeyAccessService,
        secureEnclaveCustodyDeletionContext: SecureEnclaveCustodyDeletionContext? = nil
    ) {
        self.keyAdapter = keyAdapter
        self.vault = vault
        self.catalogStore = catalogStore
        self.privateKeyAccessService = privateKeyAccessService
        self.secureEnclaveCustodyDeletionContext = secureEnclaveCustodyDeletionContext
    }

    func configureExpiryMutationService(_ service: any PrivateKeyExpiryMutationRouting) {
        expiryMutationService = service
    }

    func modifyExpiry(fingerprint: String, newValidity: PGPKeyValidity) async throws -> PGPKeyIdentity {
        let operationRoute = await routeModifyExpiry(fingerprint: fingerprint)
        defer { operationRoute.endAuthorizedOperation() }
        switch operationRoute {
        case .softwareSecretCertificate(let route):
            return try await modifySoftwareExpiry(route: route, newValidity: newValidity)
        case .secureEnclaveSigner(let route):
            guard let expiryMutationService else {
                throw CypherAirError.keyOperationUnavailable(category: .operationNotImplementedForCustody)
            }
            let result = try await expiryMutationService.modifySecureEnclaveExpiry(route: route, newValidity: newValidity)
            return try catalogStore.updateExpiry(metadata: result.metadata, publicKeyData: result.publicKeyData)
        case .secureEnclaveCompositeSigner(let route):
            guard let expiryMutationService else {
                throw CypherAirError.keyOperationUnavailable(category: .operationNotImplementedForCustody)
            }
            let result = try await expiryMutationService.modifySecureEnclaveCompositeExpiry(route: route, newValidity: newValidity)
            return try catalogStore.updateExpiry(metadata: result.metadata, publicKeyData: result.publicKeyData)
        case .secureEnclaveKeyAgreement, .secureEnclaveCompositeKeyAgreement:
            throw CypherAirError.keyOperationUnavailable(category: .privateOperationRoleMismatch)
        case .blocked(let resolution):
            throw CypherAirError.keyOperationUnavailable(category: resolution.failureCategory ?? .operationUnavailableByPolicy)
        }
    }

    private func modifySoftwareExpiry(route: SoftwareSecretCertificateRoute, newValidity: PGPKeyValidity) async throws -> PGPKeyIdentity {
        let fingerprint = route.identity.fingerprint
        let session: UnlockedSession
        do { session = try vault.requireSession() } catch { throw CypherAirError.fromStore(error) }
        let context = session.operationContext()
        defer { context.invalidate() }
        var secretKey = try await privateKeyAccessService.unwrapPrivateKey(fingerprint: fingerprint, authenticationContext: context)
        defer { secretKey.resetBytes(in: 0..<secretKey.count) }
        var result = try await keyAdapter.modifyExpiry(certData: secretKey, newValidity: newValidity)
        let mutatedCertificate = SensitiveBuffer(consuming: &result.certData)
        guard catalogStore.containsKey(fingerprint: fingerprint) else {
            throw CypherAirError.keyMetadataUnavailable
        }
        do {
            try vault.portableKeys.seal(mutatedCertificate, fingerprint: fingerprint, session: session)
        } catch {
            throw CypherAirError.fromStore(error)
        }
        return try catalogStore.updateExpiry(metadata: result.metadata, publicKeyData: result.publicKeyData)
    }

    private func routeModifyExpiry(fingerprint: String) async -> PrivateKeyOperationRoute {
        if let expiryMutationService {
            return await expiryMutationService.routeModifyExpiry(fingerprint: fingerprint)
        }
        guard let identity = catalogStore.identity(for: fingerprint) else {
            return .blocked(.unavailable(.metadataAssociationMismatch))
        }
        let resolution = PGPKeyCapabilityResolver().resolution(for: .modifyExpiry, identity: identity)
        guard resolution.support == .supported else {
            return .blocked(resolution)
        }
        switch identity.privateKeyCustodyKind {
        case .softwareSecretCertificate:
            return .softwareSecretCertificate(SoftwareSecretCertificateRoute(identity: identity, operation: .modifyExpiry))
        case .appleSecureEnclavePrivateOperations:
            return .blocked(.unavailable(.operationUnavailableByPolicy))
        }
    }

    func deleteKey(fingerprint: String) throws {
        var deletionErrors: [Error] = []
        if let identity = catalogStore.identity(for: fingerprint),
           identity.privateKeyCustodyKind == .appleSecureEnclavePrivateOperations {
            deletionErrors.append(contentsOf: deleteSecureEnclaveCustodyHandles(for: identity))
        }
        for store in [vault.portableKeys, vault.splitCustody] {
            do { try store.delete(fingerprint: fingerprint) } catch { deletionErrors.append(error) }
        }
        do { try catalogStore.removeKey(fingerprint: fingerprint) } catch { deletionErrors.append(error) }
        if let firstError = deletionErrors.first {
            throw CypherAirError.keychainError(
                "Partial key deletion: \(deletionErrors.count) item(s) could not be removed — \(firstError.localizedDescription)"
            )
        }
    }

    private func deleteSecureEnclaveCustodyHandles(for identity: PGPKeyIdentity) -> [Error] {
        guard let secureEnclaveCustodyDeletionContext else { return [] }
        guard let tier = identity.keyFamily.deviceBoundCustodyTier else {
            return [CypherAirError.keyOperationUnavailable(category: .invalidFamilyCustody)]
        }
        do {
            let (signing, keyAgreement): (Data, Data)
            let fingerprint: String
            let keyVersion: UInt8
            switch tier {
            case .classicalP256:
                let inspection = try secureEnclaveCustodyDeletionContext.publicBindingInspector.inspectPublicBindings(publicKeyData: identity.publicKeyData)
                (signing, keyAgreement) = (inspection.signingPublicKeyX963, inspection.keyAgreementPublicKeyX963)
                (fingerprint, keyVersion) = (inspection.fingerprint, inspection.keyVersion)
            case .postQuantum, .postQuantumHigh:
                guard let compositeBindingInspector = secureEnclaveCustodyDeletionContext.compositeBindingInspector else {
                    return [CypherAirError.keyOperationUnavailable(category: .operationUnavailableByPolicy)]
                }
                let inspection = try compositeBindingInspector.inspectCompositeBindings(publicKeyData: identity.publicKeyData, tier: tier)
                (signing, keyAgreement) = (inspection.signingComponentPublicKey, inspection.keyAgreementComponentPublicKey)
                (fingerprint, keyVersion) = (inspection.fingerprint, inspection.keyVersion)
            }
            guard fingerprint.caseInsensitiveCompare(identity.fingerprint) == .orderedSame, keyVersion == identity.keyVersion else {
                return [CypherAirError.keyOperationUnavailable(category: .metadataAssociationMismatch)]
            }
            let pair = try vault.custody.locatePair(tier: tier, signingPublicKeyRaw: signing, keyAgreementPublicKeyRaw: keyAgreement)
            try vault.custody.deletePair(pair)
            return []
        } catch let error as CustodyError where error.isMissing {
            return []
        } catch {
            return [error]
        }
    }

    func setDefaultKey(fingerprint: String) throws {
        try catalogStore.setDefaultKey(fingerprint: fingerprint)
    }
}
