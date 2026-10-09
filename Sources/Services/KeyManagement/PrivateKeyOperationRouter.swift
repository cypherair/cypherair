import Foundation
import LocalAuthentication
import Sealing
import Stores
import Vault

/// Decides how one private operation runs: software certificate, or one of the
/// enclave custody routes. Custody routes locate handles by public binding
/// without a prompt, then take one approval that covers every enclave load of
/// the operation, with the identity credential presented by the stores.
final class PrivateKeyOperationRouter: PrivateKeyOperationRouting, @unchecked Sendable {
    private let catalogStore: KeyCatalogStore
    private let resolver: PGPKeyCapabilityResolver
    private let vault: AppVault
    private let publicBindingInspector: any SecureEnclaveCustodyPublicBindingInspecting
    private let compositeBindingInspector: (any SecureEnclaveCompositeBindingInspecting)?
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator?

    init(
        catalogStore: KeyCatalogStore,
        resolver: PGPKeyCapabilityResolver = PGPKeyCapabilityResolver(),
        vault: AppVault,
        publicBindingInspector: any SecureEnclaveCustodyPublicBindingInspecting,
        compositeBindingInspector: (any SecureEnclaveCompositeBindingInspecting)? = nil,
        authenticationPromptCoordinator: AuthenticationPromptCoordinator? = nil
    ) {
        self.catalogStore = catalogStore
        self.resolver = resolver
        self.vault = vault
        self.publicBindingInspector = publicBindingInspector
        self.compositeBindingInspector = compositeBindingInspector
        self.authenticationPromptCoordinator = authenticationPromptCoordinator
    }

    /// One biometric system-sheet evaluation whose context then covers the
    /// operation's enclave loads. Biometrics only: device-bound keys never
    /// accept the passcode.
    func route(for request: PrivateKeyOperationRequest) async -> PrivateKeyOperationRoute {
        guard let identity = catalogStore.identity(for: request.fingerprint) else {
            return .blocked(.unavailable(.metadataAssociationMismatch))
        }
        let resolution = resolver.resolution(for: request.operation.keyOperationKind, identity: identity)
        guard resolution.support == .supported else {
            return .blocked(resolution)
        }
        switch identity.privateKeyCustodyKind {
        case .softwareSecretCertificate:
            return .softwareSecretCertificate(SoftwareSecretCertificateRoute(identity: identity, operation: request.operation))
        case .appleSecureEnclavePrivateOperations:
            guard let tier = identity.keyFamily.deviceBoundCustodyTier else {
                return .blocked(.unsupported(.invalidFamilyCustody))
            }
            guard !identity.publicKeyData.isEmpty else {
                return .blocked(.unavailable(.publicMaterialUnavailable))
            }
            switch tier {
            case .classicalP256:
                return await routeClassical(request: request, identity: identity)
            case .postQuantum, .postQuantumHigh:
                return await routeComposite(request: request, identity: identity, tier: tier)
            }
        }
    }

    private func routeClassical(request: PrivateKeyOperationRequest, identity: PGPKeyIdentity) async -> PrivateKeyOperationRoute {
        let inspection: PGPSecureEnclaveCustodyPublicBindingInspection
        do {
            inspection = try publicBindingInspector.inspectPublicBindings(publicKeyData: identity.publicKeyData)
        } catch {
            return .blocked(.unavailable(PGPKeyOperationFailureMapper.publicCertificateAssociationCategory(for: error)))
        }
        guard inspection.fingerprint.caseInsensitiveCompare(identity.fingerprint) == .orderedSame,
              inspection.keyVersion == identity.keyVersion else {
            return .blocked(.unavailable(.metadataAssociationMismatch))
        }
        do {
            let pair = try vault.custody.locatePair(tier: .classicalP256, signingPublicKeyRaw: inspection.signingPublicKeyX963, keyAgreementPublicKeyRaw: inspection.keyAgreementPublicKeyX963)
            let binding = request.operation.requiredRole == .signing ? pair.signing : pair.keyAgreement
            let authorized = try await withOperationPromptIfConfigured {
                let session = try vault.requireSession()
                let authorization = makeOperationAuthorization(session: session)
                do {
                    let handle = try vault.custody.loadHandle(reference: binding.reference, expectedPublicKeyRaw: binding.publicKeyRaw, session: session, context: authorization.authenticationContext)
                    return (handle, authorization)
                } catch {
                    authorization.end()
                    throw error
                }
            }
            switch request.operation.requiredRole {
            case .signing:
                return .secureEnclaveSigner(SecureEnclaveSignerRoute(identity: identity, operation: request.operation, publicBindingInspection: inspection, signingHandle: authorized.0, operationAuthorization: authorized.1))
            case .keyAgreement:
                return .secureEnclaveKeyAgreement(SecureEnclaveKeyAgreementRoute(identity: identity, operation: request.operation, publicBindingInspection: inspection, keyAgreementHandle: authorized.0, operationAuthorization: authorized.1))
            }
        } catch {
            return .blocked(.unavailable(PGPKeyOperationFailureMapper.category(for: error, fallback: .privateHandleInaccessible)))
        }
    }

    private func routeComposite(request: PrivateKeyOperationRequest, identity: PGPKeyIdentity, tier: CustodyTier) async -> PrivateKeyOperationRoute {
        guard let compositeBindingInspector else {
            return .blocked(.unavailable(.operationUnavailableByPolicy))
        }
        let inspection: PGPSecureEnclaveCompositeBindingInspection
        do {
            inspection = try compositeBindingInspector.inspectCompositeBindings(publicKeyData: identity.publicKeyData, tier: tier)
        } catch {
            return .blocked(.unavailable(PGPKeyOperationFailureMapper.publicCertificateAssociationCategory(for: error)))
        }
        guard inspection.fingerprint.caseInsensitiveCompare(identity.fingerprint) == .orderedSame,
              inspection.keyVersion == identity.keyVersion else {
            return .blocked(.unavailable(.metadataAssociationMismatch))
        }
        do {
            let pair = try vault.custody.locatePair(tier: tier, signingPublicKeyRaw: inspection.signingComponentPublicKey, keyAgreementPublicKeyRaw: inspection.keyAgreementComponentPublicKey)
            let binding = request.operation.requiredRole == .signing ? pair.signing : pair.keyAgreement
            let authorized = try await withOperationPromptIfConfigured {
                let session = try vault.requireSession()
                let authorization = makeOperationAuthorization(session: session)
                do {
                    let handle = try vault.custody.loadHandle(reference: binding.reference, expectedPublicKeyRaw: binding.publicKeyRaw, session: session, context: authorization.authenticationContext)
                    let opened = try vault.splitCustody.open(fingerprint: identity.fingerprint, session: session, context: authorization.authenticationContext)
                    let classical = try SplitCustodyClassicalComponent(concatenated: opened, tier: tier)
                    return (handle, classical, authorization)
                } catch {
                    authorization.end()
                    throw error
                }
            }
            switch request.operation.requiredRole {
            case .signing:
                return .secureEnclaveCompositeSigner(SecureEnclaveCompositeSignerRoute(identity: identity, operation: request.operation, compositeBindingInspection: inspection, signingHandle: authorized.0, classicalComponent: authorized.1, operationAuthorization: authorized.2))
            case .keyAgreement:
                return .secureEnclaveCompositeKeyAgreement(SecureEnclaveCompositeKeyAgreementRoute(identity: identity, compositeBindingInspection: inspection, keyAgreementHandle: authorized.0, classicalComponent: authorized.1, operationAuthorization: authorized.2))
            }
        } catch {
            return .blocked(.unavailable(PGPKeyOperationFailureMapper.category(for: error, fallback: .privateHandleInaccessible)))
        }
    }

    private func makeOperationAuthorization(session: UnlockedSession) -> SecureEnclaveCustodyOperationAuthorization {
        SecureEnclaveCustodyOperationAuthorization(
            authenticationContext: session.operationContext(
                reason: String(localized: "keyoperation.custody.auth.reason", defaultValue: "Authenticate to use your device-bound key.")
            )
        )
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
