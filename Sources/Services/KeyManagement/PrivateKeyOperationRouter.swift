import Foundation

final class PrivateKeyOperationRouter: PrivateKeyOperationRouting, @unchecked Sendable {
    private let catalogStore: KeyCatalogStore
    private let resolver: PGPKeyCapabilityResolver
    private let publicBindingInspector: any SecureEnclaveCustodyPublicBindingInspecting
    private let handleStore: SecureEnclaveCustodyHandleStore

    init(
        catalogStore: KeyCatalogStore,
        resolver: PGPKeyCapabilityResolver = PGPKeyCapabilityResolver(),
        publicBindingInspector: any SecureEnclaveCustodyPublicBindingInspecting,
        handleStore: SecureEnclaveCustodyHandleStore
    ) {
        self.catalogStore = catalogStore
        self.resolver = resolver
        self.publicBindingInspector = publicBindingInspector
        self.handleStore = handleStore
    }

    func route(for request: PrivateKeyOperationRequest) -> PrivateKeyOperationRoute {
        guard let identity = catalogStore.identity(for: request.fingerprint) else {
            return .blocked(.unavailable(.metadataAssociationMismatch))
        }

        let resolution = resolver.resolution(
            for: request.operation.keyOperationKind,
            identity: identity
        )
        guard resolution.support == .supported else {
            return .blocked(resolution)
        }

        switch identity.privateKeyCustodyKind {
        case .softwareSecretCertificate:
            return .softwareSecretCertificate(
                SoftwareSecretCertificateRoute(
                    identity: identity,
                    operation: request.operation
                )
            )
        case .appleSecureEnclavePrivateOperations:
            return routeSecureEnclaveOperation(
                request: request,
                identity: identity
            )
        }
    }

    private func routeSecureEnclaveOperation(
        request: PrivateKeyOperationRequest,
        identity: PGPKeyIdentity
    ) -> PrivateKeyOperationRoute {
        guard request.operation.requiredRole == .signing else {
            return .blocked(.notImplemented(.operationNotImplementedForCustody))
        }

        let configuration = identity.openPGPConfiguration
        guard configuration.algorithmSuite == .p256,
              configuration.keyVersion == identity.keyVersion else {
            return .blocked(.unsupported(.invalidConfigurationCustody))
        }
        guard identity.profile.keyVersion == identity.keyVersion else {
            return .blocked(.unavailable(.metadataAssociationMismatch))
        }
        guard !identity.publicKeyData.isEmpty else {
            return .blocked(.unavailable(.publicMaterialUnavailable))
        }

        let inspection: PGPSecureEnclaveCustodyPublicBindingInspection
        do {
            inspection = try publicBindingInspector.inspectPublicBindings(
                publicKeyData: identity.publicKeyData
            )
        } catch {
            return .blocked(.unavailable(
                PGPKeyOperationFailureMapper.publicCertificateAssociationCategory(for: error)
            ))
        }

        guard inspection.fingerprint.caseInsensitiveCompare(identity.fingerprint) == .orderedSame,
              inspection.keyVersion == identity.keyVersion else {
            return .blocked(.unavailable(.metadataAssociationMismatch))
        }

        do {
            let signingHandle = try handleStore.loadSigningHandle(
                signingPublicKeyX963: inspection.signingPublicKeyX963,
                keyAgreementPublicKeyX963: inspection.keyAgreementPublicKeyX963
            )
            return .secureEnclaveSigner(
                SecureEnclaveSignerRoute(
                    identity: identity,
                    operation: request.operation,
                    publicBindingInspection: inspection,
                    signingHandle: signingHandle
                )
            )
        } catch {
            return .blocked(.unavailable(
                PGPKeyOperationFailureMapper.category(
                    for: error,
                    fallback: .privateHandleInaccessible
                )
            ))
        }
    }
}
