import Foundation
import LocalAuthentication

final class PrivateKeyOperationRouter: PrivateKeyOperationRouting, @unchecked Sendable {
    private let catalogStore: KeyCatalogStore
    private let resolver: PGPKeyCapabilityResolver
    private let publicBindingInspector: any SecureEnclaveCustodyPublicBindingInspecting
    private let handleStore: SecureEnclaveCustodyHandleStore
    private let custodyOperationAuthenticator: SecureEnclaveCustodyOperationAuthenticator?

    init(
        catalogStore: KeyCatalogStore,
        resolver: PGPKeyCapabilityResolver = PGPKeyCapabilityResolver(),
        publicBindingInspector: any SecureEnclaveCustodyPublicBindingInspecting,
        handleStore: SecureEnclaveCustodyHandleStore,
        custodyOperationAuthenticator: SecureEnclaveCustodyOperationAuthenticator?
    ) {
        self.catalogStore = catalogStore
        self.resolver = resolver
        self.publicBindingInspector = publicBindingInspector
        self.handleStore = handleStore
        self.custodyOperationAuthenticator = custodyOperationAuthenticator
    }

    /// The production custody pre-authenticator: one fresh biometric
    /// system-sheet evaluation per Secure Enclave custody private operation.
    /// The returned context is interaction-disabled, so the subsequent
    /// keychain handle load and SE crypto consume the evaluated session
    /// instead of presenting further prompts.
    static var systemBiometricCustodyOperationAuthenticator: SecureEnclaveCustodyOperationAuthenticator {
        { reason in
            let context = LAContext()
            context.touchIDAuthenticationAllowableReuseDuration = 0
            context.localizedFallbackTitle = ""
            do {
                let success = try await context.evaluatePolicy(
                    .deviceOwnerAuthenticationWithBiometrics,
                    localizedReason: reason
                )
                guard success else {
                    throw CypherAirError.authenticationFailed
                }
                context.interactionNotAllowed = true
                return context
            } catch let error as CypherAirError {
                // Every failure path invalidates the never-returned context
                // exactly once; only a returned (authenticated) context is the
                // caller's to invalidate.
                context.invalidate()
                throw error
            } catch {
                context.invalidate()
                if let laError = error as? LAError {
                    switch laError.code {
                    case .userCancel, .appCancel, .systemCancel:
                        throw CypherAirError.operationCancelled
                    case .biometryNotAvailable, .biometryNotEnrolled:
                        throw CypherAirError.biometricsUnavailable
                    default:
                        throw CypherAirError.authenticationFailed
                    }
                }
                throw CypherAirError.authenticationFailed
            }
        }
    }

    func route(for request: PrivateKeyOperationRequest) async -> PrivateKeyOperationRoute {
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
            return await routeSecureEnclaveOperation(
                request: request,
                identity: identity
            )
        }
    }

    private func routeSecureEnclaveOperation(
        request: PrivateKeyOperationRequest,
        identity: PGPKeyIdentity
    ) async -> PrivateKeyOperationRoute {
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

        switch request.operation.requiredRole {
        case .signing:
            return await routeSecureEnclaveSigningOperation(
                request: request,
                identity: identity,
                inspection: inspection
            )
        case .keyAgreement:
            return await routeSecureEnclaveKeyAgreementOperation(
                request: request,
                identity: identity,
                inspection: inspection
            )
        }
    }

    private func routeSecureEnclaveSigningOperation(
        request: PrivateKeyOperationRequest,
        identity: PGPKeyIdentity,
        inspection: PGPSecureEnclaveCustodyPublicBindingInspection
    ) async -> PrivateKeyOperationRoute {
        do {
            // Locate (non-prompting) BEFORE pre-authenticating, load AFTER:
            // a missing/mismatched handle blocks without a biometric sheet,
            // and the authenticated context covers exactly one handle load.
            let pair = try handleStore.locateHandlePair(
                signingPublicKeyX963: inspection.signingPublicKeyX963,
                keyAgreementPublicKeyX963: inspection.keyAgreementPublicKeyX963
            )
            let authorization = try await makeOperationAuthorizationIfConfigured()
            do {
                let signingHandle = try handleStore.loadHandle(
                    reference: pair.signing.reference,
                    expectedPublicKeyX963: pair.signing.publicKeyX963,
                    authenticationContext: authorization?.authenticationContext
                )
                return .secureEnclaveSigner(
                    SecureEnclaveSignerRoute(
                        identity: identity,
                        operation: request.operation,
                        publicBindingInspection: inspection,
                        signingHandle: signingHandle,
                        operationAuthorization: authorization
                    )
                )
            } catch {
                authorization?.end()
                throw error
            }
        } catch {
            return .blocked(.unavailable(
                PGPKeyOperationFailureMapper.category(
                    for: error,
                    fallback: .privateHandleInaccessible
                )
            ))
        }
    }

    private func routeSecureEnclaveKeyAgreementOperation(
        request: PrivateKeyOperationRequest,
        identity: PGPKeyIdentity,
        inspection: PGPSecureEnclaveCustodyPublicBindingInspection
    ) async -> PrivateKeyOperationRoute {
        do {
            let pair = try handleStore.locateHandlePair(
                signingPublicKeyX963: inspection.signingPublicKeyX963,
                keyAgreementPublicKeyX963: inspection.keyAgreementPublicKeyX963
            )
            let authorization = try await makeOperationAuthorizationIfConfigured()
            do {
                let keyAgreementHandle = try handleStore.loadHandle(
                    reference: pair.keyAgreement.reference,
                    expectedPublicKeyX963: pair.keyAgreement.publicKeyX963,
                    authenticationContext: authorization?.authenticationContext
                )
                return .secureEnclaveKeyAgreement(
                    SecureEnclaveKeyAgreementRoute(
                        identity: identity,
                        operation: request.operation,
                        publicBindingInspection: inspection,
                        keyAgreementHandle: keyAgreementHandle,
                        operationAuthorization: authorization
                    )
                )
            } catch {
                authorization?.end()
                throw error
            }
        } catch {
            return .blocked(.unavailable(
                PGPKeyOperationFailureMapper.category(
                    for: error,
                    fallback: .privateHandleInaccessible
                )
            ))
        }
    }

    private func makeOperationAuthorizationIfConfigured() async throws -> SecureEnclaveCustodyOperationAuthorization? {
        guard let custodyOperationAuthenticator else {
            return nil
        }
        let authenticationContext = try await custodyOperationAuthenticator(
            String(
                localized: "keyoperation.custody.auth.reason",
                defaultValue: "Authenticate to use your device-bound key."
            )
        )
        return SecureEnclaveCustodyOperationAuthorization(
            authenticationContext: authenticationContext
        )
    }
}
