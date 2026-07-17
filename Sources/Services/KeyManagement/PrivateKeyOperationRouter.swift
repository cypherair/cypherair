import Foundation
import LocalAuthentication

final class PrivateKeyOperationRouter: PrivateKeyOperationRouting, @unchecked Sendable {
    private let catalogStore: KeyCatalogStore
    private let resolver: PGPKeyCapabilityResolver
    private let publicBindingInspector: any SecureEnclaveCustodyPublicBindingInspecting
    private let handleStore: SecureEnclaveCustodyHandleStore
    private let compositeBindingInspector: (any SecureEnclaveCompositeBindingInspecting)?
    private let compositeHandleStore: SecureEnclaveCustodyHandleStore?
    private let compositeHighHandleStore: SecureEnclaveCustodyHandleStore?
    private let compositeClassicalComponentStore: SecureEnclaveCompositeClassicalComponentStore?
    private let custodyOperationAuthenticator: SecureEnclaveCustodyOperationAuthenticator?
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator?

    init(
        catalogStore: KeyCatalogStore,
        resolver: PGPKeyCapabilityResolver = PGPKeyCapabilityResolver(),
        publicBindingInspector: any SecureEnclaveCustodyPublicBindingInspecting,
        handleStore: SecureEnclaveCustodyHandleStore,
        compositeBindingInspector: (any SecureEnclaveCompositeBindingInspecting)? = nil,
        compositeHandleStore: SecureEnclaveCustodyHandleStore? = nil,
        compositeHighHandleStore: SecureEnclaveCustodyHandleStore? = nil,
        compositeClassicalComponentStore: SecureEnclaveCompositeClassicalComponentStore? = nil,
        custodyOperationAuthenticator: SecureEnclaveCustodyOperationAuthenticator?,
        authenticationPromptCoordinator: AuthenticationPromptCoordinator? = nil
    ) {
        self.catalogStore = catalogStore
        self.resolver = resolver
        self.publicBindingInspector = publicBindingInspector
        self.handleStore = handleStore
        self.compositeBindingInspector = compositeBindingInspector
        self.compositeHandleStore = compositeHandleStore
        self.compositeHighHandleStore = compositeHighHandleStore
        self.compositeClassicalComponentStore = compositeClassicalComponentStore
        self.custodyOperationAuthenticator = custodyOperationAuthenticator
        self.authenticationPromptCoordinator = authenticationPromptCoordinator
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
                throw SecureEnclaveCustodyAuthenticationErrorNormalizer.normalize(error)
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
        guard let tier = identity.keyFamily.deviceBoundCustodyTier else {
            return .blocked(.unsupported(.invalidFamilyCustody))
        }
        switch tier {
        case .classicalP256:
            return await routeSecureEnclaveClassicalOperation(
                request: request,
                identity: identity
            )
        case .postQuantum, .postQuantumHigh:
            return await routeSecureEnclaveCompositeOperation(
                request: request,
                identity: identity,
                tier: tier
            )
        }
    }

    private func routeSecureEnclaveClassicalOperation(
        request: PrivateKeyOperationRequest,
        identity: PGPKeyIdentity
    ) async -> PrivateKeyOperationRoute {
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
                signingPublicKeyRaw: inspection.signingPublicKeyX963,
                keyAgreementPublicKeyRaw: inspection.keyAgreementPublicKeyX963
            )
            let authorized = try await withOperationPromptIfConfigured {
                let authorization = try await makeOperationAuthorizationIfConfigured()
                do {
                    let signingHandle = try handleStore.loadHandle(
                        reference: pair.signing.reference,
                        expectedPublicKeyRaw: pair.signing.publicKeyRaw,
                        authenticationContext: authorization?.authenticationContext
                    )
                    return AuthorizedSigningHandle(
                        handle: signingHandle,
                        authorization: authorization
                    )
                } catch {
                    authorization?.end()
                    throw error
                }
            }
            return .secureEnclaveSigner(
                SecureEnclaveSignerRoute(
                    identity: identity,
                    operation: request.operation,
                    publicBindingInspection: inspection,
                    signingHandle: authorized.handle,
                    operationAuthorization: authorized.authorization
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

    private func routeSecureEnclaveKeyAgreementOperation(
        request: PrivateKeyOperationRequest,
        identity: PGPKeyIdentity,
        inspection: PGPSecureEnclaveCustodyPublicBindingInspection
    ) async -> PrivateKeyOperationRoute {
        do {
            let pair = try handleStore.locateHandlePair(
                signingPublicKeyRaw: inspection.signingPublicKeyX963,
                keyAgreementPublicKeyRaw: inspection.keyAgreementPublicKeyX963
            )
            let authorized = try await withOperationPromptIfConfigured {
                let authorization = try await makeOperationAuthorizationIfConfigured()
                do {
                    let keyAgreementHandle = try handleStore.loadHandle(
                        reference: pair.keyAgreement.reference,
                        expectedPublicKeyRaw: pair.keyAgreement.publicKeyRaw,
                        authenticationContext: authorization?.authenticationContext
                    )
                    return AuthorizedKeyAgreementHandle(
                        handle: keyAgreementHandle,
                        authorization: authorization
                    )
                } catch {
                    authorization?.end()
                    throw error
                }
            }
            return .secureEnclaveKeyAgreement(
                SecureEnclaveKeyAgreementRoute(
                    identity: identity,
                    operation: request.operation,
                    publicBindingInspection: inspection,
                    keyAgreementHandle: authorized.handle,
                    operationAuthorization: authorized.authorization
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

    private func routeSecureEnclaveCompositeOperation(
        request: PrivateKeyOperationRequest,
        identity: PGPKeyIdentity,
        tier: SecureEnclaveCustodyTier
    ) async -> PrivateKeyOperationRoute {
        guard !identity.publicKeyData.isEmpty else {
            return .blocked(.unavailable(.publicMaterialUnavailable))
        }
        // Each tier loads and shape-checks handles against its own parameter
        // set, so the store is selected by tier (exhaustive: a new tier fails to
        // compile until it is wired here).
        let tierHandleStore: SecureEnclaveCustodyHandleStore?
        switch tier {
        case .classicalP256:
            // The tier switch upstream routes classical tiers to the classical
            // path before this function; reaching here is a wiring bug. Fail
            // loudly in debug; the guard below still fails closed in release.
            assertionFailure("Classical P-256 tier routed to the composite path")
            tierHandleStore = nil
        case .postQuantum:
            tierHandleStore = compositeHandleStore
        case .postQuantumHigh:
            tierHandleStore = compositeHighHandleStore
        }
        guard let compositeBindingInspector,
              let compositeClassicalComponentStore,
              let compositeHandleStore = tierHandleStore else {
            return .blocked(.unavailable(.operationUnavailableByPolicy))
        }

        let inspection: PGPSecureEnclaveCompositeBindingInspection
        do {
            inspection = try compositeBindingInspector.inspectCompositeBindings(
                publicKeyData: identity.publicKeyData,
                tier: tier
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
            return await routeSecureEnclaveCompositeSigningOperation(
                request: request,
                identity: identity,
                inspection: inspection,
                tier: tier,
                compositeHandleStore: compositeHandleStore,
                compositeClassicalComponentStore: compositeClassicalComponentStore
            )
        case .keyAgreement:
            return await routeSecureEnclaveCompositeKeyAgreementOperation(
                request: request,
                identity: identity,
                inspection: inspection,
                tier: tier,
                compositeHandleStore: compositeHandleStore,
                compositeClassicalComponentStore: compositeClassicalComponentStore
            )
        }
    }

    private func routeSecureEnclaveCompositeSigningOperation(
        request: PrivateKeyOperationRequest,
        identity: PGPKeyIdentity,
        inspection: PGPSecureEnclaveCompositeBindingInspection,
        tier: SecureEnclaveCustodyTier,
        compositeHandleStore: SecureEnclaveCustodyHandleStore,
        compositeClassicalComponentStore: SecureEnclaveCompositeClassicalComponentStore
    ) async -> PrivateKeyOperationRoute {
        do {
            // Locate (non-prompting) BEFORE pre-authenticating, load AFTER:
            // a missing/mismatched handle blocks without a biometric sheet, and
            // the authenticated context covers exactly one handle load plus the
            // classical component unwrap of the same identity.
            let pair = try compositeHandleStore.locateHandlePair(
                signingPublicKeyRaw: inspection.signingComponentPublicKey,
                keyAgreementPublicKeyRaw: inspection.keyAgreementComponentPublicKey
            )
            let authorized = try await withOperationPromptIfConfigured {
                let authorization = try await makeOperationAuthorizationIfConfigured()
                do {
                    let signingHandle = try compositeHandleStore.loadHandle(
                        reference: pair.signing.reference,
                        expectedPublicKeyRaw: pair.signing.publicKeyRaw,
                        authenticationContext: authorization?.authenticationContext
                    )
                    let classicalComponent = try compositeClassicalComponentStore.load(
                        fingerprint: identity.fingerprint,
                        authenticationContext: authorization?.authenticationContext,
                        tier: tier
                    )
                    return AuthorizedCompositeHandle(
                        handle: signingHandle,
                        classicalComponent: classicalComponent,
                        authorization: authorization
                    )
                } catch {
                    authorization?.end()
                    throw error
                }
            }
            return .secureEnclaveCompositeSigner(
                SecureEnclaveCompositeSignerRoute(
                    identity: identity,
                    operation: request.operation,
                    compositeBindingInspection: inspection,
                    signingHandle: authorized.handle,
                    classicalComponent: authorized.classicalComponent,
                    operationAuthorization: authorized.authorization
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

    private func routeSecureEnclaveCompositeKeyAgreementOperation(
        request: PrivateKeyOperationRequest,
        identity: PGPKeyIdentity,
        inspection: PGPSecureEnclaveCompositeBindingInspection,
        tier: SecureEnclaveCustodyTier,
        compositeHandleStore: SecureEnclaveCustodyHandleStore,
        compositeClassicalComponentStore: SecureEnclaveCompositeClassicalComponentStore
    ) async -> PrivateKeyOperationRoute {
        do {
            let pair = try compositeHandleStore.locateHandlePair(
                signingPublicKeyRaw: inspection.signingComponentPublicKey,
                keyAgreementPublicKeyRaw: inspection.keyAgreementComponentPublicKey
            )
            let authorized = try await withOperationPromptIfConfigured {
                let authorization = try await makeOperationAuthorizationIfConfigured()
                do {
                    let keyAgreementHandle = try compositeHandleStore.loadHandle(
                        reference: pair.keyAgreement.reference,
                        expectedPublicKeyRaw: pair.keyAgreement.publicKeyRaw,
                        authenticationContext: authorization?.authenticationContext
                    )
                    let classicalComponent = try compositeClassicalComponentStore.load(
                        fingerprint: identity.fingerprint,
                        authenticationContext: authorization?.authenticationContext,
                        tier: tier
                    )
                    return AuthorizedCompositeHandle(
                        handle: keyAgreementHandle,
                        classicalComponent: classicalComponent,
                        authorization: authorization
                    )
                } catch {
                    authorization?.end()
                    throw error
                }
            }
            return .secureEnclaveCompositeKeyAgreement(
                SecureEnclaveCompositeKeyAgreementRoute(
                    identity: identity,
                    compositeBindingInspection: inspection,
                    keyAgreementHandle: authorized.handle,
                    classicalComponent: authorized.classicalComponent,
                    operationAuthorization: authorized.authorization
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

    private func makeOperationAuthorizationIfConfigured() async throws -> SecureEnclaveCustodyOperationAuthorization? {
        guard let custodyOperationAuthenticator else {
            return nil
        }
        do {
            let authenticationContext = try await custodyOperationAuthenticator(
                String(
                    localized: "keyoperation.custody.auth.reason",
                    defaultValue: "Authenticate to use your device-bound key."
                )
            )
            return SecureEnclaveCustodyOperationAuthorization(
                authenticationContext: authenticationContext
            )
        } catch {
            throw SecureEnclaveCustodyAuthenticationErrorNormalizer.normalize(error)
        }
    }

    private func withOperationPromptIfConfigured<T>(
        operation: () async throws -> T
    ) async throws -> T {
        guard let authenticationPromptCoordinator else {
            return try await operation()
        }
        return try await authenticationPromptCoordinator.withOperationPrompt {
            try await operation()
        }
    }
}

private struct AuthorizedSigningHandle {
    let handle: SecureEnclaveCustodyLoadedHandle
    let authorization: SecureEnclaveCustodyOperationAuthorization?
}

private struct AuthorizedCompositeHandle {
    let handle: SecureEnclaveCustodyLoadedHandle
    let classicalComponent: SecureEnclaveCompositeClassicalComponentStore.ClassicalComponent
    let authorization: SecureEnclaveCustodyOperationAuthorization?
}

private struct AuthorizedKeyAgreementHandle {
    let handle: SecureEnclaveCustodyLoadedHandle
    let authorization: SecureEnclaveCustodyOperationAuthorization?
}
