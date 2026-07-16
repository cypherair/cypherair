import Foundation
import LocalAuthentication

/// Produces one authenticated `LAContext` per Secure Enclave custody private
/// operation. The router keeps the system sheet and immediately authorized
/// handle load inside the same short operation-prompt window.
typealias SecureEnclaveCustodyOperationAuthenticator = (String) async throws -> LAContext

/// Pre-authenticated, operation-confined authorization for ONE Secure Enclave
/// custody private operation. Produced only by the router/generation service;
/// ended exactly once by the operation consumer's defer (end() is idempotent).
final class SecureEnclaveCustodyOperationAuthorization {
    let authenticationContext: LAContext

    init(authenticationContext: LAContext) {
        self.authenticationContext = authenticationContext
    }

    func end() {
        authenticationContext.invalidate()
    }
}

struct PrivateKeyOperationRequest: Equatable, Sendable {
    let fingerprint: String
    let operation: PGPPrivateOperationKind
}

/// The Device-Bound Post-Quantum dependencies the router needs to produce
/// composite routes. Wired once at the composition root; nil leaves the
/// composite branch blocked (`operationUnavailableByPolicy`). One binding
/// inspector and classical component store serve both tiers (the inspector
/// dispatches on the tier argument; the classical store on the tier of the
/// component secrets); each tier has its own enclave handle store so a handle
/// load validates the shape against the correct parameter set.
struct CompositeCustodyRouterContext {
    let bindingInspector: any SecureEnclaveCompositeBindingInspecting
    let handleStore: SecureEnclaveCustodyHandleStore
    let highHandleStore: SecureEnclaveCustodyHandleStore
    let classicalComponentStore: SecureEnclaveCompositeClassicalComponentStore
}

struct SoftwareSecretCertificateRoute {
    let identity: PGPKeyIdentity
    let operation: PGPPrivateOperationKind
}

struct SecureEnclaveSignerRoute {
    let identity: PGPKeyIdentity
    let operation: PGPPrivateOperationKind
    let publicBindingInspection: PGPSecureEnclaveCustodyPublicBindingInspection
    let signingHandle: SecureEnclaveCustodyLoadedHandle
    let operationAuthorization: SecureEnclaveCustodyOperationAuthorization?

    // Deliberate nil default: route values are router-produced data, and the
    // authorization exists only when the router pre-authenticated. Fixtures
    // without one stay source-compatible.
    init(
        identity: PGPKeyIdentity,
        operation: PGPPrivateOperationKind,
        publicBindingInspection: PGPSecureEnclaveCustodyPublicBindingInspection,
        signingHandle: SecureEnclaveCustodyLoadedHandle,
        operationAuthorization: SecureEnclaveCustodyOperationAuthorization? = nil
    ) {
        self.identity = identity
        self.operation = operation
        self.publicBindingInspection = publicBindingInspection
        self.signingHandle = signingHandle
        self.operationAuthorization = operationAuthorization
    }
}

struct SecureEnclaveKeyAgreementRoute {
    let identity: PGPKeyIdentity
    let operation: PGPPrivateOperationKind
    let publicBindingInspection: PGPSecureEnclaveCustodyPublicBindingInspection
    let keyAgreementHandle: SecureEnclaveCustodyLoadedHandle
    let operationAuthorization: SecureEnclaveCustodyOperationAuthorization?

    // Deliberate nil default: see SecureEnclaveSignerRoute.
    init(
        identity: PGPKeyIdentity,
        operation: PGPPrivateOperationKind,
        publicBindingInspection: PGPSecureEnclaveCustodyPublicBindingInspection,
        keyAgreementHandle: SecureEnclaveCustodyLoadedHandle,
        operationAuthorization: SecureEnclaveCustodyOperationAuthorization? = nil
    ) {
        self.identity = identity
        self.operation = operation
        self.publicBindingInspection = publicBindingInspection
        self.keyAgreementHandle = keyAgreementHandle
        self.operationAuthorization = operationAuthorization
    }
}

/// Device-Bound Post-Quantum split-custody signing route: the enclave-resident
/// ML-DSA-65 signing handle plus the unwrapped Ed25519 classical component the
/// engine needs for the same signature. The classical component's shared buffer
/// is zeroized when the operation window ends.
struct SecureEnclaveCompositeSignerRoute {
    let identity: PGPKeyIdentity
    let operation: PGPPrivateOperationKind
    let compositeBindingInspection: PGPSecureEnclaveCompositeBindingInspection
    let signingHandle: SecureEnclaveCustodyLoadedHandle
    let classicalComponent: SecureEnclaveCompositeClassicalComponentStore.ClassicalComponent
    let operationAuthorization: SecureEnclaveCustodyOperationAuthorization?

    init(
        identity: PGPKeyIdentity,
        operation: PGPPrivateOperationKind,
        compositeBindingInspection: PGPSecureEnclaveCompositeBindingInspection,
        signingHandle: SecureEnclaveCustodyLoadedHandle,
        classicalComponent: SecureEnclaveCompositeClassicalComponentStore.ClassicalComponent,
        operationAuthorization: SecureEnclaveCustodyOperationAuthorization? = nil
    ) {
        self.identity = identity
        self.operation = operation
        self.compositeBindingInspection = compositeBindingInspection
        self.signingHandle = signingHandle
        self.classicalComponent = classicalComponent
        self.operationAuthorization = operationAuthorization
    }
}

/// Device-Bound Post-Quantum split-custody key-agreement route: the
/// enclave-resident ML-KEM-768 handle plus the unwrapped X25519 classical
/// component. The classical component's shared buffer is zeroized when the
/// operation window ends.
struct SecureEnclaveCompositeKeyAgreementRoute {
    let identity: PGPKeyIdentity
    let compositeBindingInspection: PGPSecureEnclaveCompositeBindingInspection
    let keyAgreementHandle: SecureEnclaveCustodyLoadedHandle
    let classicalComponent: SecureEnclaveCompositeClassicalComponentStore.ClassicalComponent
    let operationAuthorization: SecureEnclaveCustodyOperationAuthorization?

    init(
        identity: PGPKeyIdentity,
        compositeBindingInspection: PGPSecureEnclaveCompositeBindingInspection,
        keyAgreementHandle: SecureEnclaveCustodyLoadedHandle,
        classicalComponent: SecureEnclaveCompositeClassicalComponentStore.ClassicalComponent,
        operationAuthorization: SecureEnclaveCustodyOperationAuthorization? = nil
    ) {
        self.identity = identity
        self.compositeBindingInspection = compositeBindingInspection
        self.keyAgreementHandle = keyAgreementHandle
        self.classicalComponent = classicalComponent
        self.operationAuthorization = operationAuthorization
    }
}

enum PrivateKeyOperationRoute {
    case softwareSecretCertificate(SoftwareSecretCertificateRoute)
    case secureEnclaveSigner(SecureEnclaveSignerRoute)
    case secureEnclaveKeyAgreement(SecureEnclaveKeyAgreementRoute)
    case secureEnclaveCompositeSigner(SecureEnclaveCompositeSignerRoute)
    case secureEnclaveCompositeKeyAgreement(SecureEnclaveCompositeKeyAgreementRoute)
    case blocked(PGPKeyOperationResolution)
}

extension PrivateKeyOperationRoute {
    /// Call from `defer` immediately after obtaining a route. Ends the
    /// operation-prompt authorization and zeroizes any unwrapped classical
    /// component secret carried by the route.
    func endAuthorizedOperation() {
        switch self {
        case .secureEnclaveSigner(let route):
            route.operationAuthorization?.end()
        case .secureEnclaveKeyAgreement(let route):
            route.operationAuthorization?.end()
        case .secureEnclaveCompositeSigner(let route):
            route.classicalComponent.zeroize()
            route.operationAuthorization?.end()
        case .secureEnclaveCompositeKeyAgreement(let route):
            route.classicalComponent.zeroize()
            route.operationAuthorization?.end()
        case .softwareSecretCertificate, .blocked:
            break
        }
    }
}

protocol PrivateKeyOperationRouting {
    func route(for request: PrivateKeyOperationRequest) async -> PrivateKeyOperationRoute
}
