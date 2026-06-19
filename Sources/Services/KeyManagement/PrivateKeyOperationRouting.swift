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

enum PrivateKeyOperationRoute {
    case softwareSecretCertificate(SoftwareSecretCertificateRoute)
    case secureEnclaveSigner(SecureEnclaveSignerRoute)
    case secureEnclaveKeyAgreement(SecureEnclaveKeyAgreementRoute)
    case blocked(PGPKeyOperationResolution)
}

extension PrivateKeyOperationRoute {
    /// Call from `defer` immediately after obtaining a route.
    func endAuthorizedOperation() {
        switch self {
        case .secureEnclaveSigner(let route):
            route.operationAuthorization?.end()
        case .secureEnclaveKeyAgreement(let route):
            route.operationAuthorization?.end()
        case .softwareSecretCertificate, .blocked:
            break
        }
    }
}

protocol PrivateKeyOperationRouting {
    func route(for request: PrivateKeyOperationRequest) async -> PrivateKeyOperationRoute
}
