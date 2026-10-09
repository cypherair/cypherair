import Foundation
import LocalAuthentication
import Stores

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

struct CompositeCustodyRouterContext {
    let bindingInspector: any SecureEnclaveCompositeBindingInspecting
}

struct SoftwareSecretCertificateRoute {
    let identity: PGPKeyIdentity
    let operation: PGPPrivateOperationKind
}

struct SecureEnclaveSignerRoute {
    let identity: PGPKeyIdentity
    let operation: PGPPrivateOperationKind
    let publicBindingInspection: PGPSecureEnclaveCustodyPublicBindingInspection
    let signingHandle: LoadedCustodyHandle
    let operationAuthorization: SecureEnclaveCustodyOperationAuthorization?
}

struct SecureEnclaveKeyAgreementRoute {
    let identity: PGPKeyIdentity
    let operation: PGPPrivateOperationKind
    let publicBindingInspection: PGPSecureEnclaveCustodyPublicBindingInspection
    let keyAgreementHandle: LoadedCustodyHandle
    let operationAuthorization: SecureEnclaveCustodyOperationAuthorization?
}

struct SecureEnclaveCompositeSignerRoute {
    let identity: PGPKeyIdentity
    let operation: PGPPrivateOperationKind
    let compositeBindingInspection: PGPSecureEnclaveCompositeBindingInspection
    let signingHandle: LoadedCustodyHandle
    let classicalComponent: SplitCustodyClassicalComponent
    let operationAuthorization: SecureEnclaveCustodyOperationAuthorization?
}

struct SecureEnclaveCompositeKeyAgreementRoute {
    let identity: PGPKeyIdentity
    let compositeBindingInspection: PGPSecureEnclaveCompositeBindingInspection
    let keyAgreementHandle: LoadedCustodyHandle
    let classicalComponent: SplitCustodyClassicalComponent
    let operationAuthorization: SecureEnclaveCustodyOperationAuthorization?
}

enum PrivateKeyOperationRoute {
    case softwareSecretCertificate(SoftwareSecretCertificateRoute)
    case secureEnclaveSigner(SecureEnclaveSignerRoute)
    case secureEnclaveKeyAgreement(SecureEnclaveKeyAgreementRoute)
    case secureEnclaveCompositeSigner(SecureEnclaveCompositeSignerRoute)
    case secureEnclaveCompositeKeyAgreement(SecureEnclaveCompositeKeyAgreementRoute)
    case blocked(PGPKeyOperationResolution)

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
