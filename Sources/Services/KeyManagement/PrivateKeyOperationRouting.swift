import Foundation

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
}

enum PrivateKeyOperationRoute {
    case softwareSecretCertificate(SoftwareSecretCertificateRoute)
    case secureEnclaveSigner(SecureEnclaveSignerRoute)
    case blocked(PGPKeyOperationResolution)
}

protocol PrivateKeyOperationRouting {
    func route(for request: PrivateKeyOperationRequest) -> PrivateKeyOperationRoute
}
