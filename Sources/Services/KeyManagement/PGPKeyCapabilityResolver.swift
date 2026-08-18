import Foundation

/// Pure policy resolver for key-family operation support. Custody is a
/// property of the family, so the family alone determines which policy axis
/// answers.
struct PGPKeyCapabilityResolver: Sendable {
    struct Policy: Equatable, Sendable {
        var secureEnclaveGenerationSupport: PGPKeyOperationSupport
        var secureEnclaveSigningOperationSupport: PGPKeyOperationSupport
        var secureEnclaveKeyAgreementOperationSupport: PGPKeyOperationSupport

        /// Generation and the implemented private-operation classes are
        /// supported — the only production shape.
        static let production = Policy(
            secureEnclaveGenerationSupport: .supported,
            secureEnclaveSigningOperationSupport: .supported,
            secureEnclaveKeyAgreementOperationSupport: .supported
        )
    }

    private let policy: Policy

    init(policy: Policy = .production) {
        self.policy = policy
    }

    func support(
        for operation: PGPKeyOperationKind,
        identity: PGPKeyIdentity
    ) -> PGPKeyOperationSupport {
        resolution(
            for: operation,
            identity: identity
        ).support
    }

    func support(
        for operation: PGPKeyOperationKind,
        family: PGPKeyFamily
    ) -> PGPKeyOperationSupport {
        resolution(
            for: operation,
            family: family
        ).support
    }

    func resolution(
        for operation: PGPKeyOperationKind,
        identity: PGPKeyIdentity
    ) -> PGPKeyOperationResolution {
        resolution(
            for: operation,
            family: identity.keyFamily
        )
    }

    func resolution(
        for operation: PGPKeyOperationKind,
        family: PGPKeyFamily
    ) -> PGPKeyOperationResolution {
        switch family.custody {
        case .portable:
            return .supported
        case .deviceBound:
            return resolutionForSecureEnclaveCustody(operation: operation)
        }
    }

    private func resolutionForSecureEnclaveCustody(
        operation: PGPKeyOperationKind
    ) -> PGPKeyOperationResolution {
        switch operation {
        case .generate:
            return resolutionForPolicySupport(policy.secureEnclaveGenerationSupport)
        case .sign,
             .certify,
             .revoke,
             .modifyExpiry:
            return resolutionForPolicySupport(policy.secureEnclaveSigningOperationSupport)
        case .decrypt:
            return resolutionForPolicySupport(policy.secureEnclaveKeyAgreementOperationSupport)
        }
    }

    private func resolutionForPolicySupport(
        _ support: PGPKeyOperationSupport
    ) -> PGPKeyOperationResolution {
        switch support {
        case .supported:
            return .supported
        case .unsupported:
            return .unsupported(.operationUnsupportedForCustody)
        case .notImplemented:
            return .notImplemented(.operationNotImplementedForCustody)
        case .unavailable:
            return .unavailable(.operationUnavailableByPolicy)
        }
    }
}
