import Foundation

/// The two public bindings of one device-bound custody identity.
struct SecureEnclaveCustodyHandlePair: Hashable, Sendable {
    let signing: SecureEnclaveCustodyHandlePublicBinding
    let keyAgreement: SecureEnclaveCustodyHandlePublicBinding

    init(
        signing: SecureEnclaveCustodyHandlePublicBinding,
        keyAgreement: SecureEnclaveCustodyHandlePublicBinding
    ) throws {
        guard signing.role == .signing else {
            throw SecureEnclaveCustodyHandleError.privateOperationRoleMismatch(
                expected: .signing,
                actual: signing.role
            )
        }
        guard keyAgreement.role == .keyAgreement else {
            throw SecureEnclaveCustodyHandleError.privateOperationRoleMismatch(
                expected: .keyAgreement,
                actual: keyAgreement.role
            )
        }
        guard signing.reference.handleSetIdentifier == keyAgreement.reference.handleSetIdentifier,
              signing.reference.tier == keyAgreement.reference.tier else {
            throw SecureEnclaveCustodyHandleError.handlePublicKeyBindingMismatch(.keyAgreement)
        }
        guard signing.publicKeyRaw != keyAgreement.publicKeyRaw else {
            throw SecureEnclaveCustodyHandleError.handlePublicKeyBindingMismatch(.keyAgreement)
        }

        self.signing = signing
        self.keyAgreement = keyAgreement
    }

    var handleSetIdentifier: String {
        signing.reference.handleSetIdentifier
    }

    var tier: SecureEnclaveCustodyTier {
        signing.reference.tier
    }

    var references: [SecureEnclaveCustodyHandleReference] {
        [signing.reference, keyAgreement.reference]
    }
}
