import Foundation

struct SecureEnclaveCustodyHandlePair: Equatable, Sendable {
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
        guard signing.reference.handleSetIdentifier == keyAgreement.reference.handleSetIdentifier else {
            throw SecureEnclaveCustodyHandleError.handlePublicKeyBindingMismatch(.keyAgreement)
        }
        guard signing.publicKeyX963 != keyAgreement.publicKeyX963 else {
            throw SecureEnclaveCustodyHandleError.handlePublicKeyBindingMismatch(.keyAgreement)
        }

        self.signing = signing
        self.keyAgreement = keyAgreement
    }

    var handleSetIdentifier: String {
        signing.reference.handleSetIdentifier
    }

    var references: [SecureEnclaveCustodyHandleReference] {
        [signing.reference, keyAgreement.reference]
    }
}
