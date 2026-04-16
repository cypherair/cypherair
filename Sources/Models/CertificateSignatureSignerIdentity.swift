import Foundation

struct CertificateSignatureSignerIdentity: Equatable {
    let source: CertificateSignerSource
    let displayName: String
    let secondaryText: String?
    let shortKeyId: String?
    let fingerprint: String
    let isVerifiedContact: Bool

    static func resolve(
        fingerprint: String?,
        contacts: [Contact],
        ownKeys: [PGPKeyIdentity]
    ) -> CertificateSignatureSignerIdentity? {
        guard let fingerprint else { return nil }

        if let contact = contacts.first(where: { $0.fingerprint == fingerprint }) {
            return CertificateSignatureSignerIdentity(
                source: .contact,
                displayName: contact.displayName,
                secondaryText: contact.email ?? contact.userId,
                shortKeyId: contact.shortKeyId,
                fingerprint: contact.fingerprint,
                isVerifiedContact: contact.isVerified
            )
        }

        if let ownKey = ownKeys.first(where: { $0.fingerprint == fingerprint }) {
            let displayName = ownKey.userId.map(IdentityPresentation.displayName(from:))
                ?? ownKey.shortKeyId
            return CertificateSignatureSignerIdentity(
                source: .ownKey,
                displayName: displayName,
                secondaryText: ownKey.userId,
                shortKeyId: ownKey.shortKeyId,
                fingerprint: ownKey.fingerprint,
                isVerifiedContact: true
            )
        }

        return CertificateSignatureSignerIdentity(
            source: .unknown,
            displayName: IdentityPresentation.shortKeyId(from: fingerprint),
            secondaryText: nil,
            shortKeyId: IdentityPresentation.shortKeyId(from: fingerprint),
            fingerprint: fingerprint,
            isVerifiedContact: false
        )
    }
}
