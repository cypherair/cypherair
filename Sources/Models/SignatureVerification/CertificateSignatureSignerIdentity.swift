import Foundation

struct CertificateSignatureSignerIdentity: Equatable {
    let source: CertificateSignerSource
    let displayName: String
    let secondaryText: String?
    let fingerprint: String
    let isVerifiedContact: Bool

    static func resolve(
        fingerprint: String?,
        contactKeys: [ContactKeyRecord],
        ownKeys: [PGPKeyIdentity]
    ) -> CertificateSignatureSignerIdentity? {
        guard let fingerprint else { return nil }

        if let contactKey = contactKeys.first(where: { $0.fingerprint == fingerprint }) {
            return CertificateSignatureSignerIdentity(
                source: .contact,
                displayName: contactKey.displayName,
                secondaryText: contactKey.email ?? contactKey.primaryUserId,
                fingerprint: contactKey.fingerprint,
                isVerifiedContact: contactKey.manualVerificationState.isVerified
            )
        }

        if let ownKey = ownKeys.first(where: { $0.fingerprint == fingerprint }) {
            let displayName = IdentityPresentation.parsedDisplayName(from: ownKey.userId)
                ?? ownKey.shortKeyId
            return CertificateSignatureSignerIdentity(
                source: .ownKey,
                displayName: displayName,
                secondaryText: ownKey.userId,
                fingerprint: ownKey.fingerprint,
                isVerifiedContact: true
            )
        }

        return CertificateSignatureSignerIdentity(
            source: .unknown,
            displayName: IdentityPresentation.shortKeyId(from: fingerprint),
            secondaryText: nil,
            fingerprint: fingerprint,
            isVerifiedContact: false
        )
    }
}
