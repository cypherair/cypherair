import Foundation

/// Additive message-signature verification result that preserves detailed per-signature outcomes
/// while retaining a legacy compatibility bridge for existing consumers.
struct DetailedSignatureVerification: Equatable {
    struct Entry: Equatable {
        enum Status: Equatable {
            case valid
            case unknownSigner
            case bad
            case expired
        }

        let status: Status
        let signerPrimaryFingerprint: String?
        let signerIdentity: SignatureVerification.SignerIdentity?
    }

    let legacyStatus: SignatureStatus
    let legacySignerFingerprint: String?
    let legacySignerContact: Contact?
    let legacySignerIdentity: SignatureVerification.SignerIdentity?
    let signatures: [Entry]

    var legacyVerification: SignatureVerification {
        SignatureVerification(
            status: legacyStatus,
            signerFingerprint: legacySignerFingerprint,
            signerContact: legacySignerContact,
            signerIdentity: legacySignerIdentity
        )
    }

    static func from(
        legacyStatus: SignatureStatus,
        legacySignerFingerprint: String?,
        signatures: [DetailedSignatureEntry],
        contacts: [Contact],
        ownKeys: [PGPKeyIdentity]
    ) -> DetailedSignatureVerification {
        let legacySignerContact = legacySignerFingerprint.flatMap { fingerprint in
            contacts.first(where: { $0.fingerprint == fingerprint })
        }
        let legacySignerIdentity = SignatureVerification.SignerIdentity.resolve(
            fingerprint: legacySignerFingerprint,
            contacts: contacts,
            ownKeys: ownKeys
        )

        return DetailedSignatureVerification(
            legacyStatus: legacyStatus,
            legacySignerFingerprint: legacySignerFingerprint,
            legacySignerContact: legacySignerContact,
            legacySignerIdentity: legacySignerIdentity,
            signatures: signatures.map { entry in
                Entry(
                    status: Entry.Status(from: entry.status),
                    signerPrimaryFingerprint: entry.signerPrimaryFingerprint,
                    signerIdentity: SignatureVerification.SignerIdentity.resolve(
                        fingerprint: entry.signerPrimaryFingerprint,
                        contacts: contacts,
                        ownKeys: ownKeys
                    )
                )
            }
        )
    }
}

private extension DetailedSignatureVerification.Entry.Status {
    init(from status: DetailedSignatureStatus) {
        switch status {
        case .valid:
            self = .valid
        case .unknownSigner:
            self = .unknownSigner
        case .bad:
            self = .bad
        case .expired:
            self = .expired
        }
    }
}
