import Foundation

/// When a contact's certifications count toward anything the app tells the user.
enum ContactVouchingPolicy {

    /// Whether certifications made by `signer` currently carry vouching weight.
    ///
    /// Provisional ruling for issue #956, pending the maintainer's confirmation:
    /// a certification that was validly made keeps its weight for as long as the
    /// signer stays verified and unrevoked. The signer's key *expiring* does not
    /// retroactively erase a vouch that was sound when it was made — expiry
    /// bounds what a key may do next, not what it already said. Revocation is a
    /// different act: the holder disowning the key, which withdraws everything it
    /// signed.
    ///
    /// Reversing the ruling means adding `&& !signer.isExpired` here and nowhere
    /// else: this predicate is the only expression of the policy in the app.
    static func carriesVouchingWeight(_ signer: ContactKeyRecord) -> Bool {
        signer.manualVerificationState.isVerified && !signer.isRevoked
    }
}

/// The one-hop web of vouching CypherAir is willing to assert, over the
/// certificates the user has already imported.
///
/// There is no discovery, no refresh and no server: a certification counts only
/// when its signer is a certificate already on the device, and only one hop —
/// a contact vouched for by a contact the user verified does not become a
/// voucher in turn.
///
/// Rebuilt from the snapshot on every projection rather than cached. That is
/// what makes withdrawing a verification take effect immediately: no stored
/// answer exists to go stale, so there is nothing to invalidate.
struct ContactCertificationTrustWeb {
    private let vouchersByTargetKeyId: [String: [ContactKeyVoucher]]

    init(
        keyRecords: [ContactKeyRecord],
        certificationArtifacts: [ContactCertificationArtifactReference]
    ) {
        let recordsByFingerprint = Dictionary(
            keyRecords.map { ($0.fingerprint.lowercased(), $0) },
            uniquingKeysWith: { first, _ in first }
        )
        let targetFingerprintsByKeyId = Dictionary(
            keyRecords.map { ($0.keyId, $0.fingerprint.lowercased()) },
            uniquingKeysWith: { first, _ in first }
        )

        var vouchers: [String: [ContactKeyVoucher]] = [:]
        for artifact in certificationArtifacts where artifact.validationStatus == .valid {
            guard let signerFingerprint = artifact.signerPrimaryFingerprint?.lowercased(),
                  signerFingerprint != targetFingerprintsByKeyId[artifact.keyId],
                  let signer = recordsByFingerprint[signerFingerprint],
                  ContactVouchingPolicy.carriesVouchingWeight(signer) else {
                continue
            }
            vouchers[artifact.keyId, default: []].append(
                ContactKeyVoucher(
                    fingerprint: signer.fingerprint,
                    displayName: signer.displayName
                )
            )
        }

        vouchersByTargetKeyId = vouchers.mapValues { voucherList in
            var seenFingerprints = Set<String>()
            return voucherList
                .filter { seenFingerprints.insert($0.fingerprint.lowercased()).inserted }
                .sorted { lhs, rhs in
                    let nameOrder = lhs.displayName.localizedCaseInsensitiveCompare(rhs.displayName)
                    if nameOrder != .orderedSame {
                        return nameOrder == .orderedAscending
                    }
                    return lhs.fingerprint < rhs.fingerprint
                }
        }
    }

    func trust(for keyRecord: ContactKeyRecord) -> ContactKeyTrust {
        ContactKeyTrust(
            isVerifiedByUser: keyRecord.manualVerificationState.isVerified,
            vouchers: vouchersByTargetKeyId[keyRecord.keyId] ?? []
        )
    }
}

/// Names the signer of one certification, given everything the user holds.
///
/// Kept separate from `ContactCertificationTrustWeb` because naming a signer
/// needs the user's own keys as well as their contacts, while deriving trust
/// deliberately does not: a certification the user made themselves is their own
/// act and is never counted as somebody vouching for the contact.
struct ContactCertificationSignerResolver {
    private let contactRecordsByFingerprint: [String: ContactKeyRecord]
    private let ownKeysByFingerprint: [String: PGPKeyIdentity]

    init(contactKeyRecords: [ContactKeyRecord], ownKeys: [PGPKeyIdentity]) {
        contactRecordsByFingerprint = Dictionary(
            contactKeyRecords.map { ($0.fingerprint.lowercased(), $0) },
            uniquingKeysWith: { first, _ in first }
        )
        ownKeysByFingerprint = Dictionary(
            ownKeys.map { ($0.fingerprint.lowercased(), $0) },
            uniquingKeysWith: { first, _ in first }
        )
    }

    /// The role of `signerFingerprint` in a certification over `targetFingerprint`.
    /// `nil` when the signature named no signer at all.
    func role(
        ofSignerFingerprint signerFingerprint: String?,
        certifying targetFingerprint: String?
    ) -> ContactCertificationSignerRole? {
        guard let signerFingerprint, !signerFingerprint.isEmpty else {
            return nil
        }
        let normalizedSigner = signerFingerprint.lowercased()

        if let targetFingerprint, normalizedSigner == targetFingerprint.lowercased() {
            return .targetKeyItself(fingerprint: signerFingerprint)
        }

        if let ownKey = ownKeysByFingerprint[normalizedSigner] {
            return .you(
                fingerprint: ownKey.fingerprint,
                displayName: IdentityPresentation.parsedDisplayName(from: ownKey.userId)
                    ?? ownKey.shortKeyId
            )
        }

        if let record = contactRecordsByFingerprint[normalizedSigner] {
            return .contact(
                ContactCertificationContactSigner(
                    fingerprint: record.fingerprint,
                    displayName: record.displayName,
                    secondaryText: record.email ?? record.primaryUserId,
                    isVerifiedByUser: record.manualVerificationState.isVerified,
                    carriesVouchingWeight: ContactVouchingPolicy.carriesVouchingWeight(record)
                )
            )
        }

        return .unknown(fingerprint: signerFingerprint)
    }
}
