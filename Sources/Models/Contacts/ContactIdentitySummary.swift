import Foundation

struct ContactIdentitySummary: Identifiable, Hashable, Sendable {
    var id: String { contactId }

    let contactId: String
    let displayName: String
    let primaryEmail: String?
    let tagIds: [String]
    let tags: [ContactTagSummary]
    let keys: [ContactKeySummary]

    var preferredKey: ContactKeySummary? {
        keys.first { $0.usageState == .preferred }
    }

    var additionalActiveKeys: [ContactKeySummary] {
        keys.filter { $0.usageState == .additionalActive }
    }

    var historicalKeys: [ContactKeySummary] {
        keys.filter { $0.usageState == .historical }
    }

    var canEncryptTo: Bool {
        preferredKey?.canEncryptTo == true
    }

    var hasUnverifiedKeys: Bool {
        keys.contains { !$0.isVerified }
    }

    /// Every contact whose certification currently carries weight over any of
    /// this contact's keys, named once each.
    var vouchers: [ContactKeyVoucher] {
        var seenFingerprints = Set<String>()
        return keys
            .flatMap(\.trust.vouchers)
            .filter { seenFingerprints.insert($0.fingerprint.lowercased()).inserted }
            .sorted { lhs, rhs in
                let nameOrder = lhs.displayName.localizedCaseInsensitiveCompare(rhs.displayName)
                if nameOrder != .orderedSame {
                    return nameOrder == .orderedAscending
                }
                return lhs.fingerprint < rhs.fingerprint
            }
    }

    /// The contact-wide reading of stored certification signatures, reporting
    /// whatever needs attention ahead of whatever is fine.
    var certificationSignatureState: ContactCertificationProjection.SignatureState {
        let states = keys.map(\.certificationProjection.signatureState)
        if states.contains(.invalidOrStale) {
            return .invalidOrStale
        }
        if states.contains(.revalidationNeeded) {
            return .revalidationNeeded
        }
        return states.contains(.valid) ? .valid : .absent
    }
}
