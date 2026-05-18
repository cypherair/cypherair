import Foundation

struct ContactsVerificationContext: Equatable, Sendable {
    let contactKeys: [ContactKeyRecord]
    let availability: ContactsAvailability

    var verificationKeys: [Data] {
        guard availability.allowsContactsVerification else {
            return []
        }
        return contactKeys.map(\.publicKeyData)
    }
}
