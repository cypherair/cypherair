import Foundation

/// The key-list domain: the non-secret projection of every owned key. Never
/// rebuilt from envelope rows.
struct KeyListPayload: Codable, Equatable, Sendable {
    static let schemaVersion = 1

    var identities: [PGPKeyIdentity]

    static let empty = KeyListPayload(identities: [])

    func validateContract() throws {
        var seen = Set<String>()
        for identity in identities {
            let fingerprint = identity.fingerprint
            guard !fingerprint.isEmpty, fingerprint == fingerprint.lowercased(),
                  fingerprint.unicodeScalars.allSatisfy({ ("0"..."9").contains($0) || ("a"..."f").contains($0) }) else {
                throw CypherAirError.invalidKeyData(reason: "Key list fingerprint is not lowercase hex.")
            }
            guard seen.insert(fingerprint).inserted else {
                throw CypherAirError.invalidKeyData(reason: "Key list contains a duplicate fingerprint.")
            }
            guard !identity.publicKeyData.isEmpty else {
                throw CypherAirError.invalidKeyData(reason: "Key list entry has no public certificate.")
            }
        }
        guard identities.filter(\.isDefault).count <= 1 else {
            throw CypherAirError.invalidKeyData(reason: "Key list names more than one default key.")
        }
    }
}

/// What each domain looked like when the session opened.
struct VaultIntegrityReport: Equatable, Sendable {
    var settings: DomainIntegrityState
    var contacts: DomainIntegrityState
    var keys: DomainIntegrityState

    static let intact = VaultIntegrityReport(settings: .intact, contacts: .intact, keys: .intact)

    var isIntact: Bool { settings == .intact && contacts == .intact && keys == .intact }
}

enum DomainIntegrityState: Equatable, Sendable {
    case intact
    case missing
    case damaged
}
