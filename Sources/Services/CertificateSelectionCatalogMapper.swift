import Foundation

/// Shared mapper from UniFFI selector discovery records into app-owned models.
enum CertificateSelectionCatalogMapper {
    static func map(_ discovered: DiscoveredCertificateSelectors) -> CertificateSelectionCatalog {
        CertificateSelectionCatalog(
            certificateFingerprint: discovered.certificateFingerprint,
            subkeys: discovered.subkeys.map { discoveredSubkey in
                SubkeySelectionOption(
                    fingerprint: discoveredSubkey.fingerprint,
                    algorithmDisplay: discoveredSubkey.algorithmDisplay,
                    isCurrentlyTransportEncryptionCapable: discoveredSubkey.isCurrentlyTransportEncryptionCapable,
                    isCurrentlyRevoked: discoveredSubkey.isCurrentlyRevoked,
                    isCurrentlyExpired: discoveredSubkey.isCurrentlyExpired
                )
            },
            userIds: discovered.userIds.map { discoveredUserId in
                UserIdSelectionOption(
                    occurrenceIndex: Int(discoveredUserId.occurrenceIndex),
                    userIdData: discoveredUserId.userIdData,
                    displayText: discoveredUserId.displayText,
                    isCurrentlyPrimary: discoveredUserId.isCurrentlyPrimary,
                    isCurrentlyRevoked: discoveredUserId.isCurrentlyRevoked
                )
            }
        )
    }
}
