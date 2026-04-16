import Foundation

/// Shared read-only selector discovery helper for arbitrary certificate bytes.
enum CertificateSelectionCatalogDiscovery {
    static func discover(
        engine: PgpEngine,
        certData: Data
    ) throws -> (raw: DiscoveredCertificateSelectors, catalog: CertificateSelectionCatalog) {
        let discovered: DiscoveredCertificateSelectors
        do {
            discovered = try engine.discoverCertificateSelectors(certData: certData)
        } catch {
            throw CypherAirError.from(error) { .invalidKeyData(reason: $0) }
        }

        return (discovered, CertificateSelectionCatalogMapper.map(discovered))
    }
}
