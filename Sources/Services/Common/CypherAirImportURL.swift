import Foundation

/// The app's custom URL scheme for contact import.
///
/// Declared in `CypherAir-Info.plist` and produced by the engine
/// (`pgp-mobile/src/qr_url.rs`); this is the single Swift home every matcher
/// reads, so the scheme is not a literal scattered across the QR service, the
/// import loader, and the incoming-URL coordinator.
enum CypherAirImportURL {
    static let scheme = "cypherairx"
    static let schemePrefix = "\(scheme)://"
}
