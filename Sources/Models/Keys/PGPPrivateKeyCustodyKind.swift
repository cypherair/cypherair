import Foundation

/// App-owned private-key custody vocabulary, separate from OpenPGP configuration.
enum PGPPrivateKeyCustodyKind: String, CaseIterable, Codable, Hashable, Sendable {
    case softwareSecretCertificate
    case appleSecureEnclavePrivateOperations
}
