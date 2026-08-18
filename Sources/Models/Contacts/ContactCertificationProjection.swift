import Foundation

/// The state of the certification signatures stored for one contact key.
///
/// This answers a question about signatures — whether stored bytes still verify
/// — and never a question about trust. A key can hold a dozen certifications
/// that all verify and still be a key the user has no reason to believe in;
/// what the app is willing to assert is `ContactKeyTrust`, derived live from the
/// anchor set and deliberately not stored here or anywhere else.
struct ContactCertificationProjection: Codable, Equatable, Hashable, Sendable {

    /// Deliberately free of trust vocabulary. `valid` means the signatures
    /// verify, not that anyone vouches for the key.
    enum SignatureState: String, Codable, Equatable, Hashable, Sendable {
        /// No certification signatures are stored for the key.
        case absent
        /// At least one stored certification signature currently verifies.
        case valid
        /// Stored signatures fail to verify, or were made over certificate bytes
        /// the key no longer has.
        case invalidOrStale
        /// The verdict could not be taken — the signer is no longer held, or the
        /// signature no longer parses.
        case revalidationNeeded
    }

    var signatureState: SignatureState
    var artifactIds: [String]
    var lastValidatedAt: Date?

    static var empty: ContactCertificationProjection {
        ContactCertificationProjection(
            signatureState: .absent,
            artifactIds: [],
            lastValidatedAt: nil
        )
    }
}
