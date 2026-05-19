import Foundation

/// Result of recipient analysis for text-based decryption.
///
/// Phase 1 runs without authentication and only determines which local key can
/// decrypt the message. Phase 2 must still authenticate before private-key use.
struct DecryptionPhase1Result {
    /// Recipient key IDs found in the ciphertext header.
    let recipientKeyIds: [String]
    /// Matched local key identity, if any.
    let matchedKey: PGPKeyIdentity?
    /// Binary ciphertext data passed through for Phase 2.
    let ciphertext: Data
}
