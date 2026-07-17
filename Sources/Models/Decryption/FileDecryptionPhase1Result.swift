import Foundation

/// Result of recipient analysis for file-based decryption.
///
/// This mirrors `DecryptionPhase1Result` without loading the ciphertext into
/// memory; Phase 2 must still authenticate before private-key use.
struct FileDecryptionPhase1Result {
    /// Matched local key identity, if any.
    let matchedKey: PGPKeyIdentity?
    /// Path to the encrypted input file passed through for Phase 2.
    let inputPath: String
}
