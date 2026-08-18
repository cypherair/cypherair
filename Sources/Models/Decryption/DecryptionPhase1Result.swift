import Foundation

/// What Phase 1 learned about a text message: how it can be opened, and the
/// binary form of it that Phase 2 will work on.
///
/// Phase 1 runs without authentication — it reads session-key packets and
/// nothing else. Phase 2 must still authenticate before any private key is
/// used; opening the message with a password uses no key and prompts for none.
struct DecryptionPhase1Result {
    /// The local key the message is addressed to, if any.
    let matchedKey: PGPKeyIdentity?
    /// The message carries a password slot, so a password can open it. Both
    /// this and `matchedKey` can be true at once — a key is the better route
    /// and the screen offers it first.
    let acceptsPassword: Bool
    /// Binary ciphertext data passed through for Phase 2.
    let ciphertext: Data
}
