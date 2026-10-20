/// Failures of the sealing layer. Reasons are stable categories with no secret
/// content; the string carries which contract was violated, never a value.
public enum SealingError: Error, Equatable, Sendable {
    /// The bytes are not the format they claim to be: wrong magic, unknown or
    /// missing field, wrong length, undecodable public key.
    case malformed(String)
    /// The blob was sealed as a different payload kind than the caller expects.
    case payloadKindMismatch
    /// The public metadata does not match what the caller expects.
    case bindingMismatch
    /// AES-GCM refused the ciphertext: tampering, or the wrong key.
    case authenticationFailed
    /// A secure random number could not be produced.
    case randomnessUnavailable
    /// The system's encoder or decoder failed for a reason that is not the
    /// caller's input.
    case internalFailure(String)
}
