/// The core's one error type. No case carries text, a fingerprint or a path;
/// the app turns each case into one sentence.
public enum CoreError: Error, Sendable, Equatable {
    /// The call came through a workspace that was locked.
    case locked
    /// The user cancelled, or the call came through a phase that is over.
    /// Nothing to report.
    case cancelled
    case restartRequired
    case authenticationFailed, authenticationUnavailable, wrongPassphrase
    /// A new passphrase has a problem that `Passphrase.problems(in:)` names.
    case passphraseTooWeak
    case notOpenPGP, wrongKindOfData, unsupported, tooComplex
    case tampered, noMatchingKey
    case keyExpired, keyRevoked, keyUnusable
    /// An expiry change came less than a minute after the key's newest
    /// self-signature.
    case tooSoon
    case recipientUnusable(Recipient)
    case notExportable, keyMaterialMissing, deviceKeyFailed
    case notEnoughMemory, outOfSpace, fileFailed
    case alreadyPresent, storageDamaged, storageFailed, internalFailure
}

public enum Recipient: Sendable, Hashable {
    case contact(Contact.ID)
    case ownKey(Key.ID)
}
