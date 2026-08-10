import Foundation

/// The encrypted-container format an outgoing public-key message carries.
///
/// CypherAir never *chooses* this. The engine derives it from the recipient
/// certificates it is handed, and no Swift code passes a format into the
/// public-key encryption path (CLAUDE.md Hard Constraint 8, docs/PRODUCT.md §5).
enum OutgoingMessageFormat: Equatable, Hashable, Sendable {
    /// RFC 4880 SEIPDv1 — integrity by MDC, no AEAD.
    case seipdV1
    /// RFC 9580 SEIPDv2 — AEAD (OCB).
    case seipdV2
}

/// What the engine will do with a recipient set that has not been sent to yet.
///
/// This is a read-only mirror of the engine's rule, never an instruction to it:
/// SEIPDv2 is an RFC 9580 container, so a message is SEIPDv2 only when every
/// certificate it is encrypted to is v6, and a single v4 certificate pulls the
/// whole message down to SEIPDv1. The engine side of that rule is pinned by
/// `pgp-mobile/tests/cross_suite_tests.rs::test_format_selection_*`.
///
/// Build this from **every** certificate the message will be encrypted to — the
/// chosen recipients *and* the Encrypt to Self copy — or it describes a message
/// other than the one that gets sent. The sender's signing key is not one of
/// them: signing does not add a recipient and does not move the format.
struct OutgoingMessageFormatPreview: Equatable, Hashable, Sendable {
    /// The format the engine will select for this recipient set.
    let format: OutgoingMessageFormat

    /// At least one certificate in the set could have received AEAD on its own.
    let hasAeadCapableRecipient: Bool

    /// An empty set is not a message: `format` reports `.seipdV2` because nothing
    /// forces a fallback, and nothing is flagged.
    init(recipientKeyVersions: some Sequence<UInt8>) {
        var hasAeadCapableRecipient = false
        var everyRecipientIsAeadCapable = true
        for keyVersion in recipientKeyVersions {
            if Self.supportsSeipdV2(keyVersion: keyVersion) {
                hasAeadCapableRecipient = true
            } else {
                everyRecipientIsAeadCapable = false
            }
        }
        self.hasAeadCapableRecipient = hasAeadCapableRecipient
        format = everyRecipientIsAeadCapable ? .seipdV2 : .seipdV1
    }

    /// The message falls back to SEIPDv1 while carrying a certificate that could
    /// have received AEAD — someone loses protection their own key supports.
    ///
    /// This is the only case worth warning about. A message addressed only to v4
    /// certificates is also SEIPDv1, but nothing was given up: SEIPDv1 is what
    /// those keys support.
    var downgradesAeadCapableRecipients: Bool {
        format == .seipdV1 && hasAeadCapableRecipient
    }

    /// Whether a certificate of this key version is what costs the message its
    /// AEAD.
    ///
    /// Also the honest answer for a recipient who is not selected yet: adding a
    /// v4 certificate to a set that already carries an AEAD-capable one is
    /// exactly what forces the fallback, so the same predicate previews the
    /// consequence of selecting the row.
    func limitsFormat(recipientKeyVersion: UInt8) -> Bool {
        !Self.supportsSeipdV2(keyVersion: recipientKeyVersion) && hasAeadCapableRecipient
    }

    private static func supportsSeipdV2(keyVersion: UInt8) -> Bool {
        keyVersion >= 6
    }
}
