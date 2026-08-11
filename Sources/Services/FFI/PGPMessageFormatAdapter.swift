import Foundation

/// FFI-owned entry point for the engine's outgoing message format rule.
///
/// The rule lives in `pgp-mobile/src/message_format.rs`, beside the encrypt path
/// that produces the messages it describes. This adapter hands it the same
/// recipient arguments the encrypt call receives and normalizes its error;
/// nothing on this side restates the rule, because a second copy is exactly how
/// a format preview comes to contradict the message it previews.
///
/// The engine is constructed here rather than injected, unlike every other
/// adapter. That is the point: an injectable engine is a seam through which a
/// test double could state a format rule the real engine does not apply, which
/// is the one thing this type exists to make impossible. There is nothing to
/// substitute for either — the call reads public certificates and touches no
/// custody, and the engine is stateless.
enum PGPMessageFormatAdapter {
    /// The format an encrypt of these recipients will produce, and which of them
    /// decide it.
    ///
    /// Reads the certificates fresh on every call — no capability is carried
    /// over from import — so the only gap between this answer and the message is
    /// the moment between previewing and pressing Encrypt. Throws wherever the
    /// encrypt path would refuse the same recipients: there is no message to
    /// describe then.
    ///
    static func decision(
        recipientKeys: [Data],
        encryptToSelfKey: Data?
    ) throws -> OutgoingFormatDecision {
        do {
            return try PgpEngine().decideOutgoingMessageFormat(
                recipients: recipientKeys,
                encryptToSelf: encryptToSelfKey
            )
        } catch {
            throw PGPErrorMapper.map(error) { .encryptionFailed(reason: $0) }
        }
    }
}
