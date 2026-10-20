/// A service that holds decrypted state for the session and must drop it when
/// the vault relocks. Relock is fail-closed: a participant that fails latches a
/// restart-required state in the lock controller.
protocol VaultRelockParticipant: AnyObject, Sendable {
    func relockVault() async throws
}
