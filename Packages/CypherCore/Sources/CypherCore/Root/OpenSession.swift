internal import CryptoKit
internal import Vault

/// The vault's unlocked session as the core holds it, shared by everything one
/// unlock opened. Closing it erases the session values; every later call
/// through it throws `locked`. Long file operations read `isOpen` to stop.
@MainActor
final class OpenSession {
    let vaultSession: UnlockedSession
    private(set) var isOpen = true

    init(vaultSession: UnlockedSession) {
        self.vaultSession = vaultSession
    }

    func checkOpen() throws(CoreError) {
        guard isOpen else { throw .locked }
    }

    func domainKey(_ domain: String) throws(CoreError) -> SymmetricKey {
        try checkOpen()
        do { return try vaultSession.domainKey(domain) } catch { throw CoreError(error) }
    }

    func close() {
        isOpen = false
        vaultSession.relock()
    }
}
