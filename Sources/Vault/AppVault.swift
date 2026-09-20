import CryptoKit
import Foundation
import LocalAuthentication
import Sealing
import Stores
import Vault
import os

/// The app's one vault: the package's vault plus the three protected-data
/// domains, the identity stores, and the current session.
///
/// Thread-safe by a lock so services that run off the main actor can read the
/// session and the domain caches; the lock controller owns the lifecycle.
final class AppVault: @unchecked Sendable {
    struct Domains: Sendable {
        let settings: SealedDomain<AppSettingsSnapshot>
        let contacts: SealedDomain<ContactsDomainSnapshot>
        let keys: SealedDomain<KeyListPayload>

        init(directory: ProtectedDataDirectory) {
            settings = SealedDomain(domain: "settings", schemaVersion: AppSettingsSnapshot.schemaVersion, directory: directory)
            contacts = SealedDomain(domain: "contacts", schemaVersion: ContactsDomainSnapshot.currentSchemaVersion, directory: directory)
            keys = SealedDomain(domain: "keys", schemaVersion: KeyListPayload.schemaVersion, directory: directory)
        }
    }

    private struct Open {
        let session: UnlockedSession
        var settings: AppSettingsSnapshot?
        var contacts: ContactsDomainSnapshot?
        var keys: KeyListPayload?
    }

    let vault: Vault
    let directory: ProtectedDataDirectory
    let domains: Domains
    let portableKeys: IdentityEnvelopeStore
    let splitCustody: IdentityEnvelopeStore
    let custody: CustodyKeyStore
    private let open = OSAllocatedUnfairLock<Open?>(initialState: nil)

    init(
        vault: Vault,
        directory: ProtectedDataDirectory,
        portableKeys: IdentityEnvelopeStore,
        splitCustody: IdentityEnvelopeStore,
        custody: CustodyKeyStore
    ) {
        self.vault = vault
        self.directory = directory
        domains = Domains(directory: directory)
        self.portableKeys = portableKeys
        self.splitCustody = splitCustody
        self.custody = custody
    }

    /// Production composition: the hardware enclave, Keychain rows, the engine's
    /// Argon2id, the system presence sheet, and Application Support.
    static func production(engine: PgpEngine) throws -> AppVault {
        let enclave = HardwareEnclave()
        return AppVault(
            vault: Vault(
                enclave: enclave,
                rootRows: KeychainRowStore(service: Vault.sealedRootService),
                stretcher: EngineStretcher(engine: engine),
                authenticator: SystemAuthenticator()
            ),
            directory: try ProtectedDataDirectory.applicationSupport(),
            portableKeys: .portableKeys(),
            splitCustody: .splitCustody(),
            custody: .keychain(enclave: enclave)
        )
    }

    /// Sandbox composition: software keys, rows in memory, no stretch, no
    /// prompt, domain files under `directory`. The tutorial and the test hosts.
    static func sandbox(directory: URL) throws -> AppVault {
        let enclave = SoftwareEnclave()
        let custodyRows = Dictionary(
            uniqueKeysWithValues: CustodyTier.allCases.flatMap { tier in
                CustodyRole.allCases.map { role in ("\(tier.rawValue).\(role.rawValue)", InMemoryRowStore()) }
            }
        )
        return AppVault(
            vault: Vault(
                enclave: enclave,
                rootRows: InMemoryRowStore(),
                stretcher: SandboxStretcher(),
                authenticator: NoPromptAuthenticator()
            ),
            directory: try ProtectedDataDirectory(url: directory),
            portableKeys: .portableKeys(rows: InMemoryRowStore()),
            splitCustody: .splitCustody(rows: InMemoryRowStore()),
            custody: CustodyKeyStore(enclave: enclave) { tier, role in
                custodyRows["\(tier.rawValue).\(role.rawValue)"]!
            }
        )
    }

    // MARK: - Lifecycle

    var hasSealedRoot: Bool {
        (try? vault.sealedRootExists()) ?? false
    }

    var isUnlocked: Bool { open.withLock { $0 != nil } }

    /// The current session, for stores that need keys or contexts.
    func requireSession() throws -> UnlockedSession {
        guard let session = open.withLock({ $0?.session }) else { throw VaultError.locked }
        return session
    }

    /// First run: seals a fresh root and writes every domain's initial payload.
    func bootstrap(passphrase: consuming SensitiveBuffer, reason: String) async throws {
        let session = try await vault.bootstrap(passphrase: passphrase, reason: reason)
        directory.sweepTemporaries()
        try domains.settings.save(.firstRun, key: try session.domainKey(domains.settings.domain))
        try domains.contacts.save(.empty(), key: try session.domainKey(domains.contacts.domain))
        try domains.keys.save(.empty, key: try session.domainKey(domains.keys.domain))
        open.withLock { $0 = Open(session: session, settings: .firstRun, contacts: .empty(), keys: .empty) }
    }

    /// A sandbox vault opened under a passphrase nobody holds.
    func bootstrapSandbox() async throws {
        var random = try Randomness.bytes(count: 32)
        try await bootstrap(passphrase: SensitiveBuffer(consuming: &random), reason: "")
    }

    func beginUnlock(reason: String) -> UnlockAttempt {
        vault.beginUnlock(reason: reason)
    }

    /// Opens every domain with a session the unlock produced. Damage never
    /// falls back to defaults: an intact domain is cached, a damaged or missing
    /// one is reported, and the session stays available so intact portable
    /// keys can still be exported before a reset.
    func adopt(session: UnlockedSession) -> VaultIntegrityReport {
        directory.sweepTemporaries()
        let settings = load(domains.settings, session: session)
        let contacts = load(domains.contacts, session: session)
        var loadedKeys = load(domains.keys, session: session)
        if let payload = loadedKeys.payload, (try? payload.validateContract()) == nil {
            loadedKeys = (nil, .damaged)
        }
        let keys = loadedKeys
        open.withLock {
            $0 = Open(session: session, settings: settings.payload, contacts: contacts.payload, keys: keys.payload)
        }
        return VaultIntegrityReport(settings: settings.state, contacts: contacts.state, keys: keys.state)
    }

    private func load<P: Codable & Sendable>(
        _ domain: SealedDomain<P>,
        session: UnlockedSession
    ) -> (payload: P?, state: DomainIntegrityState) {
        do {
            return (try domain.load(key: try session.domainKey(domain.domain)), .intact)
        } catch StoreError.missing {
            return (nil, .missing)
        } catch {
            return (nil, .damaged)
        }
    }

    /// Erases the session values and drops every cached payload.
    func relock() {
        let session = open.withLock { open -> UnlockedSession? in
            defer { open = nil }
            return open?.session
        }
        session?.relock()
    }

    /// Reset All Local Data: the sealed root, every identity row, every custody
    /// row, and every domain file. Every identity key is unusable afterwards by
    /// construction.
    func reset() throws {
        relock()
        try vault.reset()
        try portableKeys.deleteAll()
        try splitCustody.deleteAll()
        try custody.deleteAll()
        try domains.settings.delete()
        try domains.contacts.delete()
        try domains.keys.delete()
        directory.sweepTemporaries()
    }

    /// What a reset must have removed. Empty when nothing remains.
    func residue() -> [String] {
        var residue: [String] = []
        if hasSealedRoot { residue.append("sealedRoot") }
        if !((try? portableKeys.fingerprints())?.isEmpty ?? true) { residue.append("portableKeys") }
        if !((try? splitCustody.fingerprints())?.isEmpty ?? true) { residue.append("splitCustody") }
        if ((try? custody.inventory())?.totalRowCount ?? 0) > 0 { residue.append("custody") }
        if domains.settings.exists { residue.append("settings") }
        if domains.contacts.exists { residue.append("contacts") }
        if domains.keys.exists { residue.append("keys") }
        return residue
    }

    func changePassphrase(current: consuming SensitiveBuffer, new: consuming SensitiveBuffer, reason: String) async throws {
        try await vault.changePassphrase(current: current, new: new, reason: reason)
    }

    // MARK: - Domains

    var settings: AppSettingsSnapshot? { open.withLock { $0?.settings } }
    var contacts: ContactsDomainSnapshot? { open.withLock { $0?.contacts } }
    var keys: [PGPKeyIdentity]? { open.withLock { $0?.keys?.identities } }

    func saveSettings(_ snapshot: AppSettingsSnapshot) throws {
        let session = try requireSession()
        try domains.settings.save(snapshot, key: try session.domainKey(domains.settings.domain))
        open.withLock { $0?.settings = snapshot }
    }

    func saveContacts(_ snapshot: ContactsDomainSnapshot) throws {
        let session = try requireSession()
        try domains.contacts.save(snapshot, key: try session.domainKey(domains.contacts.domain))
        open.withLock { $0?.contacts = snapshot }
    }

    func saveKeys(_ identities: [PGPKeyIdentity]) throws {
        let payload = KeyListPayload(identities: identities)
        try payload.validateContract()
        let session = try requireSession()
        try domains.keys.save(payload, key: try session.domainKey(domains.keys.domain))
        open.withLock { $0?.keys = payload }
    }
}
