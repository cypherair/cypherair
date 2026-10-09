import Foundation
import LocalAuthentication
import Sealing
import Vault

/// Rows of secrets sealed against the identity wrapping key, one per key
/// fingerprint: portable secret certificates, and split-custody classical
/// halves. Sealing is software; opening is one enclave operation with the
/// caller's operation context.
public struct IdentityEnvelopeStore: Sendable {
    public static let portableKeyService = "com.cypherair.vault.portable-key"
    public static let splitCustodyService = "com.cypherair.vault.split-custody"

    public let kind: SealedPayloadKind
    private let rows: any RowStore

    public init(kind: SealedPayloadKind, rows: any RowStore) {
        precondition(kind != .rootSecret, "the root has its own row")
        self.kind = kind
        self.rows = rows
    }

    public static func portableKeys(rows: any RowStore = KeychainRowStore(service: portableKeyService)) -> IdentityEnvelopeStore {
        IdentityEnvelopeStore(kind: .secretCertificate, rows: rows)
    }

    public static func splitCustody(rows: any RowStore = KeychainRowStore(service: splitCustodyService)) -> IdentityEnvelopeStore {
        IdentityEnvelopeStore(kind: .splitCustodyComponent, rows: rows)
    }

    /// Seals `secret` for `fingerprint`, creating or replacing its row in place.
    public func seal(_ secret: borrowing SensitiveBuffer, fingerprint: String, session: UnlockedSession) throws(StoreError) {
        let account = try Self.normalize(fingerprint)
        let envelope: EnclaveSealedEnvelope
        do {
            envelope = try session.sealForIdentity(plaintext: secret, kind: kind, associatedData: Data(account.utf8))
        } catch {
            throw .vault(error)
        }
        let encoded: Data
        do { encoded = try EnclaveSealedEnvelopeCodec.encode(envelope) } catch { throw .internalFailure("envelope encoding failed") }
        do { try rows.write(account: account, data: encoded) } catch { throw .vault(error) }
    }

    /// Opens the secret for `fingerprint`. Blocking while the enclave prompts.
    public func open(fingerprint: String, session: UnlockedSession, context: LAContext) throws(StoreError) -> SensitiveBuffer {
        let account = try Self.normalize(fingerprint)
        let data: Data?
        do { data = try rows.read(account: account) } catch { throw .vault(error) }
        guard let data else { throw .missing }
        let envelope: EnclaveSealedEnvelope
        do { envelope = try EnclaveSealedEnvelopeCodec.decode(data, expectedKind: kind) } catch { throw .damaged }
        guard envelope.associatedData == Data(account.utf8) else { throw .damaged }
        do {
            return try session.openIdentityEnvelope(envelope, kind: kind, context: context)
        } catch {
            throw .vault(error)
        }
    }

    public func contains(fingerprint: String) throws(StoreError) -> Bool {
        let account = try Self.normalize(fingerprint)
        do { return try rows.read(account: account) != nil } catch { throw .vault(error) }
    }

    public func delete(fingerprint: String) throws(StoreError) {
        let account = try Self.normalize(fingerprint)
        do { try rows.delete(account: account) } catch { throw .vault(error) }
    }

    public func fingerprints() throws(StoreError) -> [String] {
        do { return try rows.accounts().map(\.account) } catch { throw .vault(error) }
    }

    /// Deletes every row. Part of Reset All Local Data.
    public func deleteAll() throws(StoreError) {
        for fingerprint in try fingerprints() {
            try delete(fingerprint: fingerprint)
        }
    }

    static func normalize(_ fingerprint: String) throws(StoreError) -> String {
        let lowered = fingerprint.lowercased()
        guard !lowered.isEmpty, lowered.unicodeScalars.allSatisfy({ ("0"..."9").contains($0) || ("a"..."f").contains($0) }) else {
            throw .invalidFingerprint
        }
        return lowered
    }
}
