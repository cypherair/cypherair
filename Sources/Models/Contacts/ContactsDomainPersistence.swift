import Foundation

/// Persistence seam for the contacts protected domain.
///
/// Exactly the surface `ContactService` drives: commit-if-needed, open,
/// replace, relock, and the open snapshot. The SQLCipher-backed
/// `ContactsDomainStore` conforms for production; `InMemoryContactsDomainStore`
/// conforms for the sandboxed worlds. Both run the same
/// `ContactsDomainSnapshot.validateContract()` at their persistence
/// boundaries, so the domain invariants live in the model, not in any one
/// backend.
protocol ContactsDomainPersistence: AnyObject {
    var snapshot: ContactsDomainSnapshot? { get }

    func ensureCommittedIfNeeded(
        wrappingRootKey: Data,
        initialSnapshotProvider: () throws -> ContactsDomainSnapshot
    ) async throws

    @discardableResult
    func openDomainIfNeeded(wrappingRootKey: Data) async throws -> ContactsDomainSnapshot

    func replaceSnapshot(_ updatedSnapshot: ContactsDomainSnapshot) throws

    func relockProtectedData() async throws
}

enum InMemoryContactsDomainStoreError: Error {
    case domainNotOpen
}

/// RAM-only contacts domain store for the guided tutorial sandbox and the
/// DEBUG UI-test container.
///
/// Holds no storage root, no registry, and no database — zero bytes on disk by
/// construction. It enforces the same domain contract as the SQLCipher-backed
/// store at the same boundaries (initial commit, open, every replacement), so
/// the sandbox cannot reach a state production rejects. Wrapping root keys are
/// accepted for interface parity and ignored: there is nothing at rest to
/// protect.
final class InMemoryContactsDomainStore: ContactsDomainPersistence, @unchecked Sendable {
    private(set) var snapshot: ContactsDomainSnapshot?
    private var storedSnapshot: ContactsDomainSnapshot?

    func ensureCommittedIfNeeded(
        wrappingRootKey: Data,
        initialSnapshotProvider: () throws -> ContactsDomainSnapshot
    ) async throws {
        guard storedSnapshot == nil else { return }
        let initialSnapshot = try initialSnapshotProvider()
        try initialSnapshot.validateContract()
        storedSnapshot = initialSnapshot
    }

    @discardableResult
    func openDomainIfNeeded(wrappingRootKey: Data) async throws -> ContactsDomainSnapshot {
        if let snapshot {
            return snapshot
        }
        guard let storedSnapshot else {
            throw InMemoryContactsDomainStoreError.domainNotOpen
        }
        try storedSnapshot.validateContract()
        snapshot = storedSnapshot
        return storedSnapshot
    }

    func replaceSnapshot(_ updatedSnapshot: ContactsDomainSnapshot) throws {
        guard snapshot != nil else {
            throw InMemoryContactsDomainStoreError.domainNotOpen
        }
        try updatedSnapshot.validateContract()
        storedSnapshot = updatedSnapshot
        snapshot = updatedSnapshot
    }

    func relockProtectedData() async throws {
        snapshot = nil
    }
}
