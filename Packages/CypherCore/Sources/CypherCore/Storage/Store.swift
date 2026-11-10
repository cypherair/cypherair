internal import Stores

/// One sealed file's value in memory, and the only way to change it.
///
/// Changes run one at a time, each on the value the one before it left. The
/// value in memory changes only after the file was written: when the write
/// fails, nothing changes and the caller gets the error. A change that
/// finishes after lock is never delivered.
@MainActor
final class Store<Payload: Codable & Sendable> {
    private let domain: SealedDomain<Payload>
    private let session: OpenSession
    private var payload: Payload?
    private var busy = false
    private var waiting: [CheckedContinuation<Void, Never>] = []

    init(domain: SealedDomain<Payload>, session: OpenSession, payload: Payload) {
        self.domain = domain
        self.session = session
        self.payload = payload
    }

    var value: Payload {
        get throws(CoreError) {
            guard let payload else { throw .locked }
            return payload
        }
    }

    /// Applies `change` to the current value, writes the result, and only then
    /// keeps it. Returns what `change` returned.
    func update<Outcome>(_ change: (inout Payload) throws(CoreError) -> Outcome) async throws(CoreError) -> Outcome {
        await takeTurn()
        defer { passTurn() }
        guard var next = payload else { throw .locked }
        let outcome = try change(&next)
        let key = try session.domainKey(domain.domain)
        let domain = self.domain
        let written = next
        do {
            try await Blocking.run { () throws(StoreError) in try domain.save(written, key: key) }
        } catch {
            throw CoreError(error)
        }
        guard payload != nil else { throw .locked }
        payload = next
        return outcome
    }

    func drop() {
        payload = nil
    }

    private func takeTurn() async {
        guard busy else {
            busy = true
            return
        }
        await withCheckedContinuation { waiting.append($0) }
    }

    private func passTurn() {
        if waiting.isEmpty {
            busy = false
        } else {
            waiting.removeFirst().resume()
        }
    }
}
