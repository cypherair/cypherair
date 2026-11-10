internal import Stores

/// One sealed file's value in memory, and the only way to change it.
///
/// Changes run one at a time under the file's turn, each on the value the one
/// before it left. The value in memory changes only after the file was
/// written: when the write fails, nothing changes and the caller gets the
/// error. A change that finishes after lock is never delivered.
@MainActor
final class Store<Payload: Codable & Sendable> {
    private let domain: SealedDomain<Payload>
    private let turn: Turn
    private let session: OpenSession
    private var payload: Payload?

    init(domain: SealedDomain<Payload>, turn: Turn, session: OpenSession, payload: Payload) {
        self.domain = domain
        self.turn = turn
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
        await turn.take()
        defer { turn.pass() }
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
}
