/// A queue of one. Work that holds the turn runs alone; the rest wait in the
/// order they asked.
@MainActor
final class Turn {
    private var busy = false
    private var waiting: [CheckedContinuation<Void, Never>] = []

    func take() async {
        guard busy else {
            busy = true
            return
        }
        await withCheckedContinuation { waiting.append($0) }
    }

    func pass() {
        if waiting.isEmpty {
            busy = false
        } else {
            waiting.removeFirst().resume()
        }
    }
}
