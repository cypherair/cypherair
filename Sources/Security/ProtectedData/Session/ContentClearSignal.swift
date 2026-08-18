import Foundation

/// The relock signal App views observe (via `.onChange` of `generation`) to
/// clear decrypted content.
///
/// It is deliberately its own small value rather than a face of
/// `AppSessionOrchestrator`: every world that renders feature views injects one
/// — production's is raised by the orchestrator on relock and local data reset,
/// the tutorial sandbox's belongs to the sandbox container — so observing the
/// clear signal never requires handing a view the real session mutators.
@Observable
final class ContentClearSignal {
    private(set) var generation = 0

    func raise() {
        generation += 1
    }
}
