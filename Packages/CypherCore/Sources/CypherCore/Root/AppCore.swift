import Foundation
import Observation
internal import Vault

/// The one root object, used by the app and by the tests. Screens follow
/// `phase`; content screens are built only from the workspace of the
/// `unlocked` phase.
@MainActor
@Observable
public final class AppCore {
    public internal(set) var phase: Phase = .starting

    @ObservationIgnored let composition: Composition?
    @ObservationIgnored var awaySince: ContinuousClock.Instant?
    @ObservationIgnored private var started = false

    init(composition: Composition?) {
        self.composition = composition
    }

    /// The hardware enclave and the Keychain on a device; the software enclave
    /// and memory on the simulator.
    public static func live(prompts: PromptTexts) -> AppCore {
        AppCore(composition: try? Composition.live(prompts: prompts))
    }

    /// Software and memory only, already unlocked: for SwiftUI previews.
    public static func preview() -> AppCore {
        let composition = Composition.software(prompts: PromptTexts(createVault: "Preview", unlock: "Preview"))
        let core = AppCore(composition: composition)
        core.started = true
        do {
            let session = OpenSession(vaultSession: try UnlockedSession.sandbox(enclave: SoftwareEnclave()))
            core.phase = .unlocked(Workspace(core: core, session: session, domains: composition.domains, payloads: .firstValues))
        } catch {
            core.phase = .restartRequired
        }
        return core
    }

    /// Decides the first phase: first run when this device holds no vault,
    /// locked when it does. Reads no secret and shows no prompt.
    public func start() async {
        guard !started else { return }
        started = true
        guard let composition else {
            phase = .restartRequired
            return
        }
        let vault = composition.vault
        do {
            let exists = try await Blocking.run { () throws(VaultError) in try vault.sealedRootExists() }
            phase = exists ? .locked(Unlock(core: self, composition: composition)) : .firstRun(FirstRun(core: self, composition: composition))
        } catch {
            phase = .restartRequired
        }
    }
}

public enum Phase: Sendable {
    case starting
    case firstRun(FirstRun)
    case locked(Unlock)
    case unlocked(Workspace)
    /// A sealed file is missing, damaged or from another version. The session
    /// is open, and lock applies here too.
    case damaged(Recovery)
    /// Lock could not erase what it must. Only a restart recovers.
    case restartRequired
}

/// The sentences of the system authentication sheets. The app owns every text,
/// so it hands these to the core once.
public struct PromptTexts: Sendable {
    public var createVault: String
    public var unlock: String

    public init(createVault: String, unlock: String) {
        self.createVault = createVault
        self.unlock = unlock
    }
}
