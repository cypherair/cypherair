import Foundation
import Sealing
import Vault

/// The lock lifecycle: first-run setup, unlock by passphrase and presence,
/// the grace period, away relocking, and the two terminal failures a session
/// can land in. Everything the shield and the lock surface show comes from
/// `lockState`.
@Observable
@MainActor
final class AppLockController {
    enum LockState: Equatable {
        case setupRequired
        case locked
        case unlocking
        case unlocked
        case failed(UnlockFailure)
        case integrityFailure(VaultIntegrityReport)
        case restartRequired
    }

    enum UnlockFailure: Equatable {
        case wrongPassphrase
        case presenceCancelled
        case presenceFailed
        case presenceUnavailable
        case enclaveUnavailable
        case sealedRootDamaged
        case other(String)

        init(_ error: VaultError) {
            switch error {
            case .passphraseRejected: self = .wrongPassphrase
            case .authenticationCancelled: self = .presenceCancelled
            case .authenticationFailed: self = .presenceFailed
            case .authenticationUnavailable: self = .presenceUnavailable
            case .enclaveUnavailable: self = .enclaveUnavailable
            case .sealedRootCorrupt: self = .sealedRootDamaged
            case .noSealedRoot: self = .other("no sealed root")
            case .locked: self = .other("locked")
            case .storage(let reason), .internalFailure(let reason): self = .other(reason)
            }
        }

        /// A failure that keeps the presence the attempt already collected, so
        /// the retry asks for the passphrase alone.
        var keepsAttempt: Bool { self == .wrongPassphrase }
    }

    private let vault: AppVault
    private let gracePeriodProvider: () -> Int?
    private let lastAuthenticationDateProvider: () -> Date?
    private let recordSuccessfulAuthentication: () -> Void
    private let loadServices: @MainActor () async -> Void
    private let relockServices: @MainActor () async throws -> Void
    private let contentClearHandler: () -> Void
    private let operationPromptInProgressProvider: (() -> Bool)?
    private let waitForAwayRelockDeadline: (TimeInterval) async throws -> Void

    private(set) var lockState: LockState

    @ObservationIgnored
    private var attempt: UnlockAttempt?
    #if os(macOS)
    private var hasPendingOperationPromptAway = false
    private var openOperationPromptSessions = 0
    private var awayRelockTask: Task<Void, Never>?
    #endif
    private var awayGeneration = 0
    private var handledAwayGeneration: Int?
    private(set) var isForegroundActive = true
    private(set) var isResolvingForegroundLock = false
    private(set) var transitionGeneration = 0

    init(
        vault: AppVault,
        gracePeriodProvider: @escaping () -> Int?,
        lastAuthenticationDateProvider: @escaping () -> Date?,
        recordSuccessfulAuthentication: @escaping () -> Void,
        loadServices: @escaping @MainActor () async -> Void,
        relockServices: @escaping @MainActor () async throws -> Void,
        contentClearHandler: @escaping () -> Void = {},
        operationPromptInProgressProvider: (() -> Bool)? = nil,
        waitForAwayRelockDeadline: @escaping (TimeInterval) async throws -> Void = { seconds in
            try await Task.sleep(for: .seconds(seconds), tolerance: .seconds(1), clock: .continuous)
        }
    ) {
        self.vault = vault
        self.gracePeriodProvider = gracePeriodProvider
        self.lastAuthenticationDateProvider = lastAuthenticationDateProvider
        self.recordSuccessfulAuthentication = recordSuccessfulAuthentication
        self.loadServices = loadServices
        self.relockServices = relockServices
        self.contentClearHandler = contentClearHandler
        self.operationPromptInProgressProvider = operationPromptInProgressProvider
        self.waitForAwayRelockDeadline = waitForAwayRelockDeadline
        lockState = vault.hasSealedRoot ? .locked : .setupRequired
    }

    var isLocked: Bool {
        lockState != .unlocked
    }

    var isUnlocking: Bool {
        lockState == .unlocking
    }

    var acceptsPassphrase: Bool {
        switch lockState {
        case .locked, .failed, .setupRequired: true
        case .unlocking, .unlocked, .integrityFailure, .restartRequired: false
        }
    }

    var isCosmeticallyCovered: Bool {
        !isForegroundActive || isResolvingForegroundLock
    }

    // MARK: - Setup and unlock

    /// First run: creates the vault under `passphrase` and opens it.
    func createVault(passphrase: consuming SensitiveBuffer) async {
        guard lockState == .setupRequired else { return }
        let generation = awayGeneration
        setLockState(.unlocking)
        do {
            try await vault.bootstrap(passphrase: passphrase, reason: Self.localizedSetupReason)
        } catch let error as VaultError {
            vault.relock()
            setLockState(vault.hasSealedRoot ? .failed(UnlockFailure(error)) : .setupRequired)
            setupFailure = UnlockFailure(error)
            return
        } catch {
            vault.relock()
            setLockState(.setupRequired)
            setupFailure = .other(error.localizedDescription)
            return
        }
        setupFailure = nil
        recordSuccessfulAuthentication()
        await loadServices()
        guard generation == awayGeneration else {
            await enterLocked()
            return
        }
        handledAwayGeneration = awayGeneration
        setLockState(.unlocked)
    }

    /// Why the last setup attempt did not produce a vault.
    private(set) var setupFailure: UnlockFailure?

    /// Unlocks with `passphrase`; the presence prompt is the enclave's.
    func unlock(passphrase: consuming SensitiveBuffer) async {
        guard acceptsPassphrase, lockState != .setupRequired else { return }
        let generation = awayGeneration
        handledAwayGeneration = generation
        setLockState(.unlocking)
        contentClearHandler()
        await relockEverything()
        let attempt = self.attempt ?? vault.beginUnlock(reason: Self.localizedUnlockReason)
        self.attempt = attempt
        let session: UnlockedSession
        do {
            session = try await attempt.submit(passphrase: passphrase)
        } catch {
            let failure = UnlockFailure(error)
            if !failure.keepsAttempt {
                discardAttempt()
            }
            guard generation == awayGeneration else {
                if lockState == .unlocking { setLockState(.locked) }
                return
            }
            setLockState(.failed(failure))
            return
        }
        discardAttempt()
        guard generation == awayGeneration else {
            session.relock()
            setLockState(.locked)
            return
        }
        recordSuccessfulAuthentication()
        let report = vault.adopt(session: session)
        await loadServices()
        guard generation == awayGeneration else {
            await enterLocked()
            return
        }
        if report.isIntact {
            setLockState(.unlocked)
            if !isForegroundActive {
                armAwayRelock()
            }
        } else {
            setLockState(.integrityFailure(report))
        }
    }

    /// Reseals the root under `new`. The current passphrase and the presence
    /// prompt gate it; a cancelled prompt leaves the old passphrase in force.
    func changePassphrase(current: consuming SensitiveBuffer, new: consuming SensitiveBuffer) async throws {
        guard lockState == .unlocked else { throw VaultError.locked }
        try await vault.changePassphrase(current: current, new: new, reason: Self.localizedChangePassphraseReason)
    }

    /// A vault sealed by something other than `createVault`: the test hosts.
    func noteVaultReady() {
        guard lockState == .setupRequired, vault.hasSealedRoot else { return }
        setLockState(.locked)
    }

    /// A session opened without a prompt: the sandbox and the test hosts.
    func noteSessionOpened() {
        awayGeneration &+= 1
        handledAwayGeneration = awayGeneration
        setLockState(.unlocked)
    }

    /// After Reset All Local Data: no vault, no session.
    func resetAfterLocalDataReset() {
        awayGeneration &+= 1
        #if os(macOS)
        hasPendingOperationPromptAway = false
        #endif
        disarmAwayRelock()
        discardAttempt()
        setLockState(.setupRequired)
    }

    // MARK: - Foreground and away

    func noteForegroundActive(_ active: Bool) {
        guard isForegroundActive != active else {
            return
        }
        isForegroundActive = active
        if active {
            disarmAwayRelock()
            isResolvingForegroundLock = true
        }
    }

    func handleAwayEvent() {
        #if os(macOS)
        if isUnlocking {
            return
        }
        if isOperationPromptInProgressForAwayRule {
            hasPendingOperationPromptAway = true
            return
        }
        #endif
        awayGeneration &+= 1
        discardAttempt()
        guard lockState == .unlocked else {
            return
        }
        guard effectiveGracePeriod() == 0 else {
            armAwayRelock()
            return
        }
        Task { await enterLocked() }
    }

    func handleForegroundActive() async {
        defer { isResolvingForegroundLock = false }
        guard isForegroundActive, lockState == .unlocked else {
            return
        }
        if let handled = handledAwayGeneration, handled == awayGeneration {
            return
        }
        if isGracePeriodExpired {
            await enterLocked()
        } else {
            handledAwayGeneration = awayGeneration
        }
    }

    func lockNow() {
        #if os(macOS)
        hasPendingOperationPromptAway = false
        #endif
        disarmAwayRelock()
        Task { await enterLocked() }
    }

    func handleOperationPromptSessionBegan() {
        #if os(macOS)
        openOperationPromptSessions += 1
        #endif
    }

    func handleOperationPromptsEnded() {
        #if os(macOS)
        if openOperationPromptSessions > 0 {
            openOperationPromptSessions -= 1
        }
        guard hasPendingOperationPromptAway else {
            return
        }
        hasPendingOperationPromptAway = false
        guard lockState == .unlocked, !isForegroundActive else {
            return
        }
        handleAwayEvent()
        #endif
    }

    #if os(macOS)
    private var isOperationPromptInProgressForAwayRule: Bool {
        if let operationPromptInProgressProvider {
            return operationPromptInProgressProvider()
        }
        return openOperationPromptSessions > 0
    }
    #endif

    private func armAwayRelock() {
        #if os(macOS)
        disarmAwayRelock()
        guard lockState == .unlocked else {
            return
        }
        let secondsRemaining = max(graceDeadline.timeIntervalSinceNow, 0)
        awayRelockTask = Task { [weak self] in
            guard let wait = self?.waitForAwayRelockDeadline else {
                return
            }
            do {
                try await wait(secondsRemaining)
            } catch {
                return
            }
            guard !Task.isCancelled else {
                return
            }
            self?.handleAwayRelockDeadline()
        }
        #endif
    }

    private func disarmAwayRelock() {
        #if os(macOS)
        awayRelockTask?.cancel()
        awayRelockTask = nil
        #endif
    }

    private func handleAwayRelockDeadline() {
        #if os(macOS)
        awayRelockTask = nil
        guard !isForegroundActive, lockState == .unlocked else {
            return
        }
        guard isGracePeriodExpired else {
            armAwayRelock()
            return
        }
        Task { await enterLocked() }
        #endif
    }

    // MARK: - Locking

    private func enterLocked() async {
        #if os(macOS)
        hasPendingOperationPromptAway = false
        #endif
        disarmAwayRelock()
        awayGeneration &+= 1
        discardAttempt()
        contentClearHandler()
        await relockEverything()
        guard lockState != .restartRequired else { return }
        setLockState(vault.hasSealedRoot ? .locked : .setupRequired)
    }

    /// Drops every service's session state, then the vault's. A service that
    /// cannot let go leaves the process unusable until it restarts.
    private func relockEverything() async {
        do {
            try await relockServices()
        } catch {
            vault.relock()
            setLockState(.restartRequired)
            return
        }
        vault.relock()
    }

    private func discardAttempt() {
        attempt?.cancel()
        attempt = nil
    }

    private func effectiveGracePeriod() -> Int {
        gracePeriodProvider() ?? 0
    }

    private var graceDeadline: Date {
        guard let lastAuthenticationDate = lastAuthenticationDateProvider() else {
            return .distantPast
        }
        return lastAuthenticationDate.addingTimeInterval(TimeInterval(effectiveGracePeriod()))
    }

    private var isGracePeriodExpired: Bool {
        Date() > graceDeadline
    }

    private func setLockState(_ newState: LockState) {
        guard newState != lockState else {
            return
        }
        lockState = newState
        transitionGeneration &+= 1
    }

    private static var localizedUnlockReason: String {
        String(localized: "vault.unlock.reason", defaultValue: "Unlock CypherAir X")
    }

    private static var localizedChangePassphraseReason: String {
        String(localized: "vault.changePassphrase.reason", defaultValue: "Change the CypherAir X passphrase")
    }

    private static var localizedSetupReason: String {
        String(localized: "vault.setup.reason", defaultValue: "Create the CypherAir X vault")
    }
}
