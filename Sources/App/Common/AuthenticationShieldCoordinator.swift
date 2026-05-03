import Foundation
#if canImport(AppKit)
import AppKit
#endif

enum AuthenticationShieldKind: String, Equatable, Hashable {
    case privacy
    case operation
}

struct AuthenticationShieldPresentationState: Equatable {
    let primaryKind: AuthenticationShieldKind
    let activeKinds: Set<AuthenticationShieldKind>
    let isPendingDismissal: Bool
}

private enum AuthenticationShieldLifecyclePhase: String, Equatable {
    case active
    case inactive
    case background
}

private enum AuthenticationShieldDismissalCompletionReason: String {
    case lifecycleSettle
    case fallbackYield
    case activeProbe
}

@Observable
final class AuthenticationShieldCoordinator: @unchecked Sendable {
    private let traceStore: AuthLifecycleTraceStore?
    private let macOSApplicationIsActive: @MainActor () -> Bool
    private var privacyPromptDepth = 0
    private var operationPromptDepth = 0
    private var isPendingDismissal = false
    private var promptCycleID: UInt64 = 0
    private var lastVisiblePrimaryKind: AuthenticationShieldKind?
    private var lastLifecyclePhase: AuthenticationShieldLifecyclePhase = .active
    private var observedNonActiveLifecycleInCurrentCycle = false
    private var dismissalFallbackTask: Task<Void, Never>?
    private var pendingDismissalStartedAt: Date?
    private var pendingDismissalCycleID: UInt64?
    private var lastDismissalCompletedAt: Date?
    private var lastDismissalCompletedCycleID: UInt64?
    private var lastDismissalElapsedMilliseconds: String?

    init(
        traceStore: AuthLifecycleTraceStore? = nil,
        macOSApplicationIsActive: @escaping @MainActor () -> Bool = AuthenticationShieldCoordinator.defaultMacOSApplicationIsActive
    ) {
        self.traceStore = traceStore
        self.macOSApplicationIsActive = macOSApplicationIsActive
    }

    var isVisible: Bool {
        totalPromptDepth > 0 || isPendingDismissal
    }

    var presentationState: AuthenticationShieldPresentationState? {
        let activeKinds = activeKinds
        let primaryKind: AuthenticationShieldKind
        if let activePrimaryKind = activePrimaryKind(for: activeKinds) {
            primaryKind = activePrimaryKind
        } else if isPendingDismissal, let lastVisiblePrimaryKind {
            primaryKind = lastVisiblePrimaryKind
        } else {
            return nil
        }

        return AuthenticationShieldPresentationState(
            primaryKind: primaryKind,
            activeKinds: activeKinds,
            isPendingDismissal: isPendingDismissal
        )
    }

    func begin(_ kind: AuthenticationShieldKind) {
        if totalPromptDepth == 0 {
            if isPendingDismissal {
                tracePendingDismissalCancellation(reason: "newPrompt", cycleID: promptCycleID)
            }
            promptCycleID &+= 1
            isPendingDismissal = false
            observedNonActiveLifecycleInCurrentCycle = false
            clearPendingDismissalTiming()
            cancelDismissalFallback()
        }
        adjustDepth(for: kind, delta: 1)
        refreshLastVisiblePrimaryKind()
        traceShieldPromptEvent(name: "shield.begin", kind: kind)
    }

    func end(_ kind: AuthenticationShieldKind) {
        adjustDepth(for: kind, delta: -1)
        traceShieldPromptEvent(name: "shield.end", kind: kind)
        if totalPromptDepth == 0 {
            isPendingDismissal = true
            pendingDismissalStartedAt = Date()
            pendingDismissalCycleID = promptCycleID
            tracePendingDismissalStart(for: promptCycleID)
            scheduleFallbackDismissalIfNeeded(for: promptCycleID)
        } else {
            refreshLastVisiblePrimaryKind()
        }
    }

    func sceneDidBecomeActive() {
        noteLifecyclePhase(.active)
    }

    func sceneDidResignActive() {
        noteLifecyclePhase(.inactive)
    }

    func sceneDidEnterBackground() {
        noteLifecyclePhase(.background)
    }

    func noteRenderVisible(_ presentationState: AuthenticationShieldPresentationState) {
        traceStore?.record(
            category: .lifecycle,
            name: "shield.render.visible",
            metadata: [
                "cycle": String(promptCycleID),
                "pending": presentationState.isPendingDismissal ? "true" : "false",
                "primaryKind": presentationState.primaryKind.rawValue,
                "activeKinds": presentationState.activeKinds.map(\.rawValue).sorted().joined(separator: ",")
            ]
        )
    }

    func noteRenderHidden() {
        traceStore?.record(
            category: .lifecycle,
            name: "shield.render.hidden",
            metadata: [
                "cycle": String(promptCycleID),
                "pending": isPendingDismissal ? "true" : "false",
                "elapsedSincePendingDismissalMs": pendingDismissalElapsedMilliseconds(),
                "lastDismissalCycle": lastDismissalCompletedCycleID.map(String.init) ?? "none",
                "lastDismissalElapsedMs": lastDismissalElapsedMilliseconds ?? "none",
                "elapsedSinceDismissalCompleteMs": dismissalCompletionToRenderHiddenElapsedMilliseconds()
            ]
        )
    }

    private var activeKinds: Set<AuthenticationShieldKind> {
        var result: Set<AuthenticationShieldKind> = []
        if privacyPromptDepth > 0 {
            result.insert(.privacy)
        }
        if operationPromptDepth > 0 {
            result.insert(.operation)
        }
        return result
    }

    private var totalPromptDepth: Int {
        privacyPromptDepth + operationPromptDepth
    }

    private func adjustDepth(for kind: AuthenticationShieldKind, delta: Int) {
        switch kind {
        case .privacy:
            privacyPromptDepth = max(privacyPromptDepth + delta, 0)
        case .operation:
            operationPromptDepth = max(operationPromptDepth + delta, 0)
        }
    }

    private func noteLifecyclePhase(_ phase: AuthenticationShieldLifecyclePhase) {
        lastLifecyclePhase = phase
        traceLifecycleObservation(phase)

        switch phase {
        case .active:
            guard isPendingDismissal else { return }
            if observedNonActiveLifecycleInCurrentCycle {
                completePendingDismissalIfEligible(for: promptCycleID, reason: .lifecycleSettle)
            } else {
                scheduleFallbackDismissalIfNeeded(for: promptCycleID)
            }
        case .inactive, .background:
            observedNonActiveLifecycleInCurrentCycle = true
            cancelDismissalFallback()
            if isPendingDismissal {
                scheduleFallbackDismissalIfNeeded(for: promptCycleID)
            }
        }
    }

    private func scheduleFallbackDismissalIfNeeded(for cycleID: UInt64) {
        guard isPendingDismissal else { return }

        cancelDismissalFallback()

        switch lastLifecyclePhase {
        case .active:
            tracePendingDismissalFallbackScheduled(for: cycleID, reason: .fallbackYield)
            dismissalFallbackTask = Task { @MainActor [weak self] in
                await Task.yield()
                guard !Task.isCancelled else { return }
                self?.tracePendingDismissalFallbackFired(for: cycleID, reason: .fallbackYield)
                self?.completePendingDismissalIfEligible(for: cycleID, reason: .fallbackYield)
            }
        case .inactive:
            scheduleMacOSActiveProbeFallback(for: cycleID)
        case .background:
            break
        }
    }

    private func scheduleMacOSActiveProbeFallback(for cycleID: UInt64) {
        #if os(macOS)
        tracePendingDismissalFallbackScheduled(for: cycleID, reason: .activeProbe)
        dismissalFallbackTask = Task { @MainActor [weak self] in
            await Task.yield()
            guard !Task.isCancelled else { return }

            self?.tracePendingDismissalFallbackFired(for: cycleID, reason: .activeProbe)
            if self?.completePendingDismissalIfMacOSApplicationIsActive(for: cycleID, attempt: 1) == true {
                return
            }

            try? await Task.sleep(nanoseconds: 50_000_000)
            guard !Task.isCancelled else { return }

            self?.tracePendingDismissalFallbackFired(for: cycleID, reason: .activeProbe)
            _ = self?.completePendingDismissalIfMacOSApplicationIsActive(for: cycleID, attempt: 2)
        }
        #endif
    }

    @discardableResult
    @MainActor
    private func completePendingDismissalIfMacOSApplicationIsActive(for cycleID: UInt64, attempt: Int) -> Bool {
        #if os(macOS)
        let applicationActive = macOSApplicationIsActive()
        traceMacOSActiveProbeSample(
            for: cycleID,
            attempt: attempt,
            applicationActive: applicationActive
        )
        guard isPendingDismissal else { return false }
        guard promptCycleID == cycleID else { return false }
        guard totalPromptDepth == 0 else { return false }
        guard applicationActive else { return false }

        lastLifecyclePhase = .active
        completePendingDismissalIfEligible(for: cycleID, reason: .activeProbe)
        return !isPendingDismissal
        #else
        return false
        #endif
    }

    private func completePendingDismissalIfEligible(
        for cycleID: UInt64,
        reason: AuthenticationShieldDismissalCompletionReason
    ) {
        guard isPendingDismissal else { return }
        guard promptCycleID == cycleID else { return }
        guard totalPromptDepth == 0 else { return }
        guard lastLifecyclePhase == .active else { return }

        traceDismissalCompletion(for: cycleID, reason: reason)
        isPendingDismissal = false
        observedNonActiveLifecycleInCurrentCycle = false
        lastVisiblePrimaryKind = nil
        clearPendingDismissalTiming()
        cancelDismissalFallback()
    }

    private func cancelDismissalFallback() {
        dismissalFallbackTask?.cancel()
        dismissalFallbackTask = nil
    }

    private func refreshLastVisiblePrimaryKind() {
        if let activePrimaryKind = activePrimaryKind(for: activeKinds) {
            lastVisiblePrimaryKind = activePrimaryKind
        }
    }

    private func activePrimaryKind(for activeKinds: Set<AuthenticationShieldKind>) -> AuthenticationShieldKind? {
        if activeKinds.contains(.privacy) {
            return .privacy
        }
        if activeKinds.contains(.operation) {
            return .operation
        }
        return nil
    }

    private func clearPendingDismissalTiming() {
        pendingDismissalStartedAt = nil
        pendingDismissalCycleID = nil
    }

    private func pendingDismissalElapsedMilliseconds() -> String {
        guard let pendingDismissalStartedAt else {
            return "none"
        }
        return String(format: "%.3f", Date().timeIntervalSince(pendingDismissalStartedAt) * 1000)
    }

    private func dismissalCompletionToRenderHiddenElapsedMilliseconds() -> String {
        guard let lastDismissalCompletedAt else {
            return "none"
        }
        return String(format: "%.3f", Date().timeIntervalSince(lastDismissalCompletedAt) * 1000)
    }

    private func traceShieldPromptEvent(name: String, kind: AuthenticationShieldKind) {
        traceStore?.record(
            category: .prompt,
            name: name,
            metadata: [
                "cycle": String(promptCycleID),
                "kind": kind.rawValue,
                "operationDepth": String(operationPromptDepth),
                "privacyDepth": String(privacyPromptDepth),
                "totalDepth": String(totalPromptDepth)
            ]
        )
    }

    private func tracePendingDismissalStart(for cycleID: UInt64) {
        traceStore?.record(
            category: .lifecycle,
            name: "shield.pendingDismissal.start",
            metadata: [
                "cycle": String(cycleID),
                "lastLifecyclePhase": lastLifecyclePhase.rawValue,
                "primaryKind": lastVisiblePrimaryKind?.rawValue ?? "unknown"
            ]
        )
    }

    @MainActor
    private static func defaultMacOSApplicationIsActive() -> Bool {
        #if os(macOS)
        NSApplication.shared.isActive
        #else
        false
        #endif
    }

    private func tracePendingDismissalFallbackScheduled(
        for cycleID: UInt64,
        reason: AuthenticationShieldDismissalCompletionReason
    ) {
        traceStore?.record(
            category: .lifecycle,
            name: "shield.pendingDismissal.fallbackScheduled",
            metadata: [
                "cycle": String(cycleID),
                "lastLifecyclePhase": lastLifecyclePhase.rawValue,
                "reason": reason.rawValue
            ]
        )
    }

    private func tracePendingDismissalFallbackFired(
        for cycleID: UInt64,
        reason: AuthenticationShieldDismissalCompletionReason
    ) {
        traceStore?.record(
            category: .lifecycle,
            name: "shield.pendingDismissal.fallbackFired",
            metadata: [
                "cycle": String(cycleID),
                "elapsedMs": pendingDismissalElapsedMilliseconds(),
                "reason": reason.rawValue
            ]
        )
    }

    private func traceMacOSActiveProbeSample(
        for cycleID: UInt64,
        attempt: Int,
        applicationActive: Bool
    ) {
        traceStore?.record(
            category: .lifecycle,
            name: "shield.activeProbe.sample",
            metadata: [
                "applicationActive": applicationActive ? "true" : "false",
                "attempt": String(attempt),
                "cycle": String(cycleID),
                "currentCycle": String(promptCycleID),
                "lastLifecyclePhase": lastLifecyclePhase.rawValue,
                "pending": isPendingDismissal ? "true" : "false",
                "totalDepth": String(totalPromptDepth)
            ]
        )
    }

    private func tracePendingDismissalCancellation(reason: String, cycleID: UInt64) {
        traceStore?.record(
            category: .lifecycle,
            name: "shield.pendingDismissal.cancel",
            metadata: [
                "cycle": String(cycleID),
                "reason": reason
            ]
        )
    }

    private func traceLifecycleObservation(_ phase: AuthenticationShieldLifecyclePhase) {
        traceStore?.record(
            category: .lifecycle,
            name: "shield.lifecycle.observed",
            metadata: [
                "cycle": String(promptCycleID),
                "pending": isPendingDismissal ? "true" : "false",
                "phase": phase.rawValue
            ]
        )
    }

    private func traceDismissalCompletion(
        for cycleID: UInt64,
        reason: AuthenticationShieldDismissalCompletionReason
    ) {
        let elapsedMilliseconds: String
        let now = Date()
        if pendingDismissalCycleID == cycleID, let pendingDismissalStartedAt {
            elapsedMilliseconds = String(format: "%.3f", now.timeIntervalSince(pendingDismissalStartedAt) * 1000)
        } else {
            elapsedMilliseconds = "unknown"
        }
        lastDismissalCompletedAt = now
        lastDismissalCompletedCycleID = cycleID
        lastDismissalElapsedMilliseconds = elapsedMilliseconds

        traceStore?.record(
            category: .lifecycle,
            name: "shield.dismissal.complete",
            metadata: [
                "cycle": String(cycleID),
                "elapsedMs": elapsedMilliseconds,
                "reason": reason.rawValue
            ]
        )
    }

    deinit {
        dismissalFallbackTask?.cancel()
    }
}
