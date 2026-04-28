import SwiftUI
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

private struct AuthenticationShieldCoordinatorKey: EnvironmentKey {
    static let defaultValue: AuthenticationShieldCoordinator? = nil
}

extension EnvironmentValues {
    var authenticationShieldCoordinator: AuthenticationShieldCoordinator? {
        get { self[AuthenticationShieldCoordinatorKey.self] }
        set { self[AuthenticationShieldCoordinatorKey.self] = newValue }
    }
}

private struct AuthenticationShieldHostModifier: ViewModifier {
    let explicitCoordinator: AuthenticationShieldCoordinator?
    let handlesLifecycleEvents: Bool

    @Environment(\.authenticationShieldCoordinator) private var environmentCoordinator
    @Environment(\.scenePhase) private var scenePhase

    private var coordinator: AuthenticationShieldCoordinator? {
        explicitCoordinator ?? environmentCoordinator
    }

    func body(content: Content) -> some View {
        let coordinator = coordinator
        let presentationState = coordinator?.presentationState

        let base = ZStack {
            content

            if let coordinator,
               let presentationState {
                AuthenticationShieldView(presentationState: presentationState)
                    .zIndex(10)
                    .transition(.asymmetric(insertion: .identity, removal: .opacity))
                    .onAppear {
                        coordinator.noteRenderVisible(presentationState)
                    }
                    .onDisappear {
                        coordinator.noteRenderHidden()
                    }
            }
        }
        .animation(
            presentationState == nil ? .easeOut(duration: AuthenticationShieldAnimation.overlayDismissalDuration) : nil,
            value: presentationState
        )

        if handlesLifecycleEvents {
            lifecycleAwareBody(base)
        } else {
            base
        }
    }

    @ViewBuilder
    private func lifecycleAwareBody<Content: View>(_ content: Content) -> some View {
        #if canImport(UIKit)
        content
            .onChange(of: scenePhase) { _, newPhase in
                guard let coordinator else { return }
                switch newPhase {
                case .active:
                    coordinator.sceneDidBecomeActive()
                case .inactive:
                    coordinator.sceneDidResignActive()
                case .background:
                    coordinator.sceneDidEnterBackground()
                @unknown default:
                    break
                }
            }
        #elseif os(macOS)
        content
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
                coordinator?.sceneDidBecomeActive()
            }
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
                coordinator?.sceneDidResignActive()
            }
        #else
        content
        #endif
    }
}

private struct AuthenticationShieldView: View {
    let presentationState: AuthenticationShieldPresentationState

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var cardIsPresented = false
    @State private var breathingGlowIsActive = false

    var body: some View {
        ZStack {
            Rectangle()
                .fill(.ultraThinMaterial)
                .ignoresSafeArea()

            AuthenticationShieldCard(
                iconName: iconName,
                isPendingDismissal: presentationState.isPendingDismissal,
                reduceMotion: reduceMotion,
                cardIsPresented: cardIsPresented,
                breathingGlowIsActive: breathingGlowIsActive
            )
            .padding(24)
            .allowsHitTesting(!presentationState.isPendingDismissal)
            .accessibilityElement(children: .combine)
            .accessibilityLabel(
                String(localized: "authShield.a11y.label", defaultValue: "Authentication in progress")
            )
            .accessibilityValue(
                String(localized: "authShield.a11y.value", defaultValue: "Secure content is hidden")
            )
        }
        .onAppear {
            prepareEntranceAnimation()
        }
        .onChange(of: presentationState.isPendingDismissal) { _, _ in
            updateBreathingGlow()
        }
        .onChange(of: reduceMotion) { _, _ in
            prepareEntranceAnimation()
        }
    }

    private var iconName: String {
        #if os(macOS)
        "touchid"
        #elseif os(visionOS)
        "opticid"
        #else
        "faceid"
        #endif
    }

    private func prepareEntranceAnimation() {
        breathingGlowIsActive = false

        guard !reduceMotion else {
            cardIsPresented = true
            return
        }

        cardIsPresented = false
        updateCardPresentation()
        updateBreathingGlow()
    }

    private func updateCardPresentation() {
        guard !reduceMotion else {
            cardIsPresented = true
            return
        }

        withAnimation(
            .spring(
                response: AuthenticationShieldAnimation.cardEntranceResponse,
                dampingFraction: AuthenticationShieldAnimation.cardEntranceDamping
            )
        ) {
            cardIsPresented = true
        }
    }

    private func updateBreathingGlow() {
        guard !reduceMotion else {
            breathingGlowIsActive = false
            return
        }

        if presentationState.isPendingDismissal {
            withAnimation(.easeOut(duration: AuthenticationShieldAnimation.breathingGlowSettleDuration)) {
                breathingGlowIsActive = false
            }
        } else {
            withAnimation(
                .easeInOut(duration: AuthenticationShieldAnimation.breathingGlowDuration)
                    .repeatForever(autoreverses: true)
            ) {
                breathingGlowIsActive = true
            }
        }
    }
}

private struct AuthenticationShieldCard: View {
    let iconName: String
    let isPendingDismissal: Bool
    let reduceMotion: Bool
    let cardIsPresented: Bool
    let breathingGlowIsActive: Bool

    private var isActivelyAuthenticating: Bool {
        cardIsPresented && !isPendingDismissal
    }

    var body: some View {
        VStack(spacing: 18) {
            AuthenticationShieldIcon(
                iconName: iconName,
                isActivelyAuthenticating: isActivelyAuthenticating,
                reduceMotion: reduceMotion,
                breathingGlowIsActive: breathingGlowIsActive
            )

            VStack(spacing: 6) {
                Text(String(localized: "authShield.title", defaultValue: "Authenticating…"))
                    .font(.headline)
                    .foregroundStyle(.primary)

                Text(String(localized: "authShield.subtitle", defaultValue: "Secure content is temporarily hidden"))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }

            ProgressView()
                .tint(.primary)
                .opacity(isPendingDismissal ? 0.4 : 1)
        }
        .padding(.horizontal, 28)
        .padding(.vertical, 24)
        .frame(maxWidth: 320)
        .background(
            .regularMaterial,
            in: RoundedRectangle(cornerRadius: 24, style: .continuous)
        )
        .overlay {
            AuthenticationShieldCardStroke(
                isActivelyAuthenticating: isActivelyAuthenticating,
                reduceMotion: reduceMotion,
                breathingGlowIsActive: breathingGlowIsActive
            )
        }
        .shadow(
            color: Color.accentColor.opacity(isActivelyAuthenticating && !reduceMotion ? 0.12 : 0),
            radius: breathingGlowIsActive ? 24 : 12,
            y: 8
        )
        .shadow(color: Color.black.opacity(0.08), radius: 18, y: 8)
        .opacity(cardIsPresented ? 1 : 0)
        .scaleEffect(cardIsPresented ? 1 : 0.97)
        .blur(radius: reduceMotion || cardIsPresented ? 0 : 3)
    }
}

private struct AuthenticationShieldIcon: View {
    let iconName: String
    let isActivelyAuthenticating: Bool
    let reduceMotion: Bool
    let breathingGlowIsActive: Bool

    private var glowScale: CGFloat {
        breathingGlowIsActive ? 1.08 : 0.96
    }

    private var glowOpacity: Double {
        if reduceMotion {
            return isActivelyAuthenticating ? 0.24 : 0.12
        }
        return breathingGlowIsActive ? 0.34 : 0.16
    }

    var body: some View {
        ZStack {
            Circle()
                .fill(
                    RadialGradient(
                        colors: [
                            Color.accentColor.opacity(glowOpacity),
                            Color.accentColor.opacity(glowOpacity * 0.34),
                            Color.accentColor.opacity(0)
                        ],
                        center: .center,
                        startRadius: 12,
                        endRadius: 52
                    )
                )
                .frame(width: 104, height: 104)
                .scaleEffect(reduceMotion ? 1 : glowScale)
                .opacity(isActivelyAuthenticating || reduceMotion ? 1 : 0.34)

            Circle()
                .fill(.thinMaterial)
                .frame(width: 78, height: 78)
                .overlay {
                    Circle()
                        .stroke(Color.primary.opacity(0.08), lineWidth: 1)
                }
                .shadow(
                    color: Color.accentColor.opacity(glowOpacity * 0.54),
                    radius: breathingGlowIsActive && !reduceMotion ? 16 : 8
                )

            Image(systemName: iconName)
                .font(.system(size: 38, weight: .medium))
                .foregroundStyle(.primary)
                .if(isActivelyAuthenticating && !reduceMotion) { view in
                    view.symbolEffect(.pulse, options: .repeating)
                }
        }
    }
}

private struct AuthenticationShieldCardStroke: View {
    let isActivelyAuthenticating: Bool
    let reduceMotion: Bool
    let breathingGlowIsActive: Bool

    private var glowOpacity: Double {
        guard isActivelyAuthenticating else {
            return reduceMotion ? 0.08 : 0
        }
        guard !reduceMotion else {
            return 0.18
        }
        return breathingGlowIsActive ? 0.26 : 0.12
    }

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: 24, style: .continuous)

        ZStack {
            shape
                .stroke(Color.primary.opacity(0.08), lineWidth: 1)

            if glowOpacity > 0 {
                shape
                    .stroke(
                        RadialGradient(
                            colors: [
                                Color.accentColor.opacity(glowOpacity),
                                Color.accentColor.opacity(glowOpacity * 0.48),
                                Color.accentColor.opacity(0)
                            ],
                            center: .center,
                            startRadius: 48,
                            endRadius: 220
                        ),
                        lineWidth: 1.2
                    )
                    .shadow(
                        color: Color.accentColor.opacity(glowOpacity),
                        radius: breathingGlowIsActive && !reduceMotion ? 16 : 8
                    )
            }
        }
    }
}

private enum AuthenticationShieldAnimation {
    static let cardEntranceResponse = 0.34
    static let cardEntranceDamping = 0.84
    static let overlayDismissalDuration = 0.26
    static let breathingGlowDuration = 1.8
    static let breathingGlowSettleDuration = 0.24
}

extension View {
    func authenticationShieldHost(
        _ coordinator: AuthenticationShieldCoordinator? = nil,
        handlesLifecycleEvents: Bool = false
    ) -> some View {
        modifier(
            AuthenticationShieldHostModifier(
                explicitCoordinator: coordinator,
                handlesLifecycleEvents: handlesLifecycleEvents
            )
        )
    }
}

private extension View {
    @ViewBuilder
    func `if`<Content: View>(
        _ condition: Bool,
        transform: (Self) -> Content
    ) -> some View {
        if condition {
            transform(self)
        } else {
            self
        }
    }
}
