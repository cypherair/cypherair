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
}

@Observable
final class AuthenticationShieldCoordinator: @unchecked Sendable {
    private let traceStore: AuthLifecycleTraceStore?
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

    init(traceStore: AuthLifecycleTraceStore? = nil) {
        self.traceStore = traceStore
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
        }
    }

    private func scheduleFallbackDismissalIfNeeded(for cycleID: UInt64) {
        guard isPendingDismissal, lastLifecyclePhase == .active else { return }

        cancelDismissalFallback()
        tracePendingDismissalFallbackScheduled(for: cycleID)
        dismissalFallbackTask = Task { @MainActor [weak self] in
            await Task.yield()
            guard !Task.isCancelled else { return }
            self?.tracePendingDismissalFallbackFired(for: cycleID)
            self?.completePendingDismissalIfEligible(for: cycleID, reason: .fallbackYield)
        }
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

    private func tracePendingDismissalFallbackScheduled(for cycleID: UInt64) {
        traceStore?.record(
            category: .lifecycle,
            name: "shield.pendingDismissal.fallbackScheduled",
            metadata: [
                "cycle": String(cycleID),
                "lastLifecyclePhase": lastLifecyclePhase.rawValue
            ]
        )
    }

    private func tracePendingDismissalFallbackFired(for cycleID: UInt64) {
        traceStore?.record(
            category: .lifecycle,
            name: "shield.pendingDismissal.fallbackFired",
            metadata: [
                "cycle": String(cycleID),
                "elapsedMs": pendingDismissalElapsedMilliseconds()
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
    @State private var accentSweepIsActive = false

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
                accentSweepIsActive: accentSweepIsActive
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
            updateCardPresentation()
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
        accentSweepIsActive = false

        guard !reduceMotion else {
            cardIsPresented = !presentationState.isPendingDismissal
            return
        }

        cardIsPresented = false
        updateCardPresentation()

        guard !presentationState.isPendingDismissal else {
            return
        }
        withAnimation(.linear(duration: AuthenticationShieldAnimation.accentSweepDuration).repeatForever(autoreverses: false)) {
            accentSweepIsActive = true
        }
    }

    private func updateCardPresentation() {
        let shouldPresentCard = !presentationState.isPendingDismissal

        guard !reduceMotion else {
            cardIsPresented = shouldPresentCard
            return
        }

        let animation: Animation = shouldPresentCard
            ? .spring(
                response: AuthenticationShieldAnimation.cardEntranceResponse,
                dampingFraction: AuthenticationShieldAnimation.cardEntranceDamping
            )
            : .easeOut(duration: AuthenticationShieldAnimation.cardDismissalDuration)

        withAnimation(animation) {
            cardIsPresented = shouldPresentCard
        }
    }
}

private struct AuthenticationShieldCard: View {
    let iconName: String
    let isPendingDismissal: Bool
    let reduceMotion: Bool
    let cardIsPresented: Bool
    let accentSweepIsActive: Bool

    private var isActivelyAuthenticating: Bool {
        cardIsPresented && !isPendingDismissal
    }

    var body: some View {
        VStack(spacing: 18) {
            AuthenticationShieldIcon(
                iconName: iconName,
                isActivelyAuthenticating: isActivelyAuthenticating,
                reduceMotion: reduceMotion,
                accentSweepIsActive: accentSweepIsActive
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
                accentSweepIsActive: accentSweepIsActive
            )
        }
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
    let accentSweepIsActive: Bool

    var body: some View {
        ZStack {
            Circle()
                .fill(.thinMaterial)
                .frame(width: 78, height: 78)
                .overlay {
                    Circle()
                        .stroke(Color.primary.opacity(0.08), lineWidth: 1)
                }

            if isActivelyAuthenticating && !reduceMotion {
                Circle()
                    .trim(from: 0.08, to: 0.34)
                    .stroke(
                        AngularGradient(
                            colors: [
                                Color.accentColor.opacity(0),
                                Color.accentColor.opacity(0.55),
                                Color.primary.opacity(0.18),
                                Color.accentColor.opacity(0)
                            ],
                            center: .center
                        ),
                        style: StrokeStyle(lineWidth: 2, lineCap: .round)
                    )
                    .frame(width: 78, height: 78)
                    .rotationEffect(.degrees(accentSweepIsActive ? 360 : 0))
            }

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
    let accentSweepIsActive: Bool

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: 24, style: .continuous)

        ZStack {
            shape
                .stroke(Color.primary.opacity(0.08), lineWidth: 1)

            if isActivelyAuthenticating && !reduceMotion {
                shape
                    .stroke(
                        LinearGradient(
                            colors: [
                                Color.accentColor.opacity(0.34),
                                Color.primary.opacity(0.1),
                                Color.accentColor.opacity(0.04)
                            ],
                            startPoint: accentSweepIsActive ? .topLeading : .bottomTrailing,
                            endPoint: accentSweepIsActive ? .bottomTrailing : .topLeading
                        ),
                        lineWidth: 1.2
                    )
                    .opacity(0.85)
            }
        }
    }
}

private enum AuthenticationShieldAnimation {
    static let cardEntranceResponse = 0.34
    static let cardEntranceDamping = 0.84
    static let cardDismissalDuration = 0.22
    static let overlayDismissalDuration = 0.26
    static let accentSweepDuration = 2.4
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
