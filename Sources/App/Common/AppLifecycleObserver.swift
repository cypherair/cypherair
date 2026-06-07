import SwiftUI
#if canImport(AppKit)
import AppKit
#endif

/// The single owner of the platform lifecycle signal (P1 of the auth-lifecycle
/// redesign). It translates the platform's unambiguous away/foreground events into
/// (a) the cosmetic-cover `isForegroundActive` binding and (b) `AppLockController`
/// away/foreground calls.
///
/// Per-platform away-event rule (TARGET §3):
/// - iOS / iPadOS / visionOS: away = `ScenePhase.background` ONLY. A biometric
///   prompt yields `.inactive` (cover only), never `.background`, so it is never an
///   away event — this is how grace=0 "no double-auth" is preserved structurally,
///   without the deleted disambiguation gate/settle/union.
/// - macOS: away = app-resign ∪ screen-lock ∪ explicit "Lock Now". (In the P1
///   interim the detached system auth sheet still resigns the app; the controller's
///   in-flight-auth guard absorbs that for app-session unlock. Per-operation
///   private-key prompts regress until P3 moves macOS auth in-window — accepted per
///   ROADMAP §6.)
struct AppLifecycleObserverModifier: ViewModifier {
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.authLifecycleTraceStore) private var authLifecycleTraceStore
    let appLockController: AppLockController
    @Binding var isForegroundActive: Bool

    func body(content: Content) -> some View {
        content
        #if canImport(UIKit)
            .onChange(of: scenePhase) { _, newPhase in
                authLifecycleTraceStore?.record(
                    category: .lifecycle,
                    name: "observer.scenePhase",
                    metadata: ["phase": Self.scenePhaseName(newPhase)]
                )
                switch newPhase {
                case .active:
                    isForegroundActive = true
                    Task { await appLockController.handleForegroundActive(source: "scenePhase.active") }
                case .inactive:
                    // Cover only — a biometric prompt produces `.inactive`, which is
                    // never an away event.
                    isForegroundActive = false
                case .background:
                    isForegroundActive = false
                    appLockController.handleAwayEvent(source: "scenePhase.background")
                @unknown default:
                    break
                }
            }
        #elseif os(macOS)
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
                authLifecycleTraceStore?.record(category: .lifecycle, name: "observer.macResign")
                isForegroundActive = false
                appLockController.handleAwayEvent(source: "macResignActive")
            }
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
                authLifecycleTraceStore?.record(category: .lifecycle, name: "observer.macActive")
                isForegroundActive = true
                Task { await appLockController.handleForegroundActive(source: "macBecomeActive") }
            }
            .onReceive(
                DistributedNotificationCenter.default().publisher(for: Notification.Name("com.apple.screenIsLocked"))
            ) { _ in
                authLifecycleTraceStore?.record(category: .lifecycle, name: "observer.screenLock")
                isForegroundActive = false
                appLockController.lockNow(source: "screenLock")
            }
        #endif
    }

    #if canImport(UIKit)
    private static func scenePhaseName(_ phase: ScenePhase) -> String {
        switch phase {
        case .active:
            "active"
        case .inactive:
            "inactive"
        case .background:
            "background"
        @unknown default:
            "unknown"
        }
    }
    #endif
}

extension View {
    /// Observe the platform lifecycle and drive the cosmetic cover + `AppLockController`.
    func appLifecycleObserver(
        appLockController: AppLockController,
        isForegroundActive: Binding<Bool>
    ) -> some View {
        modifier(
            AppLifecycleObserverModifier(
                appLockController: appLockController,
                isForegroundActive: isForegroundActive
            )
        )
    }
}
