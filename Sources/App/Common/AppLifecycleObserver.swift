import SwiftUI
#if canImport(AppKit)
import AppKit
#endif

/// The single owner of the platform lifecycle signal. It translates the platform's
/// unambiguous away/foreground events into
/// `AppLockController`'s foreground-active / away / foreground calls. The controller
/// owns the foreground-active state (the cosmetic cover reads it), so there is no
/// separate cover binding here.
///
/// Per-platform away-event rule:
/// - iOS / iPadOS / visionOS: away = `ScenePhase.background` ONLY. A biometric
///   prompt yields `.inactive` (cover only), never `.background`, so it is never an
///   away event — this is how grace=0 "no double-auth" holds structurally.
/// - macOS: away = app-resign ∪ screen-lock ∪ explicit "Lock Now", filtered by the
///   controller's `.authenticating` rule: a resign during an in-flight
///   app-session unlock is the auth sheet's own, and a resign during a private-key
///   operation prompt is deferred and decided when the prompts end. The observer
///   stays signal-only — every resign is still routed; the controller decides.
struct AppLifecycleObserverModifier: ViewModifier {
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.authLifecycleTraceStore) private var authLifecycleTraceStore
    let appLockController: AppLockController

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
                    appLockController.noteForegroundActive(true)
                    Task { await appLockController.handleForegroundActive(source: "scenePhase.active") }
                case .inactive:
                    // Cover only — a biometric prompt produces `.inactive`, which is
                    // never an away event.
                    appLockController.noteForegroundActive(false)
                case .background:
                    appLockController.noteForegroundActive(false)
                    appLockController.handleAwayEvent(source: "scenePhase.background")
                @unknown default:
                    break
                }
            }
        #elseif os(macOS)
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
                authLifecycleTraceStore?.record(category: .lifecycle, name: "observer.macResign")
                appLockController.noteForegroundActive(false)
                appLockController.handleAwayEvent(source: "macResignActive")
            }
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
                authLifecycleTraceStore?.record(category: .lifecycle, name: "observer.macActive")
                appLockController.noteForegroundActive(true)
                Task { await appLockController.handleForegroundActive(source: "macBecomeActive") }
            }
            .onReceive(
                DistributedNotificationCenter.default().publisher(for: Notification.Name("com.apple.screenIsLocked"))
            ) { _ in
                authLifecycleTraceStore?.record(category: .lifecycle, name: "observer.screenLock")
                appLockController.noteForegroundActive(false)
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
    /// Observe the platform lifecycle and drive `AppLockController`'s
    /// foreground-active / away / foreground state.
    func appLifecycleObserver(
        appLockController: AppLockController
    ) -> some View {
        modifier(
            AppLifecycleObserverModifier(
                appLockController: appLockController
            )
        )
    }
}
