// THROWAWAY DIAGNOSTIC — do not commit. Probes the real LocalAuthentication
// embedded-UI behavior on this Mac to root-cause the PR-1 "Authentication
// denied" failure: does evaluateAccessControl fail fast when the paired
// LAAuthenticationView is not attached to a visible window?
#if os(macOS)
import AppKit
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import SwiftUI
import XCTest
@testable import CypherAir

final class InWindowAuthProbeTests: XCTestCase {
    private func report(_ label: String, _ error: Error) {
        let ns = error as NSError
        print("PROBE-RESULT \(label): domain=\(ns.domain) code=\(ns.code) desc=\(ns.localizedDescription) userInfo=\(ns.userInfo)")
    }

    @MainActor
    func test_probeA_pairedViewNeverAttached() async throws {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        let accessControl = try AuthenticationMode.standard.createAccessControl()
        let view = LAAuthenticationView(context: context)
        _ = view // paired, never attached to any window
        let watchdog = Task { @MainActor in
            try? await Task.sleep(nanoseconds: 5_000_000_000)
            print("PROBE-RESULT A: WATCHDOG fired (evaluation was pending) — invalidating")
            context.invalidate()
        }
        do {
            let ok = try await context.evaluateAccessControl(
                accessControl, operation: .useKeyKeyExchange, localizedReason: "probe A"
            )
            print("PROBE-RESULT A: returned \(ok) (unexpected success)")
        } catch {
            report("A(detached)", error)
        }
        watchdog.cancel()
    }

    @MainActor
    func test_probeB_pairedViewAttachedAndVisible() async throws {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        let accessControl = try AuthenticationMode.standard.createAccessControl()
        let view = LAAuthenticationView(context: context)
        let window = NSWindow(
            contentRect: NSRect(x: 300, y: 300, width: 280, height: 280),
            styleMask: [.titled], backing: .buffered, defer: false
        )
        window.contentView = view
        window.orderFrontRegardless()
        try await Task.sleep(nanoseconds: 500_000_000) // let it attach + draw
        let watchdog = Task { @MainActor in
            try? await Task.sleep(nanoseconds: 4_000_000_000)
            print("PROBE-RESULT B: WATCHDOG fired (evaluation armed and waiting) — invalidating")
            context.invalidate()
        }
        do {
            let ok = try await context.evaluateAccessControl(
                accessControl, operation: .useKeyKeyExchange, localizedReason: "probe B"
            )
            print("PROBE-RESULT B: returned \(ok)")
        } catch {
            report("B(attached+visible)", error)
        }
        watchdog.cancel()
        window.orderOut(nil)
    }

    @MainActor
    func test_probeD_pairedViewAttached_evaluatePolicyBiometrics() async throws {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        let view = LAAuthenticationView(context: context)
        let window = NSWindow(
            contentRect: NSRect(x: 300, y: 650, width: 280, height: 280),
            styleMask: [.titled], backing: .buffered, defer: false
        )
        window.contentView = view
        window.orderFrontRegardless()
        try await Task.sleep(nanoseconds: 300_000_000)
        let watchdog = Task { @MainActor in
            try? await Task.sleep(nanoseconds: 4_000_000_000)
            print("PROBE-RESULT D: WATCHDOG fired (policy evaluation armed and waiting) — invalidating")
            context.invalidate()
        }
        do {
            let ok = try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: "probe D"
            )
            print("PROBE-RESULT D: returned \(ok)")
        } catch {
            report("D(attached, evaluatePolicy)", error)
        }
        watchdog.cancel()
        window.orderOut(nil)
    }

    @MainActor
    func test_probeE_noPairedView_evaluateAccessControl_systemRoute() async throws {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        let accessControl = try AuthenticationMode.standard.createAccessControl()
        let watchdog = Task { @MainActor in
            try? await Task.sleep(nanoseconds: 4_000_000_000)
            print("PROBE-RESULT E: WATCHDOG fired (system-route evaluation armed) — invalidating")
            context.invalidate()
        }
        do {
            let ok = try await context.evaluateAccessControl(
                accessControl, operation: .useKeyKeyExchange, localizedReason: "probe E"
            )
            print("PROBE-RESULT E: returned \(ok)")
        } catch {
            report("E(no view, system route)", error)
        }
        watchdog.cancel()
    }

    @MainActor
    func test_probeF_systemSheet_resignActiveMeasurement() async throws {
        NSApp.activate()
        try await Task.sleep(nanoseconds: 700_000_000)
        let wasActive = NSApp.isActive
        var resignCount = 0
        var becomeCount = 0
        let resignToken = NotificationCenter.default.addObserver(
            forName: NSApplication.didResignActiveNotification, object: nil, queue: .main
        ) { _ in resignCount += 1 }
        let becomeToken = NotificationCenter.default.addObserver(
            forName: NSApplication.didBecomeActiveNotification, object: nil, queue: .main
        ) { _ in becomeCount += 1 }

        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        let watchdog = Task { @MainActor in
            try? await Task.sleep(nanoseconds: 4_000_000_000)
            print("PROBE-RESULT F: WATCHDOG fired — invalidating")
            context.invalidate()
        }
        do {
            let ok = try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: "probe F (system sheet, measuring resign)"
            )
            print("PROBE-RESULT F: evaluate returned \(ok)")
        } catch {
            report("F(system sheet)", error)
        }
        watchdog.cancel()
        try await Task.sleep(nanoseconds: 500_000_000)
        print("PROBE-RESULT F: wasActive=\(wasActive) isActiveNow=\(NSApp.isActive) resignCount=\(resignCount) becomeCount=\(becomeCount)")
        NotificationCenter.default.removeObserver(resignToken)
        NotificationCenter.default.removeObserver(becomeToken)
    }

    @MainActor
    func test_probeG_swiftUILocalAuthenticationView_evaluatePolicy() async throws {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        let view = LocalAuthenticationView("Probe G", context: context)
        let hosting = NSHostingView(rootView: view.frame(width: 220, height: 220))
        let window = NSWindow(
            contentRect: NSRect(x: 300, y: 300, width: 260, height: 260),
            styleMask: [.titled], backing: .buffered, defer: false
        )
        window.contentView = hosting
        window.orderFrontRegardless()
        try await Task.sleep(nanoseconds: 500_000_000)
        let watchdog = Task { @MainActor in
            try? await Task.sleep(nanoseconds: 4_000_000_000)
            print("PROBE-RESULT G: WATCHDOG fired (policy evaluation armed in SwiftUI view) — invalidating")
            context.invalidate()
        }
        do {
            let ok = try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: "probe G"
            )
            print("PROBE-RESULT G: returned \(ok)")
        } catch {
            report("G(SwiftUI view, evaluatePolicy)", error)
        }
        watchdog.cancel()
        window.orderOut(nil)
    }

    @MainActor
    func test_probeH_swiftUILocalAuthenticationView_evaluateAccessControl() async throws {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        let accessControl = try AuthenticationMode.standard.createAccessControl()
        let view = LocalAuthenticationView("Probe H", context: context)
        let hosting = NSHostingView(rootView: view.frame(width: 220, height: 220))
        let window = NSWindow(
            contentRect: NSRect(x: 650, y: 300, width: 260, height: 260),
            styleMask: [.titled], backing: .buffered, defer: false
        )
        window.contentView = hosting
        window.orderFrontRegardless()
        try await Task.sleep(nanoseconds: 500_000_000)
        let watchdog = Task { @MainActor in
            try? await Task.sleep(nanoseconds: 4_000_000_000)
            print("PROBE-RESULT H: WATCHDOG fired (access-control evaluation armed in SwiftUI view) — invalidating")
            context.invalidate()
        }
        do {
            let ok = try await context.evaluateAccessControl(
                accessControl, operation: .useKeyKeyExchange, localizedReason: "probe H"
            )
            print("PROBE-RESULT H: returned \(ok)")
        } catch {
            report("H(SwiftUI view, evaluateAccessControl)", error)
        }
        watchdog.cancel()
        window.orderOut(nil)
    }

    @MainActor
    func test_probeC_pairedViewAttachedEvaluateImmediately() async throws {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        let accessControl = try AuthenticationMode.standard.createAccessControl()
        let view = LAAuthenticationView(context: context)
        let window = NSWindow(
            contentRect: NSRect(x: 650, y: 300, width: 280, height: 280),
            styleMask: [.titled], backing: .buffered, defer: false
        )
        window.contentView = view
        window.orderFrontRegardless()
        // No settle delay — mimics production timing (evaluate right after mount).
        let watchdog = Task { @MainActor in
            try? await Task.sleep(nanoseconds: 4_000_000_000)
            print("PROBE-RESULT C: WATCHDOG fired (evaluation armed and waiting) — invalidating")
            context.invalidate()
        }
        do {
            let ok = try await context.evaluateAccessControl(
                accessControl, operation: .useKeyKeyExchange, localizedReason: "probe C"
            )
            print("PROBE-RESULT C: returned \(ok)")
        } catch {
            report("C(attached, immediate)", error)
        }
        watchdog.cancel()
        window.orderOut(nil)
    }
}
#endif
