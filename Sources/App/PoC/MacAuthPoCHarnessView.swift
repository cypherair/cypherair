#if DEBUG && os(macOS)
import AppKit
import LocalAuthentication
import SwiftUI

/// P0 PoC harness (throwaway `poc/auth-lifecycle-macos` branch). Mounted inside the REAL app
/// shell (real `makeDefault` container, real privacy/shield lifecycle active) via
/// `CYPHERAIR_POC_HARNESS=1`. It only DRIVES the real operations and OBSERVES — it implements
/// no operation logic of its own.
///
/// This increment wires items 1 (no resign / no false lock) and 5 (in-app password fallback).
/// Items 2/3/4/6 (Secure Enclave seam consumption, custody, unlock-vs-key-use, rewrap) are
/// added in later increments and are marked below.
struct MacAuthPoCHarnessView: View {
    let container: AppContainer

    @State private var presenter = AuthPoCPresenter()
    @State private var log: [String] = []
    @State private var resignCount = 0
    @State private var becomeActiveCount = 0
    @State private var isActive = NSApplication.shared.isActive
    @State private var observerTokens: [NSObjectProtocol] = []
    @State private var busy = false

    var body: some View {
        ZStack {
            VStack(alignment: .leading, spacing: 12) {
                Text("CypherAir — P0 Auth PoC (macOS)")
                    .font(.title2).bold()

                observationPanel

                Divider()

                VStack(alignment: .leading, spacing: 8) {
                    runButton("Item 1 — No resign / no false lock", id: "1") { try await runItem1() }
                    runButton("Item 5 — In-app password fallback (observe)", id: "5") { try await runItem5() }
                    Text("Items 2/3/4/6 wired in later increments.")
                        .font(.caption).foregroundStyle(.secondary)
                }

                Divider()
                logPanel
            }
            .padding(24)
            .frame(minWidth: 560, minHeight: 520, alignment: .topLeading)

            // The in-window authentication surface. When the presenter has an active context,
            // the LAAuthenticationView renders the biometric INSIDE this window.
            if let ctx = presenter.activeContext {
                VStack(spacing: 12) {
                    Text("Authenticate in-window").font(.headline)
                    LAAuthenticationViewHost(context: ctx, onReady: presenter.viewDidMount)
                        .frame(width: 160, height: 160)
                }
                .padding(28)
                .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16))
                .shadow(radius: 24)
            }
        }
        .onAppear(perform: installObservers)
        .onDisappear(perform: removeObservers)
    }

    private var observationPanel: some View {
        Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 4) {
            GridRow {
                Text("NSApplication.isActive").foregroundStyle(.secondary)
                Text(isActive ? "true" : "FALSE").bold().foregroundStyle(isActive ? .green : .red)
            }
            GridRow {
                Text("resign / becomeActive count").foregroundStyle(.secondary)
                Text("\(resignCount) / \(becomeActiveCount)").bold()
                    .foregroundStyle(resignCount == 0 ? .green : .red)
            }
            GridRow {
                Text("privacyScreenBlurred (real)").foregroundStyle(.secondary)
                Text(container.appSessionOrchestrator.isPrivacyScreenBlurred ? "BLURRED" : "clear").bold()
            }
        }
        .font(.system(.body, design: .monospaced))
    }

    private var logPanel: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 2) {
                ForEach(Array(log.enumerated()), id: \.offset) { _, line in
                    Text(line).font(.system(.caption, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .frame(maxHeight: 180)
    }

    private func runButton(_ title: String, id: String, _ action: @escaping () async throws -> Void) -> some View {
        Button(title) {
            guard !busy else { return }
            busy = true
            Task { @MainActor in
                defer { busy = false }
                do { try await action() }
                catch { append("Item \(id): ERROR \(String(describing: type(of: error)))") }
            }
        }
        .disabled(busy)
    }

    // MARK: - Items

    /// Item 1: drive a real in-window auth and confirm the app does NOT resign and the real
    /// privacy screen does NOT activate.
    @MainActor
    private func runItem1() async throws {
        let resignBefore = resignCount
        let blurBefore = container.appSessionOrchestrator.isPrivacyScreenBlurred
        append("Item 1: presenting in-window biometric (evaluatePolicy .biometrics)…")
        _ = try await presenter.authenticate(
            policy: .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: "P0 PoC item 1: in-window authentication"
        )
        let resignDelta = resignCount - resignBefore
        let blurAfter = container.appSessionOrchestrator.isPrivacyScreenBlurred
        let pass = resignDelta == 0 && isActive && !(!blurBefore && blurAfter)
        append("Item 1: \(pass ? "PASS" : "FAIL") — resignDelta=\(resignDelta), isActive=\(isActive), privacyBlur \(blurBefore)->\(blurAfter)")
    }

    /// Item 5: present .deviceOwnerAuthentication in-window; observe whether an in-window
    /// password field appears (expected: biometric/companion only, per the LAAuthenticationView
    /// header — i.e. no in-window passcode).
    @MainActor
    private func runItem5() async throws {
        append("Item 5: presenting .deviceOwnerAuthentication in-window — OBSERVE whether a password field appears.")
        _ = try await presenter.authenticate(
            policy: .deviceOwnerAuthentication,
            localizedReason: "P0 PoC item 5: does in-window offer a password field?"
        )
        append("Item 5: completed. Record manually: was there an in-window password field? (expected: NO)")
    }

    // MARK: - Observation

    private func installObservers() {
        let nc = NotificationCenter.default
        let resign = nc.addObserver(forName: NSApplication.didResignActiveNotification, object: nil, queue: .main) { _ in
            resignCount += 1
            isActive = NSApplication.shared.isActive
            append("• NSApplication didResignActive (count=\(resignCount))")
        }
        let active = nc.addObserver(forName: NSApplication.didBecomeActiveNotification, object: nil, queue: .main) { _ in
            becomeActiveCount += 1
            isActive = NSApplication.shared.isActive
        }
        observerTokens = [resign, active]
        append("PoC harness mounted. Real container, real lifecycle. Tap a button, then Touch ID.")
    }

    private func removeObservers() {
        observerTokens.forEach(NotificationCenter.default.removeObserver)
        observerTokens = []
    }

    private func append(_ line: String) {
        log.append(line)
        if log.count > 200 { log.removeFirst(log.count - 200) }
    }
}
#endif
