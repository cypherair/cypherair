#if DEBUG && os(macOS)
import AppKit
import LocalAuthentication
import Security
import SwiftUI

/// P0 PoC harness (throwaway `poc/auth-lifecycle-macos` branch). Mounted inside the REAL app
/// shell (real `makeDefault` container, real privacy/shield lifecycle active) via
/// `CYPHERAIR_POC_HARNESS=1`. It only DRIVES the real operations and OBSERVES — it implements
/// no operation logic of its own.
///
/// This harness wires items 1 (no resign / no false lock), 5 (in-app password fallback),
/// 2 (per-operation Secure Enclave seam consumption), and 6 (mode-switch / rewrap under the
/// in-window presenter). Items 3 (custody) and 4 (unlock-vs-key-use) are deferred / architectural
/// per the findings doc — not harness experiments.
struct MacAuthPoCHarnessView: View {
    let container: AppContainer

    @State private var presenter = AuthPoCPresenter()
    @State private var log: [String] = []
    @State private var resignCount = 0
    @State private var becomeActiveCount = 0
    @State private var isActive = NSApplication.shared.isActive
    @State private var observerTokens: [NSObjectProtocol] = []
    @State private var busy = false
    @State private var generatedFingerprints: [String] = []
    @State private var keyCounter = 0
    @State private var item2Key: PGPKeyIdentity?
    @State private var item2Ciphertext: Data?

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
                    runButton("Item 2a — Setup (generate real key; may use the OLD system sheet)", id: "2a") { try await runItem2Setup() }
                    runButton("Item 2b — Measure DECRYPT (one in-window auth)", id: "2b") { try await runItem2MeasureDecrypt() }
                    runButton("Item 2c — Measure SIGN (one in-window auth)", id: "2c") { try await runItem2MeasureSign() }
                    runButton("Item 6 setup — ensure ≥2 real SE keys", id: "6setup") { try await runItem6Setup() }
                    runButton("Item 6 — Mode-switch rewrap (one in-window auth)", id: "6") { await runItem6Measure() }
                    runButton("Item 6 restore — switch back (one in-window auth)", id: "6restore") { await runItem6Restore() }
                    runButton("Cleanup — delete PoC-generated keys", id: "cleanup") { try await runCleanup() }
                    Text("Items 3/4 are deferred / architectural (not harness experiments).")
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
                .transition(.opacity)
            }
        }
        .animation(.easeInOut(duration: 0.15), value: presenter.activeContext != nil)
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

    /// Item 2a — SETUP only (separated from measurement). Generates a real software key and a test
    /// ciphertext. Key generation may trigger the OLD detached system sheet; that is setup, NOT
    /// measured. Run this first, let prompts and lifecycle fully settle, then run Item 2b.
    @MainActor
    private func runItem2Setup() async throws {
        keyCounter += 1
        append("Item 2a: SETUP — generating a real software key (may use the OLD system sheet; NOT measured)…")
        let id = try await container.keyManagement.generateKey(
            name: "PoC SW \(keyCounter)", email: nil, expirySeconds: nil, profile: .universal)
        generatedFingerprints.append(id.fingerprint)
        _ = try container.contactService.importContact(publicKeyData: id.publicKeyData)
        guard let contactId = container.contactService.contactId(forFingerprint: id.fingerprint) else {
            append("Item 2a: FAIL — could not resolve contact id"); return
        }
        let ciphertext = try await container.encryptionService.encryptText(
            "PoC item 2 plaintext", recipientContactIds: [contactId],
            signWithFingerprint: nil, encryptToSelf: false)
        item2Key = id
        item2Ciphertext = ciphertext
        append("Item 2a: SETUP DONE (key …\(id.fingerprint.suffix(8))). Let prompts/lifecycle settle, then tap Item 2b.")
    }

    /// Item 2b — MEASURE decrypt only. ONE in-window per-operation authentication. Counters reset
    /// first so setup's lifecycle events are excluded.
    @MainActor
    private func runItem2MeasureDecrypt() async throws {
        guard let ciphertext = item2Ciphertext else { append("Item 2b: run Item 2a (setup) first."); return }
        resetObservationCounters()
        append("Item 2b: MEASURED in-window DECRYPT — one authentication. Tap Touch ID in-window.")
        try await measureSoftwareOp("decrypt") {
            let (pt, _) = try await container.decryptionService.decryptMessageDetailed(ciphertext: ciphertext)
            return String(data: pt, encoding: .utf8) == "PoC item 2 plaintext" ? "plaintext ok" : "plaintext MISMATCH"
        }
    }

    /// Item 2c — MEASURE sign only. ONE in-window per-operation authentication (separate from 2b,
    /// because decrypt and sign are two distinct private-key operations).
    @MainActor
    private func runItem2MeasureSign() async throws {
        guard let id = item2Key else { append("Item 2c: run Item 2a (setup) first."); return }
        resetObservationCounters()
        append("Item 2c: MEASURED in-window SIGN — one authentication. Tap Touch ID in-window.")
        try await measureSoftwareOp("sign") {
            let sig = try await container.signingService.signCleartext("PoC item 2 sign", signerFingerprint: id.fingerprint)
            return "signature \(sig.count) bytes"
        }
    }

    // MARK: - Item 6 (mode-switch / rewrap under the in-window presenter)

    /// Item 6 setup — ensure ≥2 real SE-wrapped keys exist so the rewrap re-wraps MORE than one key
    /// (the point being "one auth for the whole action even though it re-wraps every key"). Generation
    /// may use the OLD system sheet; that is setup, NOT measured.
    @MainActor
    private func runItem6Setup() async throws {
        while container.keyManagement.keys.count < 2 {
            keyCounter += 1
            append("Item 6 setup: generating real SE-wrapped key \(container.keyManagement.keys.count + 1)/2 (may use the OLD system sheet)…")
            let id = try await container.keyManagement.generateKey(
                name: "PoC SW \(keyCounter)", email: nil, expirySeconds: nil, profile: .universal)
            generatedFingerprints.append(id.fingerprint)
        }
        append("Item 6 setup: DONE — \(container.keyManagement.keys.count) SE-wrapped key(s) present.")
    }

    /// Item 6 — measure ONE forward mode switch (current→opposite) with its single authority auth
    /// rendered IN-WINDOW (via the evaluator seam). Restore is a SEPARATE user step (`runItem6Restore`)
    /// so this stays a single, cleanly-dismissed in-window auth instead of two back-to-back prompts.
    @MainActor
    private func runItem6Measure() async { await runItem6OneSwitch(label: "measure") }

    /// Item 6 restore — switch the mode back (current→opposite) as an explicit, separate user action.
    @MainActor
    private func runItem6Restore() async { await runItem6OneSwitch(label: "restore") }

    /// Validate prerequisites, then run exactly ONE in-window mode switch (current→opposite).
    @MainActor
    private func runItem6OneSwitch(label: String) async {
        guard let box = container.pocEvaluatorBox else { append("Item 6: FAIL — no evaluator box (harness not active?)"); return }
        guard let current = container.authManager.currentMode else {
            append("Item 6: PREREQUISITE — unlock first (authenticate the privacy shield / run any key op), then retry.")
            return
        }
        let fingerprints = container.keyManagement.keys.map(\.fingerprint)
        guard !fingerprints.isEmpty else { append("Item 6: run Item 6 setup first (need ≥1 SE-wrapped key)."); return }
        let target: AuthenticationMode = current == .standard ? .highSecurity : .standard
        _ = await runItem6Switch(box: box, from: current, to: target, fingerprints: fingerprints, label: label)
    }

    /// Run one real `switchMode` with the single authority auth rendered in-window, and assert the
    /// Item 6 properties. Catches internally and logs; returns true on PASS.
    @MainActor
    private func runItem6Switch(
        box: AuthPoCEvaluatorBox,
        from: AuthenticationMode,
        to: AuthenticationMode,
        fingerprints: [String],
        label: String
    ) async -> Bool {
        // Production-faithful backup flag (SettingsScreenModel uses the same). hasBackup only gates
        // the High-Security `.backupRequired` pre-flight; the auth/rewrap mechanics are identical.
        var hasBackup = container.keyManagement.keys.contains(where: \.isBackedUp)
        if to == .highSecurity && !hasBackup {
            hasBackup = true
            append("Item 6 \(label): overriding hasBackup→true for High-Security (no real backup; mechanics identical).")
        }
        resetObservationCounters()
        let resignBefore = resignCount
        let presentsBefore = presenter.inWindowPresentCount
        // Route the single authority auth through the in-window presenter; forbid a hidden second
        // per-key prompt so it throws deterministically instead of presenting another Touch ID.
        presenter.forbidInteractionAfterPolicySuccess = true
        box.evaluator = presenter.inWindowPolicyEvaluator
        defer {
            box.evaluator = nil
            presenter.forbidInteractionAfterPolicySuccess = false
        }
        append("Item 6 \(label): switching \(from.rawValue)→\(to.rawValue) over \(fingerprints.count) key(s) — one in-window Touch ID.")
        do {
            try await container.authManager.switchMode(
                to: to, fingerprints: fingerprints, hasBackup: hasBackup,
                authenticator: container.authManager)
        } catch {
            let journalEmpty = ((try? container.privateKeyControlStore.recoveryJournal()) ?? .empty) == .empty
            let mode = container.authManager.currentMode?.rawValue ?? "nil"
            append("Item 6 \(label): switchMode THREW \(String(describing: type(of: error))) — presents=\(presenter.inWindowPresentCount - presentsBefore); mode now \(mode) (want unchanged \(from.rawValue)); journal=\(journalEmpty ? "empty" : "NONEMPTY") ⇒ old keys recoverable.")
            return false
        }
        let presents = presenter.inWindowPresentCount - presentsBefore
        let resignDelta = resignCount - resignBefore
        let newMode = container.authManager.currentMode
        let journalEmpty = ((try? container.privateKeyControlStore.recoveryJournal()) ?? .empty) == .empty
        let pass = presents == 1 && resignDelta == 0 && newMode == to && journalEmpty
        append("Item 6 \(label): \(pass ? "PASS" : "FAIL") — presents=\(presents) (want 1), resignDelta=\(resignDelta) (want 0), mode \(from.rawValue)->\(newMode?.rawValue ?? "nil") (want \(to.rawValue)), journal=\(journalEmpty ? "empty" : "NONEMPTY"), N=\(fingerprints.count)")
        return pass
    }

    private func resetObservationCounters() {
        resignCount = 0
        becomeActiveCount = 0
        isActive = NSApplication.shared.isActive
    }

    /// Authenticate in-window, deposit the context (with `interactionNotAllowed = true`), run the
    /// real op. PASS = the op succeeds non-interactively ⇒ the SE op consumed the pre-authenticated
    /// context. The SE op for BOTH decrypt and sign is the wrapping key's self-ECDH → `.useKeyKeyExchange`.
    @MainActor
    private func measureSoftwareOp(_ label: String, _ op: @escaping () async throws -> String) async throws {
        guard let box = container.pocContextBox else { append("Item 2 \(label): FAIL — no context box"); return }
        let mode = container.authManager.currentMode ?? .standard
        let resignBefore = resignCount
        var acLabel = "wrappingAC"
        let ctx: LAContext
        do {
            ctx = try await presenter.authenticate(
                accessControl: try mode.createAccessControl(),
                operation: .useKeyKeyExchange,
                localizedReason: "PoC item 2 \(label): authorize private-key use")
        } catch {
            acLabel = "biometryOnly"
            append("Item 2 \(label): wrapping AC rejected (\(String(describing: type(of: error)))); retrying biometry-only AC")
            ctx = try await presenter.authenticate(
                accessControl: try biometryOnlyAccessControl(),
                operation: .useKeyKeyExchange,
                localizedReason: "PoC item 2 \(label): authorize (biometry-only AC)")
        }
        ctx.interactionNotAllowed = true
        box.context = ctx
        defer { box.context = nil }
        do {
            let detail = try await op()
            append("Item 2 \(label): PASS — \(detail); consumed non-interactively; resignDelta=\(resignCount - resignBefore); AC=\(acLabel)")
        } catch {
            append("Item 2 \(label): NOT consumed — op threw \(String(describing: type(of: error))) under interactionNotAllowed. AC=\(acLabel)")
        }
    }

    private func biometryOnlyAccessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.biometryAny], &error) else {
            _ = error?.takeRetainedValue()
            throw CocoaError(.featureUnsupported)
        }
        return accessControl
    }

    /// Cleanup PoC-generated real keys via the REAL deletion path.
    @MainActor
    private func runCleanup() async throws {
        append("Cleanup: deleting \(generatedFingerprints.count) PoC-generated key(s) via the real delete path…")
        for fingerprint in generatedFingerprints {
            do {
                try await container.keyManagement.deleteKey(fingerprint: fingerprint)
                append("• deleted …\(fingerprint.suffix(8))")
            } catch {
                append("• delete failed …\(fingerprint.suffix(8)): \(String(describing: type(of: error)))")
            }
        }
        generatedFingerprints.removeAll()
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
