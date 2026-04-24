import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir

private typealias TraceProtectedDataRightStoreClientProtocol = CypherAir.ProtectedDataRightStoreClientProtocol
private typealias TraceProtectedDataPersistedRightHandle = CypherAir.ProtectedDataPersistedRightHandle
private typealias TraceProtectedDataSessionCoordinator = CypherAir.ProtectedDataSessionCoordinator
private typealias TraceProtectedDataStorageRoot = CypherAir.ProtectedDataStorageRoot
private typealias TraceProtectedDomainKeyManager = CypherAir.ProtectedDomainKeyManager
private typealias TraceAppSessionOrchestrator = CypherAir.AppSessionOrchestrator
private typealias TraceAuthenticationPromptCoordinator = CypherAir.AuthenticationPromptCoordinator
private typealias TraceAuthLifecycleTraceStore = CypherAir.AuthLifecycleTraceStore
private typealias TraceProtectedDataError = CypherAir.ProtectedDataError
private typealias TracePrivacyScreenLifecycleGate = CypherAir.PrivacyScreenLifecycleGate
private typealias TraceAuthenticationManager = CypherAir.AuthenticationManager

private final class TraceLineSink: @unchecked Sendable {
    private let lock = NSLock()
    private var lines: [String] = []

    func append(_ line: String) {
        lock.lock()
        defer { lock.unlock() }
        lines.append(line)
    }

    func snapshot() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return lines
    }
}

private final class TraceTestPersistedRightHandle: TraceProtectedDataPersistedRightHandle {
    let identifier: String

    init(identifier: String) {
        self.identifier = identifier
    }

    func authorize(localizedReason: String) async throws {}

    func deauthorize() async {}

    func rawSecretData() async throws -> Data {
        Data(repeating: 0xAB, count: 32)
    }
}

private final class TraceTestRightStoreClient: TraceProtectedDataRightStoreClientProtocol {
    func right(forIdentifier identifier: String) async throws -> any TraceProtectedDataPersistedRightHandle {
        TraceTestPersistedRightHandle(identifier: identifier)
    }

    func saveRight(_ right: LARight, identifier: String) async throws -> any TraceProtectedDataPersistedRightHandle {
        TraceTestPersistedRightHandle(identifier: identifier)
    }

    func saveRight(
        _ right: LARight,
        identifier: String,
        secret: Data
    ) async throws -> any TraceProtectedDataPersistedRightHandle {
        TraceTestPersistedRightHandle(identifier: identifier)
    }

    func removeRight(forIdentifier identifier: String) async throws {}
}

@MainActor
final class AuthLifecycleTraceStoreTests: XCTestCase {
    private func makeTemporaryDirectory(_ prefix: String) -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func settleShieldDismissal() async {
        for _ in 0..<5 {
            await Task.yield()
        }
        try? await Task.sleep(nanoseconds: 10_000_000)
    }

    private func makeIsolatedDefaults() -> (UserDefaults, String) {
        let suiteName = "com.cypherair.tests.trace.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.removePersistentDomain(forName: suiteName)
        return (defaults, suiteName)
    }

    func test_traceStore_capsEntriesAtCapacity() {
        let sink = TraceLineSink()
        let store = TraceAuthLifecycleTraceStore(
            isEnabled: true,
            capacity: 2,
            sink: { sink.append($0) }
        )

        store.record(category: .session, name: "one")
        store.record(category: .session, name: "two")
        store.record(category: .session, name: "three")

        XCTAssertEqual(store.recentEntries.map(\.name), ["two", "three"])
        XCTAssertEqual(sink.snapshot().count, 3)
    }

    func test_traceStore_disabledMode_doesNotStoreOrEmit() {
        let sink = TraceLineSink()
        let store = TraceAuthLifecycleTraceStore(
            isEnabled: false,
            sink: { sink.append($0) }
        )

        store.record(category: .prompt, name: "ignored")

        XCTAssertTrue(store.recentEntries.isEmpty)
        XCTAssertTrue(sink.snapshot().isEmpty)
    }

    func test_traceStore_enabledMode_mirrorsToSinkWithStablePrefix() {
        let sink = TraceLineSink()
        let store = TraceAuthLifecycleTraceStore(
            isEnabled: true,
            sink: { sink.append($0) }
        )

        store.record(category: .lifecycle, name: "gate.active", metadata: ["decision": "handled"])

        let lines = sink.snapshot()
        XCTAssertEqual(store.recentEntries.count, 1)
        XCTAssertEqual(lines.count, 1)
        XCTAssertTrue(lines[0].contains("[AuthTrace]"))
        XCTAssertTrue(lines[0].contains("gate.active"))
    }

    func test_authenticationPromptCoordinator_recordsPrivacyAndOperationPromptEvents() async throws {
        let store = TraceAuthLifecycleTraceStore(isEnabled: true, sink: { _ in })
        let coordinator = TraceAuthenticationPromptCoordinator(traceStore: store)
        let initialGeneration = coordinator.operationPromptAttemptGeneration

        _ = try await coordinator.withPrivacyPrompt { 1 }
        XCTAssertEqual(coordinator.operationPromptAttemptGeneration, initialGeneration)
        _ = try await coordinator.withOperationPrompt { 2 }
        XCTAssertEqual(coordinator.operationPromptAttemptGeneration, initialGeneration + 1)

        let kinds = store.recentEntries
            .filter { $0.name == "prompt.begin" }
            .compactMap { $0.metadata["kind"] }

        XCTAssertEqual(kinds, ["privacy", "operation"])
    }

    func test_authenticationShieldCoordinator_recordsShieldTraceEventsIntoStoreAndSink() async {
        let sink = TraceLineSink()
        let store = TraceAuthLifecycleTraceStore(
            isEnabled: true,
            sink: { sink.append($0) }
        )
        let coordinator = CypherAir.AuthenticationShieldCoordinator(traceStore: store)

        coordinator.begin(.operation)
        coordinator.end(.operation)
        await settleShieldDismissal()

        let names = store.recentEntries.map(\.name)
        XCTAssertTrue(names.contains("shield.begin"))
        XCTAssertTrue(names.contains("shield.pendingDismissal.start"))
        XCTAssertTrue(names.contains("shield.dismissal.complete"))

        let lines = sink.snapshot()
        XCTAssertTrue(lines.contains(where: { $0.contains("shield.begin") }))
        XCTAssertTrue(lines.contains(where: { $0.contains("shield.dismissal.complete") }))
    }

    func test_authenticationShieldCoordinator_disabledTraceStoreDoesNotRecordShieldEvents() async {
        let sink = TraceLineSink()
        let store = TraceAuthLifecycleTraceStore(
            isEnabled: false,
            sink: { sink.append($0) }
        )
        let coordinator = CypherAir.AuthenticationShieldCoordinator(traceStore: store)

        coordinator.begin(.privacy)
        coordinator.end(.privacy)
        await settleShieldDismissal()

        XCTAssertTrue(store.recentEntries.isEmpty)
        XCTAssertTrue(sink.snapshot().isEmpty)
    }

    func test_appSessionOrchestrator_recordsHandleResumeAndContentClearEvents() async {
        let storageRoot = TraceProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("TraceStoreResume")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }

        let traceStore = TraceAuthLifecycleTraceStore(isEnabled: true, sink: { _ in })
        let authPromptCoordinator = TraceAuthenticationPromptCoordinator(traceStore: traceStore)
        let coordinator = TraceProtectedDataSessionCoordinator(
            rootSecretStore: CypherAir.MockProtectedDataRootSecretStore(),
            legacyRightStoreClient: TraceTestRightStoreClient(),
            domainKeyManager: TraceProtectedDomainKeyManager(storageRoot: storageRoot),
            sharedRightIdentifier: "com.cypherair.tests.trace.resume",
            authenticationPromptCoordinator: authPromptCoordinator,
            traceStore: traceStore
        )
        let orchestrator = TraceAppSessionOrchestrator(
            currentRegistryProvider: {
                throw TraceProtectedDataError.invalidRegistry("Not used in this trace test")
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { 0 },
            requireAuthOnLaunchProvider: { true },
            evaluateAppAuthentication: { _ in .authenticated(context: nil) },
            protectedDataSessionCoordinator: coordinator,
            authenticationPromptCoordinator: authPromptCoordinator,
            traceStore: traceStore
        )

        let attemptedAuthentication = await orchestrator.handleResume(
            localizedReason: "Trace handleResume"
        )

        XCTAssertTrue(attemptedAuthentication)
        XCTAssertTrue(traceStore.recentEntries.contains(where: { $0.name == "session.handleResume.enter" }))
        XCTAssertTrue(traceStore.recentEntries.contains(where: { $0.name == "session.requestContentClear" }))
        XCTAssertTrue(traceStore.recentEntries.contains(where: { $0.name == "session.pendingContext.discard" && $0.metadata["reason"] == "contentClear" }))
        XCTAssertTrue(traceStore.recentEntries.contains(where: { $0.name == "session.pendingContext.store" && $0.metadata["reason"] == "resumeAuthenticated" }))
        XCTAssertTrue(traceStore.recentEntries.contains(where: { $0.name == "session.recordAuthentication" }))
        XCTAssertTrue(traceStore.recentEntries.contains(where: { $0.name == "session.handleResume.exit" }))
    }

    func test_authenticationManager_evaluateAppSessionBypass_recordsStartAndFinishTrace() async throws {
        let (defaults, suiteName) = makeIsolatedDefaults()
        defer { defaults.removePersistentDomain(forName: suiteName) }
        defaults.set(true, forKey: "com.cypherair.preference.uiTestBypassAuthentication")
        let traceStore = TraceAuthLifecycleTraceStore(isEnabled: true, sink: { _ in })
        let manager = TraceAuthenticationManager(
            secureEnclave: MockSecureEnclave(),
            keychain: MockKeychain(),
            defaults: defaults,
            traceStore: traceStore
        )

        let result = try await manager.evaluateAppSession(policy: .userPresence, reason: "Trace bypass")

        XCTAssertTrue(result.isAuthenticated)
        XCTAssertNil(result.context)
        XCTAssertTrue(traceStore.recentEntries.contains(where: { $0.name == "appSession.evaluate.start" && $0.metadata["policy"] == "userPresence" }))
        XCTAssertTrue(traceStore.recentEntries.contains(where: { $0.name == "appSession.evaluate.finish" && $0.metadata["result"] == "bypass" && $0.metadata["hasContext"] == "false" }))
    }

    func test_authenticationManager_switchModeSuccess_recordsPhaseTraceWithoutFingerprints() async throws {
        let (defaults, suiteName) = makeIsolatedDefaults()
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let traceStore = TraceAuthLifecycleTraceStore(isEnabled: true, sink: { _ in })
        let secureEnclave = MockSecureEnclave()
        let keychain = MockKeychain()
        let manager = TraceAuthenticationManager(
            secureEnclave: secureEnclave,
            keychain: keychain,
            defaults: defaults,
            traceStore: traceStore
        )
        let fingerprint = String(repeating: "a", count: 40)
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil)
        let bundle = try secureEnclave.wrap(
            privateKey: Data(repeating: 0x42, count: 32),
            using: handle,
            fingerprint: fingerprint
        )
        try KeyBundleStore(keychain: keychain).saveBundle(bundle, fingerprint: fingerprint)

        try await manager.switchMode(
            to: .highSecurity,
            fingerprints: [fingerprint],
            hasBackup: true,
            authenticator: MockAuthenticator()
        )

        let names = traceStore.recentEntries.map(\.name)
        XCTAssertTrue(names.contains("privateKeyProtection.switch.start"))
        XCTAssertTrue(names.contains("privateKeyProtection.switch.auth.start"))
        XCTAssertTrue(names.contains("privateKeyProtection.switch.phaseA.start"))
        XCTAssertTrue(names.contains("privateKeyProtection.switch.phaseB.start"))
        XCTAssertTrue(
            traceStore.recentEntries.contains {
                $0.name == "privateKeyProtection.switch.finish" && $0.metadata["result"] == "success"
            }
        )
        let allMetadataValues = traceStore.recentEntries.flatMap { $0.metadata.values }
        XCTAssertFalse(allMetadataValues.contains(fingerprint))
    }

    func test_authenticationManager_switchModeNoIdentities_recordsFailureTrace() async throws {
        let (defaults, suiteName) = makeIsolatedDefaults()
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let traceStore = TraceAuthLifecycleTraceStore(isEnabled: true, sink: { _ in })
        let manager = TraceAuthenticationManager(
            secureEnclave: MockSecureEnclave(),
            keychain: MockKeychain(),
            defaults: defaults,
            traceStore: traceStore
        )

        do {
            try await manager.switchMode(
                to: .highSecurity,
                fingerprints: [],
                hasBackup: true,
                authenticator: MockAuthenticator()
            )
            XCTFail("Expected noIdentities")
        } catch AuthenticationError.noIdentities {
        } catch {
            XCTFail("Expected noIdentities, got \(error)")
        }

        XCTAssertTrue(
            traceStore.recentEntries.contains {
                $0.name == "privateKeyProtection.switch.finish" && $0.metadata["result"] == "noIdentities"
            }
        )
    }

    func test_protectedDataSessionCoordinator_recordsRootSecretHandoffTrace() async {
        let storageRoot = TraceProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("TraceRootSecretHandoff")
        )
        defer { try? FileManager.default.removeItem(at: storageRoot.rootURL.deletingLastPathComponent()) }
        let traceStore = TraceAuthLifecycleTraceStore(isEnabled: true, sink: { _ in })
        let rootSecretStore = MockProtectedDataRootSecretStore()
        try? rootSecretStore.saveRootSecret(
            Data(repeating: 0x41, count: 32),
            identifier: "com.cypherair.tests.trace.root-secret",
            policy: .userPresence
        )
        let coordinator = TraceProtectedDataSessionCoordinator(
            rootSecretStore: rootSecretStore,
            domainKeyManager: TraceProtectedDomainKeyManager(storageRoot: storageRoot),
            sharedRightIdentifier: "com.cypherair.tests.trace.root-secret",
            traceStore: traceStore
        )
        let registry = ProtectedDataRegistry(
            formatVersion: ProtectedDataRegistry.currentFormatVersion,
            sharedRightIdentifier: "com.cypherair.tests.trace.root-secret",
            sharedResourceLifecycleState: .ready,
            committedMembership: ["protected-settings": .active],
            pendingMutation: nil
        )
        let context = LAContext()
        defer { context.invalidate() }

        let result = await coordinator.beginProtectedDataAuthorization(
            registry: registry,
            localizedReason: "Trace root secret handoff",
            authenticationContext: context
        )

        XCTAssertEqual(result, .authorized)
        XCTAssertTrue(
            traceStore.recentEntries.contains {
                $0.name == "protectedData.rootSecret.load.start"
                    && $0.metadata["source"] == "handoff"
                    && $0.metadata["interactionNotAllowed"] == "true"
            }
        )
        XCTAssertTrue(
            traceStore.recentEntries.contains {
                $0.name == "protectedData.rootSecret.load.finish" && $0.metadata["result"] == "success"
            }
        )
    }

    func test_protectedSettingsHost_recordsRefreshGateAndOpenTrace() async {
        let traceStore = TraceAuthLifecycleTraceStore(isEnabled: true, sink: { _ in })
        var domainState: CypherAir.ProtectedSettingsHost.DomainState = .locked
        let host = CypherAir.ProtectedSettingsHost(
            evaluateAccessGate: { _ in .alreadyAuthorized },
            authorizeSharedRight: { _ in
                XCTFail("Already-authorized refresh should not authorize again")
                return .authorized
            },
            currentWrappingRootKey: { Data(repeating: 0x11, count: 32) },
            syncPreAuthorizationState: {},
            currentDomainState: { domainState },
            currentClipboardNotice: { nil },
            migrateLegacyClipboardNoticeIfNeeded: {},
            openDomainIfNeeded: { _ in domainState = .unlocked },
            updateClipboardNotice: { _, _ in },
            recoverPendingMutation: { .retryablePending },
            resetDomain: {},
            traceStore: traceStore
        )

        await host.refreshSettingsSection()

        XCTAssertTrue(traceStore.recentEntries.contains(where: { $0.name == "protectedSettings.refresh.start" }))
        XCTAssertTrue(
            traceStore.recentEntries.contains {
                $0.name == "protectedSettings.gate.decision" && $0.metadata["decision"] == "alreadyAuthorized"
            }
        )
        XCTAssertTrue(
            traceStore.recentEntries.contains {
                $0.name == "protectedSettings.openDomain.finish" && $0.metadata["result"] == "success"
            }
        )
    }

    func test_privacyScreenLifecycleGate_recordsDecisionTagsWithoutChangingBehavior() {
        let traceStore = TraceAuthLifecycleTraceStore(isEnabled: true, sink: { _ in })
        var gate = TracePrivacyScreenLifecycleGate(traceStore: traceStore)

        XCTAssertFalse(gate.shouldHandleInactive(isAuthenticating: false, isOperationPromptInProgress: true))
        XCTAssertFalse(gate.shouldHandleBecomeActive(isAuthenticating: false))
        XCTAssertTrue(gate.shouldHandleBecomeActive(isAuthenticating: false))

        let names = traceStore.recentEntries.map(\.name)
        XCTAssertTrue(names.contains("gate.inactive"))
        XCTAssertTrue(names.contains("gate.active"))
    }
}
