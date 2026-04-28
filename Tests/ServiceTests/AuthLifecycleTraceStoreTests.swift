import Foundation
import LocalAuthentication
import Security
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

private enum TracePrivateKeyAccessTestError: Error {
    case seUnwrapFailed
}

private final class TraceFailingUnwrapSecureEnclave: SecureEnclaveManageable {
    private let base: MockSecureEnclave
    private let unwrapError: Error

    init(base: MockSecureEnclave, unwrapError: Error = TracePrivateKeyAccessTestError.seUnwrapFailed) {
        self.base = base
        self.unwrapError = unwrapError
    }

    static var isAvailable: Bool { MockSecureEnclave.isAvailable }

    func generateWrappingKey(
        accessControl: SecAccessControl?,
        authenticationContext: LAContext?
    ) throws -> any SEKeyHandle {
        try base.generateWrappingKey(
            accessControl: accessControl,
            authenticationContext: authenticationContext
        )
    }

    func wrap(
        privateKey: Data,
        using handle: any SEKeyHandle,
        fingerprint: String
    ) throws -> WrappedKeyBundle {
        try base.wrap(privateKey: privateKey, using: handle, fingerprint: fingerprint)
    }

    func unwrap(
        bundle: WrappedKeyBundle,
        using handle: any SEKeyHandle,
        fingerprint: String
    ) throws -> Data {
        throw unwrapError
    }

    func deleteKey(_ handle: any SEKeyHandle) throws {
        try base.deleteKey(handle)
    }

    func reconstructKey(from data: Data, authenticationContext: LAContext?) throws -> any SEKeyHandle {
        try base.reconstructKey(from: data, authenticationContext: authenticationContext)
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

    private func assertTraceNames(
        _ names: [String],
        containOrdered expectedNames: [String],
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        var searchStart = names.startIndex
        for expectedName in expectedNames {
            guard let foundIndex = names[searchStart...].firstIndex(of: expectedName) else {
                XCTFail("Missing trace entry \(expectedName) in order", file: file, line: line)
                return
            }
            searchStart = names.index(after: foundIndex)
        }
    }

    private func saveTraceWrappedPrivateKey(
        secureEnclave: MockSecureEnclave,
        bundleStore: KeyBundleStore,
        fingerprint: String = String(repeating: "a", count: 40),
        privateKey: Data = Data([0x11, 0x22, 0x33, 0x44])
    ) throws -> (fingerprint: String, privateKey: Data) {
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil)
        let bundle = try secureEnclave.wrap(
            privateKey: privateKey,
            using: handle,
            fingerprint: fingerprint
        )
        try bundleStore.saveBundle(bundle, fingerprint: fingerprint)
        return (fingerprint, privateKey)
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
        XCTAssertTrue(lines[0].contains("wall="))
        XCTAssertTrue(lines[0].contains("elapsedMs="))
        XCTAssertTrue(lines[0].contains("deltaMs="))
        XCTAssertTrue(lines[0].contains("ref="))
        XCTAssertTrue(lines[0].contains("gate.active"))
    }

    func test_promptCoordinator_recordsPromptErrorBeforeRethrowing() async {
        enum ExpectedError: Error {
            case failed
        }

        let store = TraceAuthLifecycleTraceStore(isEnabled: true, sink: { _ in })
        let coordinator = TraceAuthenticationPromptCoordinator(traceStore: store)

        do {
            _ = try await coordinator.withPrivacyPrompt(source: "traceTest") {
                throw ExpectedError.failed
            }
            XCTFail("Expected prompt operation to rethrow")
        } catch ExpectedError.failed {
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        let entries = store.recentEntries
        XCTAssertTrue(entries.contains { $0.name == "prompt.begin" && $0.metadata["source"] == "traceTest" })
        XCTAssertTrue(entries.contains { $0.name == "prompt.error" && $0.metadata["source"] == "traceTest" })
        XCTAssertTrue(entries.contains { $0.name == "prompt.end" && $0.metadata["source"] == "traceTest" })
    }

    func test_startupCoordinator_recordsSegmentTrace() {
        let container = AppContainer.makeUITest(authTraceEnabled: true)

        _ = AppStartupCoordinator().performPreAuthBootstrap(using: container)

        let names = container.authLifecycleTraceStore?.recentEntries.map(\.name) ?? []
        XCTAssertTrue(names.contains("startup.protectedDataBootstrap.start"))
        XCTAssertTrue(names.contains("startup.protectedDataBootstrap.finish"))
        XCTAssertTrue(names.contains("startup.keyMetadata.load.deferred"))
        XCTAssertTrue(names.contains("startup.contacts.load.start"))
        XCTAssertTrue(names.contains("startup.contacts.load.finish"))
        XCTAssertTrue(names.contains("startup.loadWarning.computed"))
    }

    func test_systemKeychain_recordsPassiveTraceWithoutChangingResults() throws {
        let store = TraceAuthLifecycleTraceStore(isEnabled: true, sink: { _ in })
        let keychain = SystemKeychain(traceStore: store)
        let service = "\(KeychainConstants.metadataPrefix)trace-\(UUID().uuidString)"
        let account = "com.cypherair.tests.trace"

        try? keychain.delete(service: service, account: account)

        do {
            try keychain.save(Data([0xCA, 0xFE]), service: service, account: account, accessControl: nil)
        } catch {
            throw XCTSkip("System Keychain is unavailable in this test environment: \(error)")
        }
        defer {
            try? keychain.delete(service: service, account: account)
        }

        XCTAssertEqual(try keychain.load(service: service, account: account), Data([0xCA, 0xFE]))
        XCTAssertTrue(keychain.exists(service: service, account: account))
        XCTAssertTrue(try keychain.listItems(servicePrefix: KeychainConstants.metadataPrefix, account: account).contains(service))
        try keychain.delete(service: service, account: account)
        XCTAssertFalse(keychain.exists(service: service, account: account))

        let entries = store.recentEntries
        XCTAssertTrue(entries.contains { $0.name == "keychain.save.start" })
        XCTAssertTrue(entries.contains { $0.name == "keychain.save.finish" && $0.metadata["statusName"] == "success" })
        XCTAssertTrue(entries.contains { $0.name == "keychain.load.start" })
        XCTAssertTrue(entries.contains { $0.name == "keychain.load.finish" && $0.metadata["statusName"] == "success" })
        XCTAssertTrue(entries.contains { $0.name == "keychain.delete.finish" && $0.metadata["statusName"] == "success" })
    }

    func test_errorMetadata_includesNSErrorDomainAndCode() {
        let error = NSError(
            domain: NSCocoaErrorDomain,
            code: 260,
            userInfo: [
                NSLocalizedDescriptionKey: "The file could not be opened.",
                NSUnderlyingErrorKey: NSError(domain: NSPOSIXErrorDomain, code: 2)
            ]
        )

        let metadata = AuthTraceMetadata.errorMetadata(error)

        XCTAssertEqual(metadata["errorDomain"], NSCocoaErrorDomain)
        XCTAssertEqual(metadata["errorCode"], "260")
        XCTAssertEqual(metadata["underlyingErrorDomain"], NSPOSIXErrorDomain)
        XCTAssertEqual(metadata["underlyingErrorCode"], "2")
        XCTAssertEqual(metadata["errorDescription"], "The file could not be opened.")
    }

    func test_protectedDataStorageRoot_recordsContractStagesForMissingBaseBootstrap() throws {
        let store = TraceAuthLifecycleTraceStore(isEnabled: true, sink: { _ in })
        let applicationSupportDirectory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let baseDirectory = applicationSupportDirectory.appendingPathComponent(
            "TraceProtectedDataMissingBase-\(UUID().uuidString)",
            isDirectory: true
        )
        defer { try? FileManager.default.removeItem(at: baseDirectory) }

        let storageRoot = TraceProtectedDataStorageRoot(
            baseDirectory: baseDirectory,
            validationMode: .enforceAppSupportContainment,
            fileProtectionCapabilityProvider: { _ in true },
            traceStore: store
        )
        let registryStore = ProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.trace.protected-data",
            traceStore: store
        )

        _ = try registryStore.performSynchronousBootstrap()

        let entries = store.recentEntries
        XCTAssertTrue(entries.contains { $0.name == "protectedData.registryBootstrap.start" })
        XCTAssertTrue(entries.contains { $0.name == "protectedData.registryBootstrap.finish" && $0.metadata["result"] == "success" })
        XCTAssertTrue(entries.contains {
            $0.name == "protectedData.storageContract"
                && $0.metadata["stage"] == "containmentCheck"
                && $0.metadata["result"] == "success"
        })
        XCTAssertTrue(entries.contains {
            $0.name == "protectedData.storageContract"
                && $0.metadata["stage"] == "protectionProbe"
                && $0.metadata["result"] == "success"
        })
    }

    func test_loadWarningPresentationGate_defersWhileAuthenticationPresentationIsActive() {
        XCTAssertTrue(LoadWarningPresentationGate.canPresent(
            LoadWarningPresentationState(
                isShieldVisible: false,
                isAuthenticating: false,
                isPrivacyScreenBlurred: false,
                hasAuthenticatedSession: true,
                allowsPreAuthenticationPresentation: false
            )
        ))
        XCTAssertFalse(LoadWarningPresentationGate.canPresent(
            LoadWarningPresentationState(
                isShieldVisible: true,
                isAuthenticating: false,
                isPrivacyScreenBlurred: false,
                hasAuthenticatedSession: true,
                allowsPreAuthenticationPresentation: false
            )
        ))
        XCTAssertFalse(LoadWarningPresentationGate.canPresent(
            LoadWarningPresentationState(
                isShieldVisible: false,
                isAuthenticating: true,
                isPrivacyScreenBlurred: false,
                hasAuthenticatedSession: true,
                allowsPreAuthenticationPresentation: false
            )
        ))
        XCTAssertFalse(LoadWarningPresentationGate.canPresent(
            LoadWarningPresentationState(
                isShieldVisible: false,
                isAuthenticating: false,
                isPrivacyScreenBlurred: true,
                hasAuthenticatedSession: true,
                allowsPreAuthenticationPresentation: false
            )
        ))
        XCTAssertFalse(LoadWarningPresentationGate.canPresent(
            LoadWarningPresentationState(
                isShieldVisible: false,
                isAuthenticating: false,
                isPrivacyScreenBlurred: false,
                hasAuthenticatedSession: false,
                allowsPreAuthenticationPresentation: false
            )
        ))
        XCTAssertTrue(LoadWarningPresentationGate.canPresent(
            LoadWarningPresentationState(
                isShieldVisible: false,
                isAuthenticating: false,
                isPrivacyScreenBlurred: false,
                hasAuthenticatedSession: false,
                allowsPreAuthenticationPresentation: true
            )
        ))
    }

    func test_traceStore_recordsMonotonicRelativeTiming() {
        let store = TraceAuthLifecycleTraceStore(isEnabled: true, sink: { _ in })

        store.record(category: .session, name: "one")
        store.record(category: .session, name: "two")

        let entries = store.recentEntries
        XCTAssertEqual(entries.map(\.sequence), [1, 2])
        XCTAssertGreaterThanOrEqual(entries[0].elapsedMilliseconds, 0)
        XCTAssertGreaterThanOrEqual(entries[1].elapsedMilliseconds, entries[0].elapsedMilliseconds)
        XCTAssertEqual(entries[0].deltaMilliseconds, 0, accuracy: 0.001)
        XCTAssertGreaterThanOrEqual(entries[1].deltaMilliseconds, 0)
    }

    func test_authenticationPromptCoordinator_recordsPrivacyAndOperationPromptEvents() async throws {
        let store = TraceAuthLifecycleTraceStore(isEnabled: true, sink: { _ in })
        let coordinator = TraceAuthenticationPromptCoordinator(traceStore: store)
        let initialGeneration = coordinator.operationPromptAttemptGeneration

        _ = try await coordinator.withPrivacyPrompt(source: "trace.privacy") { 1 }
        XCTAssertEqual(coordinator.operationPromptAttemptGeneration, initialGeneration)
        _ = try await coordinator.withOperationPrompt(source: "trace.operation") { 2 }
        XCTAssertEqual(coordinator.operationPromptAttemptGeneration, initialGeneration + 1)

        let promptBegins = store.recentEntries.filter { $0.name == "prompt.begin" }
        let promptEnds = store.recentEntries.filter { $0.name == "prompt.end" }

        XCTAssertEqual(promptBegins.compactMap { $0.metadata["kind"] }, ["privacy", "operation"])
        XCTAssertEqual(promptBegins.compactMap { $0.metadata["source"] }, ["trace.privacy", "trace.operation"])
        XCTAssertEqual(promptBegins.compactMap { $0.metadata["promptID"] }, promptEnds.compactMap { $0.metadata["promptID"] })
        XCTAssertEqual(Set(promptBegins.compactMap { $0.metadata["promptID"] }).count, 2)
    }

    func test_authenticationPromptCoordinator_recordsOperationPromptSuccessBoundaries() async throws {
        let store = TraceAuthLifecycleTraceStore(isEnabled: true, sink: { _ in })
        let coordinator = TraceAuthenticationPromptCoordinator(traceStore: store)

        let result = try await coordinator.withOperationPrompt(source: "trace.operation.success") { context in
            XCTAssertEqual(context.source, "trace.operation.success")
            return 2
        }

        XCTAssertEqual(result, 2)
        let names = store.recentEntries.map(\.name)
        assertTraceNames(
            names,
            containOrdered: [
                "prompt.operation.handler.enter",
                "prompt.operation.operation.await.start",
                "prompt.operation.operation.await.finish",
                "prompt.operation.endDepth.start",
                "prompt.operation.endDepth.finish",
                "prompt.operation.shieldEnd.start",
                "prompt.operation.shieldEnd.finish"
            ]
        )

        let operationBoundaryEntries = store.recentEntries
            .filter { $0.name.hasPrefix("prompt.operation.") }
        XCTAssertFalse(operationBoundaryEntries.isEmpty)
        XCTAssertEqual(Set(operationBoundaryEntries.compactMap { $0.metadata["promptID"] }).count, 1)
        for entry in operationBoundaryEntries {
            XCTAssertEqual(entry.metadata["source"], "trace.operation.success")
            XCTAssertEqual(entry.metadata["kind"], "operation")
            XCTAssertNotNil(entry.metadata["isMainThread"])
        }
    }

    func test_authenticationPromptCoordinator_recordsOperationPromptThrowBoundaries() async {
        let store = TraceAuthLifecycleTraceStore(isEnabled: true, sink: { _ in })
        let coordinator = TraceAuthenticationPromptCoordinator(traceStore: store)

        do {
            _ = try await coordinator.withOperationPrompt(source: "trace.operation.throw") { _ in
                throw TracePrivateKeyAccessTestError.seUnwrapFailed
            }
            XCTFail("Expected operation prompt to throw")
        } catch TracePrivateKeyAccessTestError.seUnwrapFailed {
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        let names = store.recentEntries.map(\.name)
        assertTraceNames(
            names,
            containOrdered: [
                "prompt.operation.operation.await.start",
                "prompt.operation.operation.await.throw",
                "prompt.operation.endDepth.start",
                "prompt.operation.endDepth.finish",
                "prompt.operation.shieldEnd.start",
                "prompt.operation.shieldEnd.finish"
            ]
        )

        guard let throwEntry = store.recentEntries.first(where: { $0.name == "prompt.operation.operation.await.throw" }) else {
            XCTFail("Expected operation await throw trace")
            return
        }
        XCTAssertEqual(throwEntry.metadata["source"], "trace.operation.throw")
        XCTAssertEqual(throwEntry.metadata["kind"], "operation")
        XCTAssertEqual(throwEntry.metadata["errorType"], "TracePrivateKeyAccessTestError")
        XCTAssertNotNil(throwEntry.metadata["isMainThread"])
    }

    func test_authenticationPromptCoordinator_recordsPrivacyPromptSuccessBoundaries() async throws {
        let store = TraceAuthLifecycleTraceStore(isEnabled: true, sink: { _ in })
        let coordinator = TraceAuthenticationPromptCoordinator(traceStore: store)

        let result = await coordinator.withPrivacyPrompt(source: "trace.privacy.success") { context in
            XCTAssertEqual(context.source, "trace.privacy.success")
            return 1
        }

        XCTAssertEqual(result, 1)
        let names = store.recentEntries.map(\.name)
        assertTraceNames(
            names,
            containOrdered: [
                "prompt.privacy.handler.enter",
                "prompt.privacy.operation.await.start",
                "prompt.privacy.operation.await.finish",
                "prompt.privacy.endDepth.start",
                "prompt.privacy.endDepth.finish",
                "prompt.privacy.shieldEnd.start",
                "prompt.privacy.shieldEnd.finish"
            ]
        )

        let privacyBoundaryEntries = store.recentEntries
            .filter { $0.name.hasPrefix("prompt.privacy.") }
        XCTAssertFalse(privacyBoundaryEntries.isEmpty)
        XCTAssertEqual(Set(privacyBoundaryEntries.compactMap { $0.metadata["promptID"] }).count, 1)
        for entry in privacyBoundaryEntries {
            XCTAssertEqual(entry.metadata["source"], "trace.privacy.success")
            XCTAssertEqual(entry.metadata["kind"], "privacy")
            XCTAssertNotNil(entry.metadata["isMainThread"])
        }
    }

    func test_authenticationPromptCoordinator_recordsPrivacyPromptThrowBoundaries() async {
        let store = TraceAuthLifecycleTraceStore(isEnabled: true, sink: { _ in })
        let coordinator = TraceAuthenticationPromptCoordinator(traceStore: store)

        do {
            _ = try await coordinator.withPrivacyPrompt(source: "trace.privacy.throw") { _ in
                throw TracePrivateKeyAccessTestError.seUnwrapFailed
            }
            XCTFail("Expected privacy prompt to throw")
        } catch TracePrivateKeyAccessTestError.seUnwrapFailed {
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        let names = store.recentEntries.map(\.name)
        assertTraceNames(
            names,
            containOrdered: [
                "prompt.privacy.operation.await.start",
                "prompt.privacy.operation.await.throw",
                "prompt.privacy.endDepth.start",
                "prompt.privacy.endDepth.finish",
                "prompt.privacy.shieldEnd.start",
                "prompt.privacy.shieldEnd.finish"
            ]
        )

        guard let throwEntry = store.recentEntries.first(where: { $0.name == "prompt.privacy.operation.await.throw" }) else {
            XCTFail("Expected privacy await throw trace")
            return
        }
        XCTAssertEqual(throwEntry.metadata["source"], "trace.privacy.throw")
        XCTAssertEqual(throwEntry.metadata["kind"], "privacy")
        XCTAssertEqual(throwEntry.metadata["errorType"], "TracePrivateKeyAccessTestError")
        XCTAssertNotNil(throwEntry.metadata["isMainThread"])
    }

    func test_privateKeyAccessService_recordsSuccessfulUnwrapClosureTraceWithoutSensitiveValues() async throws {
        let store = TraceAuthLifecycleTraceStore(isEnabled: true, sink: { _ in })
        let secureEnclave = MockSecureEnclave()
        let keychain = MockKeychain()
        let bundleStore = KeyBundleStore(keychain: keychain)
        let fixture = try saveTraceWrappedPrivateKey(
            secureEnclave: secureEnclave,
            bundleStore: bundleStore
        )
        let accessService = PrivateKeyAccessService(
            secureEnclave: secureEnclave,
            bundleStore: bundleStore,
            authenticationPromptCoordinator: TraceAuthenticationPromptCoordinator(traceStore: store),
            traceStore: store
        )

        let unwrapped = try await accessService.unwrapPrivateKey(fingerprint: fixture.fingerprint)

        XCTAssertEqual(unwrapped, fixture.privateKey)
        assertTraceNames(
            store.recentEntries.map(\.name),
            containOrdered: [
                "privateKey.unwrap.bundle.load.start",
                "privateKey.unwrap.bundle.load.finish",
                "privateKey.unwrap.reconstruct.start",
                "privateKey.unwrap.reconstruct.finish",
                "privateKey.unwrap.seUnwrap.call.start",
                "privateKey.unwrap.seUnwrap.call.finish",
                "privateKey.unwrap.closure.return",
                "prompt.operation.operation.await.finish"
            ]
        )
        XCTAssertTrue(
            store.recentEntries.contains {
                $0.name == "privateKey.unwrap.seUnwrap.call.finish"
                    && $0.metadata["result"] == "success"
            }
        )

        let metadataKeys = Set(store.recentEntries.flatMap { $0.metadata.keys })
        let metadataValues = store.recentEntries.flatMap { $0.metadata.values }
        XCTAssertFalse(metadataKeys.contains("fingerprint"))
        XCTAssertFalse(metadataKeys.contains("privateKey"))
        XCTAssertFalse(metadataValues.contains(fixture.fingerprint))
    }

    func test_privateKeyAccessService_recordsUnwrapFailureStageWithoutSensitiveValues() async {
        let store = TraceAuthLifecycleTraceStore(isEnabled: true, sink: { _ in })
        let secureEnclave = MockSecureEnclave()
        let keychain = MockKeychain()
        let bundleStore = KeyBundleStore(keychain: keychain)
        let fixture: (fingerprint: String, privateKey: Data)
        do {
            fixture = try saveTraceWrappedPrivateKey(
                secureEnclave: secureEnclave,
                bundleStore: bundleStore
            )
        } catch {
            XCTFail("Failed to create wrapped test key: \(error)")
            return
        }
        let accessService = PrivateKeyAccessService(
            secureEnclave: TraceFailingUnwrapSecureEnclave(base: secureEnclave),
            bundleStore: bundleStore,
            authenticationPromptCoordinator: TraceAuthenticationPromptCoordinator(traceStore: store),
            traceStore: store
        )

        do {
            _ = try await accessService.unwrapPrivateKey(fingerprint: fixture.fingerprint)
            XCTFail("Expected unwrapPrivateKey to throw")
        } catch TracePrivateKeyAccessTestError.seUnwrapFailed {
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        assertTraceNames(
            store.recentEntries.map(\.name),
            containOrdered: [
                "privateKey.unwrap.bundle.load.start",
                "privateKey.unwrap.bundle.load.finish",
                "privateKey.unwrap.reconstruct.start",
                "privateKey.unwrap.reconstruct.finish",
                "privateKey.unwrap.seUnwrap.call.start",
                "privateKey.unwrap.seUnwrap.call.finish",
                "prompt.operation.operation.await.throw",
                "privateKey.unwrap.finish"
            ]
        )
        XCTAssertTrue(
            store.recentEntries.contains {
                $0.name == "privateKey.unwrap.seUnwrap.call.finish"
                    && $0.metadata["result"] == "failure"
                    && $0.metadata["errorType"] == "TracePrivateKeyAccessTestError"
            }
        )
        XCTAssertFalse(store.recentEntries.contains { $0.name == "privateKey.unwrap.closure.return" })

        let metadataKeys = Set(store.recentEntries.flatMap { $0.metadata.keys })
        let metadataValues = store.recentEntries.flatMap { $0.metadata.values }
        XCTAssertFalse(metadataKeys.contains("fingerprint"))
        XCTAssertFalse(metadataKeys.contains("privateKey"))
        XCTAssertFalse(metadataValues.contains(fixture.fingerprint))
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
        assertTraceNames(
            traceStore.recentEntries.map(\.name),
            containOrdered: [
                "session.handleResume.evaluate.start",
                "session.handleResume.evaluate.finish",
                "session.handleResume.postAuth.start",
                "session.handleResume.postAuth.finish",
                "session.handleResume.exit"
            ]
        )
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
        XCTAssertTrue(
            traceStore.recentEntries.contains {
                $0.name == "appSession.evaluate.start"
                    && $0.metadata["policy"] == "userPresence"
                    && $0.metadata["source"] == "unspecified"
                    && $0.metadata["promptID"] == "none"
            }
        )
        XCTAssertTrue(
            traceStore.recentEntries.contains {
                $0.name == "appSession.evaluate.finish"
                    && $0.metadata["result"] == "bypass"
                    && $0.metadata["hasContext"] == "false"
                    && $0.metadata["promptID"] == "none"
            }
        )
    }

    func test_authenticationManager_evaluateAppSessionRecordsPolicyAwaitSuccessTrace() async throws {
        let (defaults, suiteName) = makeIsolatedDefaults()
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let traceStore = TraceAuthLifecycleTraceStore(isEnabled: true, sink: { _ in })
        let reason = "Trace policy reason must stay out of metadata"
        let manager = TraceAuthenticationManager(
            secureEnclave: MockSecureEnclave(),
            keychain: MockKeychain(),
            defaults: defaults,
            authenticationPromptCoordinator: TraceAuthenticationPromptCoordinator(traceStore: traceStore),
            traceStore: traceStore,
            localAuthenticationPolicyEvaluator: { _, policy, receivedReason, reply in
                XCTAssertEqual(policy, AppSessionAuthenticationPolicy.biometricsOnly.localAuthenticationPolicy)
                XCTAssertEqual(receivedReason, reason)
                reply(true, nil)
            }
        )

        let result = try await manager.evaluateAppSession(
            policy: .biometricsOnly,
            reason: reason,
            source: "unit.appSession.success"
        )

        XCTAssertTrue(result.isAuthenticated)
        XCTAssertNotNil(result.context)
        assertTraceNames(
            traceStore.recentEntries.map(\.name),
            containOrdered: [
                "prompt.privacy.operation.await.start",
                "appSession.evaluate.start",
                "appSession.evaluate.policy.await.start",
                "appSession.evaluate.callback.call.start",
                "appSession.evaluate.callback.reply",
                "appSession.evaluate.callback.resume",
                "appSession.evaluate.policy.await.finish",
                "prompt.privacy.operation.await.finish",
                "appSession.evaluate.finish"
            ]
        )
        XCTAssertTrue(
            traceStore.recentEntries.contains {
                $0.name == "appSession.evaluate.policy.await.finish"
                    && $0.metadata["policy"] == "biometricsOnly"
                    && $0.metadata["source"] == "unit.appSession.success"
                    && $0.metadata["promptID"] != "none"
                    && $0.metadata["result"] == "success"
                    && $0.metadata["isMainThread"] != nil
            }
        )
        XCTAssertTrue(
            traceStore.recentEntries.contains {
                $0.name == "appSession.evaluate.callback.reply"
                    && $0.metadata["policy"] == "biometricsOnly"
                    && $0.metadata["source"] == "unit.appSession.success"
                    && $0.metadata["promptID"] != "none"
                    && $0.metadata["result"] == "success"
                    && $0.metadata["isMainThread"] != nil
            }
        )
        XCTAssertTrue(
            traceStore.recentEntries.contains {
                $0.name == "appSession.evaluate.callback.resume"
                    && $0.metadata["result"] == "success"
            }
        )

        let metadataKeys = Set(traceStore.recentEntries.flatMap { $0.metadata.keys })
        let metadataValues = traceStore.recentEntries.flatMap { $0.metadata.values }
        XCTAssertFalse(metadataKeys.contains("reason"))
        XCTAssertFalse(metadataValues.contains(reason))
    }

    func test_authenticationManager_evaluateAppSessionRecordsPolicyAwaitThrowTrace() async {
        let (defaults, suiteName) = makeIsolatedDefaults()
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let traceStore = TraceAuthLifecycleTraceStore(isEnabled: true, sink: { _ in })
        let reason = "Trace failing policy reason must stay out of metadata"
        let manager = TraceAuthenticationManager(
            secureEnclave: MockSecureEnclave(),
            keychain: MockKeychain(),
            defaults: defaults,
            authenticationPromptCoordinator: TraceAuthenticationPromptCoordinator(traceStore: traceStore),
            traceStore: traceStore,
            localAuthenticationPolicyEvaluator: { _, policy, receivedReason, reply in
                XCTAssertEqual(policy, AppSessionAuthenticationPolicy.userPresence.localAuthenticationPolicy)
                XCTAssertEqual(receivedReason, reason)
                reply(false, TracePrivateKeyAccessTestError.seUnwrapFailed)
            }
        )

        do {
            _ = try await manager.evaluateAppSession(
                policy: .userPresence,
                reason: reason,
                source: "unit.appSession.throw"
            )
            XCTFail("Expected app session evaluation to throw")
        } catch AuthenticationError.failed {
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        assertTraceNames(
            traceStore.recentEntries.map(\.name),
            containOrdered: [
                "appSession.evaluate.policy.await.start",
                "appSession.evaluate.callback.call.start",
                "appSession.evaluate.callback.reply",
                "appSession.evaluate.callback.resume",
                "appSession.evaluate.policy.await.throw",
                "prompt.privacy.operation.await.throw",
                "appSession.evaluate.error",
                "appSession.evaluate.finish"
            ]
        )
        guard let throwEntry = traceStore.recentEntries.first(where: { $0.name == "appSession.evaluate.policy.await.throw" }) else {
            XCTFail("Expected policy await throw trace")
            return
        }
        XCTAssertEqual(throwEntry.metadata["policy"], "userPresence")
        XCTAssertEqual(throwEntry.metadata["source"], "unit.appSession.throw")
        XCTAssertEqual(throwEntry.metadata["errorType"], "TracePrivateKeyAccessTestError")
        XCTAssertNotNil(throwEntry.metadata["isMainThread"])
        guard let replyEntry = traceStore.recentEntries.first(where: { $0.name == "appSession.evaluate.callback.reply" }) else {
            XCTFail("Expected callback reply trace")
            return
        }
        XCTAssertEqual(replyEntry.metadata["policy"], "userPresence")
        XCTAssertEqual(replyEntry.metadata["source"], "unit.appSession.throw")
        XCTAssertEqual(replyEntry.metadata["result"], "error")
        XCTAssertEqual(replyEntry.metadata["errorType"], "TracePrivateKeyAccessTestError")
        XCTAssertNil(replyEntry.metadata["errorDescription"])

        let metadataKeys = Set(traceStore.recentEntries.flatMap { $0.metadata.keys })
        let metadataValues = traceStore.recentEntries.flatMap { $0.metadata.values }
        XCTAssertFalse(metadataKeys.contains("reason"))
        XCTAssertFalse(metadataValues.contains(reason))
    }

    func test_authenticationManager_evaluateModeBypass_recordsStartAndFinishTrace() async throws {
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

        let result = try await manager.evaluate(
            mode: .standard,
            reason: "Trace private key bypass",
            source: "unit.evaluateMode"
        )

        XCTAssertTrue(result)
        XCTAssertTrue(
            traceStore.recentEntries.contains {
                $0.name == "privateKey.evaluate.start"
                    && $0.metadata["mode"] == "standard"
                    && $0.metadata["source"] == "unit.evaluateMode"
                    && $0.metadata["promptID"] == "none"
            }
        )
        XCTAssertTrue(
            traceStore.recentEntries.contains {
                $0.name == "privateKey.evaluate.finish"
                    && $0.metadata["result"] == "bypass"
                    && $0.metadata["promptID"] == "none"
            }
        )
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
        manager.configurePrivateKeyControlStore(InMemoryPrivateKeyControlStore(mode: .standard))
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
        manager.configurePrivateKeyControlStore(InMemoryPrivateKeyControlStore(mode: .standard))

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
            authorizeSharedRight: { _, _ in
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
