import Foundation
import XCTest
@testable import CypherAir

private final class MockScopedResource: SecurityScopedResource {
    var startResult = true
    private(set) var startCalls = 0
    private(set) var stopCalls = 0

    func startAccessingSecurityScopedResource() -> Bool {
        startCalls += 1
        return startResult
    }

    func stopAccessingSecurityScopedResource() {
        stopCalls += 1
    }
}

private actor RunnerCallCounter {
    var count = 0

    func increment() {
        count += 1
    }

    func currentValue() -> Int {
        count
    }
}

@MainActor
private final class OperationGate {
    private var continuations: [Int: CheckedContinuation<Void, Never>] = [:]

    func suspend(operationID: Int) async {
        await withCheckedContinuation { continuation in
            continuations[operationID] = continuation
        }
    }

    func isSuspended(operationID: Int) -> Bool {
        continuations[operationID] != nil
    }

    func resume(operationID: Int) {
        continuations.removeValue(forKey: operationID)?.resume()
    }
}

private enum CommonHelpersTestError: Error {
    case delayedFailure
}

private final class FailingCompleteRewrapPrivateKeyControlStore: PrivateKeyControlStoreProtocol, @unchecked Sendable {
    private var mode: AuthenticationMode?
    private var journal: PrivateKeyControlRecoveryJournal
    var failNextCompleteRewrap = false

    init(
        mode: AuthenticationMode?,
        journal: PrivateKeyControlRecoveryJournal
    ) {
        self.mode = mode
        self.journal = journal
    }

    var privateKeyControlState: PrivateKeyControlState {
        guard let mode else {
            return .locked
        }
        return .unlocked(mode)
    }

    func requireUnlockedAuthMode() throws -> AuthenticationMode {
        guard let mode else {
            throw PrivateKeyControlError.locked
        }
        return mode
    }

    func recoveryJournal() throws -> PrivateKeyControlRecoveryJournal {
        _ = try requireUnlockedAuthMode()
        return journal
    }

    func beginRewrap(targetMode: AuthenticationMode) throws {
        _ = try requireUnlockedAuthMode()
        journal.rewrapTargetMode = targetMode
        journal.rewrapPhase = .preparing
    }

    func markRewrapCommitRequired() throws {
        _ = try requireUnlockedAuthMode()
        guard journal.rewrapTargetMode != nil else {
            throw PrivateKeyControlError.recoveryNeeded
        }
        journal.rewrapPhase = .commitRequired
    }

    func completeRewrap(targetMode: AuthenticationMode) throws {
        _ = try requireUnlockedAuthMode()
        if failNextCompleteRewrap {
            failNextCompleteRewrap = false
            throw CommonHelpersTestError.delayedFailure
        }
        mode = targetMode
        journal.rewrapTargetMode = nil
        journal.rewrapPhase = nil
    }

    func clearRewrapJournal() throws {
        _ = try requireUnlockedAuthMode()
        journal.rewrapTargetMode = nil
        journal.rewrapPhase = nil
    }

    func beginModifyExpiry(fingerprint: String) throws {
        _ = try requireUnlockedAuthMode()
        journal.modifyExpiry = ModifyExpiryRecoveryEntry(fingerprint: fingerprint)
    }

    func clearModifyExpiryJournal() throws {
        _ = try requireUnlockedAuthMode()
        journal.modifyExpiry = nil
    }

    func clearModifyExpiryJournalIfMatches(fingerprint: String) throws {
        _ = try requireUnlockedAuthMode()
        if journal.modifyExpiry?.fingerprint == fingerprint {
            journal.modifyExpiry = nil
        }
    }
}

@MainActor
final class CommonHelpersTests: XCTestCase {
    func test_securityScopedFileAccess_failure_stopsPreviouslyStartedResources() async {
        let first = MockScopedResource()
        let second = MockScopedResource()
        second.startResult = false

        do {
            _ = try await SecurityScopedFileAccess.withAccess(
                to: [
                    SecurityScopedAccessRequest(resource: first, failure: .internalError(reason: "first")),
                    SecurityScopedAccessRequest(resource: second, failure: .internalError(reason: "second"))
                ]
            ) {
                XCTFail("Operation should not run when a resource cannot be accessed")
                return ()
            }
            XCTFail("Expected an access failure")
        } catch let error as CypherAirError {
            XCTAssertEqual(error.localizedDescription, CypherAirError.internalError(reason: "second").localizedDescription)
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }

        XCTAssertEqual(first.startCalls, 1)
        XCTAssertEqual(first.stopCalls, 1)
        XCTAssertEqual(second.startCalls, 1)
        XCTAssertEqual(second.stopCalls, 0)
    }

    func test_securityScopedFileAccess_success_stopsAllResources() async throws {
        let first = MockScopedResource()
        let second = MockScopedResource()
        var didRun = false

        try await SecurityScopedFileAccess.withAccess(
            to: [
                SecurityScopedAccessRequest(resource: first, failure: .internalError(reason: "first")),
                SecurityScopedAccessRequest(resource: second, failure: .internalError(reason: "second"))
            ]
        ) {
            didRun = true
        }

        XCTAssertTrue(didRun)
        XCTAssertEqual(first.stopCalls, 1)
        XCTAssertEqual(second.stopCalls, 1)
    }

    func test_fileExportController_prepareDataExport_finishRemovesTemporaryFile() throws {
        let controller = FileExportController()

        try controller.prepareDataExport(
            Data("export me".utf8),
            suggestedFilename: "sample.asc"
        )

        guard let url = controller.payload?.url else {
            XCTFail("Expected a payload URL")
            return
        }

        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))
        controller.finish()
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
    }

    func test_privacyScreenLifecycleGate_allowsNormalResignAndActivation() {
        var gate = PrivacyScreenLifecycleGate()

        XCTAssertTrue(gate.shouldHandleResignActive(isAuthenticating: false))
        XCTAssertTrue(gate.shouldHandleBecomeActive(isAuthenticating: false))
    }

    func test_privacyScreenLifecycleGate_suppressesAuthPromptActivationBeforeAuthCompletes() {
        var gate = PrivacyScreenLifecycleGate()

        XCTAssertFalse(gate.shouldHandleResignActive(isAuthenticating: true))
        XCTAssertFalse(gate.shouldHandleBecomeActive(isAuthenticating: true))
        XCTAssertFalse(gate.shouldHandleBecomeActive(isAuthenticating: false))
        XCTAssertTrue(gate.shouldHandleBecomeActive(isAuthenticating: false))
    }

    func test_privacyScreenLifecycleGate_suppressesOnlyOneActivationPerAuthPromptCycle() {
        var gate = PrivacyScreenLifecycleGate()

        XCTAssertFalse(gate.shouldHandleResignActive(isAuthenticating: true))
        XCTAssertFalse(gate.shouldHandleBecomeActive(isAuthenticating: false))
        XCTAssertTrue(gate.shouldHandleBecomeActive(isAuthenticating: false))
    }

    func test_privacyScreenLifecycleGate_suppressesOneActivationForExternalAuthPromptCycle() {
        var gate = PrivacyScreenLifecycleGate()

        XCTAssertFalse(
            gate.shouldHandleResignActive(
                isAuthenticating: false,
                isOperationPromptInProgress: true
            )
        )
        XCTAssertFalse(gate.shouldHandleBecomeActive(isAuthenticating: false))
        XCTAssertTrue(gate.shouldHandleBecomeActive(isAuthenticating: false))
    }

    func test_privacyScreenLifecycleGate_observedOperationPromptGenerationSuppressesLateInactiveAndActivation() {
        var gate = PrivacyScreenLifecycleGate()

        gate.syncOperationAuthenticationAttemptGeneration(1)

        XCTAssertFalse(
            gate.shouldHandleResignActive(
                isAuthenticating: false,
                isOperationPromptInProgress: false
            )
        )
        XCTAssertFalse(gate.shouldHandleBecomeActive(isAuthenticating: false))
        XCTAssertTrue(gate.shouldHandleBecomeActive(isAuthenticating: false))
    }

    func test_privacyScreenLifecycleGate_activeDuringPromptDoesNotConsumeSuppression() {
        var gate = PrivacyScreenLifecycleGate()

        gate.armForAuthenticationAttempt()

        XCTAssertFalse(
            gate.shouldHandleBecomeActive(
                isAuthenticating: false,
                isOperationPromptInProgress: true
            )
        )
        XCTAssertFalse(gate.shouldHandleBecomeActive(isAuthenticating: false))
        XCTAssertTrue(gate.shouldHandleBecomeActive(isAuthenticating: false))
    }

    func test_privacyScreenLifecycleGate_backgroundClearsPromptSuppression() {
        var gate = PrivacyScreenLifecycleGate()

        gate.armForAuthenticationAttempt()

        XCTAssertTrue(gate.shouldHandleBackground())
        XCTAssertTrue(gate.shouldHandleBecomeActive(isAuthenticating: false))
    }

    func test_privacyScreenLifecycleGate_backgroundClearsObservedOperationPromptSuppression() {
        var gate = PrivacyScreenLifecycleGate()

        gate.syncOperationAuthenticationAttemptGeneration(1)

        XCTAssertTrue(gate.shouldHandleBackground())

        gate.syncOperationAuthenticationAttemptGeneration(1)

        XCTAssertTrue(gate.shouldHandleBecomeActive(isAuthenticating: false))
    }

    func test_privacyScreenLifecycleGate_authenticationAttemptSuppressesActivationWithoutResignEvent() {
        var gate = PrivacyScreenLifecycleGate()

        gate.armForAuthenticationAttempt()

        XCTAssertFalse(gate.shouldHandleBecomeActive(isAuthenticating: false))
    }

    func test_privacyScreenLifecycleGate_authenticationAttemptSuppressionIsConsumedAfterOneActivation() {
        var gate = PrivacyScreenLifecycleGate()

        gate.armForAuthenticationAttempt()

        XCTAssertFalse(gate.shouldHandleBecomeActive(isAuthenticating: false))
        XCTAssertTrue(gate.shouldHandleBecomeActive(isAuthenticating: false))
    }

    func test_operationController_runFileOperation_usesBackgroundRunnerAndClearsState() async {
        let runnerCallCounter = RunnerCallCounter()
        let controller = OperationController(
            backgroundRunner: { operation in
                await runnerCallCounter.increment()
                try await operation()
            }
        )

        controller.runFileOperation(
            mapError: { _ in .internalError(reason: "unexpected") }
        ) { progress in
            _ = progress.onProgress(bytesProcessed: 5, totalBytes: 10)
        }

        while controller.isRunning {
            await Task.yield()
        }

        let runnerCallCount = await runnerCallCounter.currentValue()
        XCTAssertEqual(runnerCallCount, 1)
        XCTAssertNil(controller.progress)
        XCTAssertFalse(controller.isShowingError)
    }

    func test_operationController_copyToClipboard_showsNoticeWhenRequested() {
        let controller = OperationController()

        controller.copyToClipboard("ciphertext", shouldShowNotice: true)

        XCTAssertTrue(controller.isShowingClipboardNotice)
    }

    func test_operationController_copyToClipboard_skipsNoticeWhenDisabled() {
        let controller = OperationController()

        controller.copyToClipboard("ciphertext", shouldShowNotice: false)

        XCTAssertFalse(controller.isShowingClipboardNotice)
    }

    func test_operationController_cancel_keepsBusyUntilTaskFinishes() async {
        let gate = OperationGate()
        let controller = OperationController()

        controller.runFileOperation(mapError: { _ in .internalError(reason: "unexpected") }) { progress in
            _ = progress.onProgress(bytesProcessed: 5, totalBytes: 10)
            await gate.suspend(operationID: 1)
        }

        await waitUntil("operation to suspend before cancellation") {
            guard controller.isRunning, controller.progress != nil else { return false }
            return gate.isSuspended(operationID: 1)
        }

        controller.cancel()

        XCTAssertTrue(controller.isRunning)
        XCTAssertTrue(controller.isCancelling)
        XCTAssertNotNil(controller.progress)

        gate.resume(operationID: 1)

        await waitUntil("controller to finish cancelling") {
            controller.isRunning == false
        }

        XCTAssertFalse(controller.isCancelling)
        XCTAssertNil(controller.progress)
        XCTAssertFalse(controller.isShowingError)
    }

    func test_operationController_staleCompletionDoesNotClearReplacementOperation() async {
        let gate = OperationGate()
        let controller = OperationController()
        var startedOperations = 0

        controller.runFileOperation(mapError: { _ in .internalError(reason: "unexpected") }) { progress in
            startedOperations += 1
            let operationID = startedOperations
            _ = progress.onProgress(bytesProcessed: UInt64(operationID), totalBytes: 10)
            await gate.suspend(operationID: operationID)
        }

        await waitUntil("first operation to suspend") {
            guard controller.isRunning, controller.progress != nil else { return false }
            return gate.isSuspended(operationID: 1)
        }

        controller.cancel()
        controller.runFileOperation(mapError: { _ in .internalError(reason: "unexpected") }) { progress in
            startedOperations += 1
            let operationID = startedOperations
            _ = progress.onProgress(bytesProcessed: UInt64(operationID), totalBytes: 10)
            await gate.suspend(operationID: operationID)
        }

        await waitUntil("replacement operation to suspend") {
            guard controller.isRunning, !controller.isCancelling else { return false }
            return gate.isSuspended(operationID: 2)
        }

        let replacementProgress = controller.progress
        gate.resume(operationID: 1)
        await Task.yield()
        await Task.yield()

        XCTAssertTrue(controller.isRunning)
        XCTAssertFalse(controller.isCancelling)
        XCTAssertTrue(controller.progress === replacementProgress)

        gate.resume(operationID: 2)
        await waitUntil("replacement operation to finish") {
            controller.isRunning == false
        }
    }

    func test_operationController_staleErrorDoesNotSurfaceForReplacementOperation() async {
        let gate = OperationGate()
        let controller = OperationController()
        var startedOperations = 0

        controller.run(mapError: { _ in .internalError(reason: "stale failure") }) {
            startedOperations += 1
            let operationID = startedOperations
            await gate.suspend(operationID: operationID)
            if operationID == 1 {
                throw CommonHelpersTestError.delayedFailure
            }
        }

        await waitUntil("first operation to suspend") {
            guard controller.isRunning else { return false }
            return gate.isSuspended(operationID: 1)
        }

        controller.cancel()
        controller.run(mapError: { _ in .internalError(reason: "replacement failure") }) {
            startedOperations += 1
            let operationID = startedOperations
            await gate.suspend(operationID: operationID)
        }

        await waitUntil("replacement operation to suspend") {
            guard controller.isRunning, !controller.isCancelling else { return false }
            return gate.isSuspended(operationID: 2)
        }

        gate.resume(operationID: 1)
        await Task.yield()
        await Task.yield()

        XCTAssertFalse(controller.isShowingError)
        XCTAssertNil(controller.error)

        gate.resume(operationID: 2)
        await waitUntil("replacement operation to finish") {
            controller.isRunning == false
        }

        XCTAssertFalse(controller.isShowingError)
        XCTAssertNil(controller.error)
    }

    func test_appStartupCoordinator_mergedStartupMessages_appendsRecoveryDiagnostics() {
        let coordinator = AppStartupCoordinator()
        let merged = coordinator.mergedStartupMessages(
            loadErrors: ["Contacts failed to load"],
            recoveryDiagnostics: [
                "A previous secure key migration could not be recovered. Restore from backup if private-key operations fail."
            ]
        )

        XCTAssertEqual(
            merged,
            """
            Contacts failed to load
            A previous secure key migration could not be recovered. Restore from backup if private-key operations fail.
            """
        )
    }

    func test_appStartupCoordinator_mergedStartupMessages_recoveryDiagnostic_isGeneric() {
        let coordinator = AppStartupCoordinator()
        let merged = coordinator.mergedStartupMessages(
            loadErrors: [],
            recoveryDiagnostics: [
                "A previous secure key migration could not be fully recovered. CypherAir will retry recovery on next launch."
            ]
        )

        XCTAssertNotNil(merged)
        XCTAssertFalse(merged?.contains("fingerprint") == true)
        XCTAssertFalse(merged?.contains("89abcdef") == true)
    }

    func test_rewrapRecovery_commitRequiredNoPending_retriesTargetModePersistence() throws {
        let keychain = MockKeychain()
        let fingerprint = "commit-required-\(UUID().uuidString)"
        try savePermanentRecoveryBundle(in: keychain, fingerprint: fingerprint)

        let privateKeyControlStore = FailingCompleteRewrapPrivateKeyControlStore(
            mode: .standard,
            journal: PrivateKeyControlRecoveryJournal(
                rewrapTargetMode: .highSecurity,
                rewrapPhase: .commitRequired
            )
        )
        privateKeyControlStore.failNextCompleteRewrap = true
        let authManager = makeRecoveryAuthenticationManager(
            keychain: keychain,
            privateKeyControlStore: privateKeyControlStore
        )

        let firstSummary = authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        XCTAssertEqual(firstSummary?.outcomes, [.noActionSafe, .retryableFailure])
        XCTAssertEqual(try privateKeyControlStore.recoveryJournal().rewrapTargetMode, .highSecurity)
        XCTAssertEqual(try privateKeyControlStore.recoveryJournal().rewrapPhase, .commitRequired)
        XCTAssertEqual(authManager.currentMode, .standard)
        XCTAssertFalse(firstSummary?.startupDiagnostics.isEmpty ?? true)

        let secondSummary = authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        XCTAssertEqual(secondSummary?.outcomes, [.noActionSafe])
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapTargetMode)
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapPhase)
        XCTAssertEqual(authManager.currentMode, .highSecurity)
    }

    func test_rewrapRecovery_preparingNoPending_clearsJournalWithoutChangingMode() throws {
        let keychain = MockKeychain()
        let fingerprint = "preparing-\(UUID().uuidString)"
        try savePermanentRecoveryBundle(in: keychain, fingerprint: fingerprint)

        let privateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        try privateKeyControlStore.beginRewrap(targetMode: .highSecurity)
        let authManager = makeRecoveryAuthenticationManager(
            keychain: keychain,
            privateKeyControlStore: privateKeyControlStore
        )

        let summary = authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        XCTAssertEqual(summary?.outcomes, [.noActionSafe])
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapTargetMode)
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapPhase)
        XCTAssertEqual(authManager.currentMode, .standard)
    }

    func test_rewrapRecovery_preparingOldAndPending_cleansPendingKeepsOldMode() throws {
        let keychain = MockKeychain()
        let fingerprint = "preparing-clean-\(UUID().uuidString)"
        try savePermanentRecoveryBundle(in: keychain, fingerprint: fingerprint)
        try savePendingRecoveryBundle(in: keychain, fingerprint: fingerprint)

        let privateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        try privateKeyControlStore.beginRewrap(targetMode: .highSecurity)
        let authManager = makeRecoveryAuthenticationManager(
            keychain: keychain,
            privateKeyControlStore: privateKeyControlStore
        )

        let summary = authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        XCTAssertEqual(summary?.outcomes, [.cleanedPendingSafe])
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapTargetMode)
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapPhase)
        XCTAssertEqual(authManager.currentMode, .standard)
        XCTAssertEqual(
            try keychain.load(
                service: KeychainConstants.seKeyService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount
            ),
            Data("permanent-se-key".utf8)
        )
        XCTAssertFalse(keychain.exists(
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount
        ))
    }

    func test_rewrapRecovery_commitRequiredOldAndPending_replacesPermanentWithPending() throws {
        let keychain = MockKeychain()
        let fingerprint = "commit-replace-\(UUID().uuidString)"
        try savePermanentRecoveryBundle(in: keychain, fingerprint: fingerprint)
        try savePendingRecoveryBundle(in: keychain, fingerprint: fingerprint)

        let privateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        try privateKeyControlStore.beginRewrap(targetMode: .highSecurity)
        try privateKeyControlStore.markRewrapCommitRequired()
        let authManager = makeRecoveryAuthenticationManager(
            keychain: keychain,
            privateKeyControlStore: privateKeyControlStore
        )

        let summary = authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        XCTAssertEqual(summary?.outcomes, [.promotedPendingSafe])
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapTargetMode)
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapPhase)
        XCTAssertEqual(authManager.currentMode, .highSecurity)
        XCTAssertEqual(
            try keychain.load(
                service: KeychainConstants.seKeyService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount
            ),
            Data("pending-se-key".utf8)
        )
        XCTAssertFalse(keychain.exists(
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount
        ))
    }

    func test_rewrapRecovery_commitRequiredMixedPhaseB_promotesAllTargetBundles() throws {
        let keychain = MockKeychain()
        let pendingOnlyFingerprint = "commit-pending-\(UUID().uuidString)"
        let oldAndPendingFingerprint = "commit-mixed-\(UUID().uuidString)"
        try savePendingRecoveryBundle(in: keychain, fingerprint: pendingOnlyFingerprint)
        try savePermanentRecoveryBundle(in: keychain, fingerprint: oldAndPendingFingerprint)
        try savePendingRecoveryBundle(in: keychain, fingerprint: oldAndPendingFingerprint)

        let privateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        try privateKeyControlStore.beginRewrap(targetMode: .highSecurity)
        try privateKeyControlStore.markRewrapCommitRequired()
        let authManager = makeRecoveryAuthenticationManager(
            keychain: keychain,
            privateKeyControlStore: privateKeyControlStore
        )

        let summary = authManager.checkAndRecoverFromInterruptedRewrap(
            fingerprints: [pendingOnlyFingerprint, oldAndPendingFingerprint]
        )

        XCTAssertEqual(summary?.outcomes, [.promotedPendingSafe, .promotedPendingSafe])
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapTargetMode)
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapPhase)
        XCTAssertEqual(authManager.currentMode, .highSecurity)
        for fingerprint in [pendingOnlyFingerprint, oldAndPendingFingerprint] {
            XCTAssertEqual(
                try keychain.load(
                    service: KeychainConstants.seKeyService(fingerprint: fingerprint),
                    account: KeychainConstants.defaultAccount
                ),
                Data("pending-se-key".utf8)
            )
            XCTAssertFalse(keychain.exists(
                service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount
            ))
        }
    }

    func test_rewrapRecovery_commitRequiredPartialPending_keepsJournalAndFailsClosed() throws {
        let keychain = MockKeychain()
        let fingerprint = "commit-partial-\(UUID().uuidString)"
        try savePermanentRecoveryBundle(in: keychain, fingerprint: fingerprint)
        try savePartialPendingRecoveryBundle(in: keychain, fingerprint: fingerprint)

        let privateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        try privateKeyControlStore.beginRewrap(targetMode: .highSecurity)
        try privateKeyControlStore.markRewrapCommitRequired()
        let authManager = makeRecoveryAuthenticationManager(
            keychain: keychain,
            privateKeyControlStore: privateKeyControlStore
        )

        let summary = authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        XCTAssertEqual(summary?.outcomes, [.retryableFailure])
        XCTAssertEqual(try privateKeyControlStore.recoveryJournal().rewrapTargetMode, .highSecurity)
        XCTAssertEqual(try privateKeyControlStore.recoveryJournal().rewrapPhase, .commitRequired)
        XCTAssertEqual(authManager.currentMode, .standard)
        XCTAssertEqual(
            try keychain.load(
                service: KeychainConstants.seKeyService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount
            ),
            Data("permanent-se-key".utf8)
        )
        XCTAssertTrue(keychain.exists(
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount
        ))
    }

    func test_postUnlockRecoveryWarningBuilder_surfacesOnlyUnsafeOutcomes() {
        let retryableWarning = AppContainer.postUnlockRecoveryLoadWarning(
            rewrapSummary: KeyMigrationRecoverySummary(outcomes: [.noActionSafe, .retryableFailure]),
            modifyExpiryOutcome: nil
        )
        XCTAssertNotNil(retryableWarning)
        XCTAssertTrue(retryableWarning?.contains("retry") == true)

        let duplicateWarning = AppContainer.postUnlockRecoveryLoadWarning(
            rewrapSummary: KeyMigrationRecoverySummary(outcomes: [.retryableFailure]),
            modifyExpiryOutcome: .retryableFailure
        )
        XCTAssertEqual(duplicateWarning?.components(separatedBy: "\n").count, 1)

        let unrecoverableWarning = AppContainer.postUnlockRecoveryLoadWarning(
            rewrapSummary: nil,
            modifyExpiryOutcome: .unrecoverable
        )
        XCTAssertNotNil(unrecoverableWarning)
        XCTAssertTrue(unrecoverableWarning?.contains("Restore from backup") == true)

        XCTAssertNil(AppContainer.postUnlockRecoveryLoadWarning(
            rewrapSummary: KeyMigrationRecoverySummary(outcomes: [.noActionSafe, .cleanedPendingSafe]),
            modifyExpiryOutcome: .cleanedPendingSafe
        ))
    }

    func test_postUnlockRecovery_resyncsConfigAfterRewrapCompletes() async throws {
        let suiteName = "com.cypherair.postUnlockSync.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.removePersistentDomain(forName: suiteName)
        defer { defaults.removePersistentDomain(forName: suiteName) }

        let keychain = MockKeychain()
        let secureEnclave = MockSecureEnclave()
        let privateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        let authManager = makeRecoveryAuthenticationManager(
            keychain: keychain,
            privateKeyControlStore: privateKeyControlStore
        )
        let keyManagement = KeyManagementService(
            engine: PgpEngine(),
            secureEnclave: secureEnclave,
            keychain: keychain,
            authenticator: authManager,
            defaults: defaults,
            privateKeyControlStore: privateKeyControlStore
        )
        _ = try await keyManagement.generateKey(
            name: "Post Unlock",
            email: "post-unlock@example.invalid",
            expirySeconds: nil,
            profile: .universal,
            authMode: .standard
        )
        try privateKeyControlStore.beginRewrap(targetMode: .highSecurity)
        try privateKeyControlStore.markRewrapCommitRequired()

        let config = AppConfiguration(defaults: defaults)
        config.privateKeyControlState = .unlocked(.standard)

        AppContainer.recoverPrivateKeyControlJournalsAfterPostUnlock(
            authManager: authManager,
            keyManagement: keyManagement,
            config: config,
            privateKeyControlStore: privateKeyControlStore
        )

        XCTAssertEqual(config.authModeIfUnlocked, .highSecurity)
        XCTAssertNil(config.postUnlockRecoveryLoadWarning)
    }

    func test_postUnlockRecovery_warningPathStillResyncsConfig() async throws {
        let suiteName = "com.cypherair.postUnlockWarningSync.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.removePersistentDomain(forName: suiteName)
        defer { defaults.removePersistentDomain(forName: suiteName) }

        let keychain = MockKeychain()
        let privateKeyControlStore = FailingCompleteRewrapPrivateKeyControlStore(
            mode: .standard,
            journal: .empty
        )
        let authManager = makeRecoveryAuthenticationManager(
            keychain: keychain,
            privateKeyControlStore: privateKeyControlStore
        )
        let keyManagement = KeyManagementService(
            engine: PgpEngine(),
            secureEnclave: MockSecureEnclave(),
            keychain: keychain,
            authenticator: authManager,
            defaults: defaults,
            privateKeyControlStore: privateKeyControlStore
        )
        _ = try await keyManagement.generateKey(
            name: "Post Unlock Warning",
            email: "post-unlock-warning@example.invalid",
            expirySeconds: nil,
            profile: .universal,
            authMode: .standard
        )
        try privateKeyControlStore.beginRewrap(targetMode: .highSecurity)
        try privateKeyControlStore.markRewrapCommitRequired()
        privateKeyControlStore.failNextCompleteRewrap = true

        let config = AppConfiguration(defaults: defaults)
        config.privateKeyControlState = .unlocked(.highSecurity)

        AppContainer.recoverPrivateKeyControlJournalsAfterPostUnlock(
            authManager: authManager,
            keyManagement: keyManagement,
            config: config,
            privateKeyControlStore: privateKeyControlStore
        )

        XCTAssertEqual(config.authModeIfUnlocked, .standard)
        XCTAssertTrue(config.postUnlockRecoveryLoadWarning?.contains("retry") == true)
        XCTAssertEqual(try privateKeyControlStore.recoveryJournal().rewrapTargetMode, .highSecurity)
    }

    private func makeRecoveryAuthenticationManager(
        keychain: MockKeychain,
        privateKeyControlStore: any PrivateKeyControlStoreProtocol
    ) -> AuthenticationManager {
        AuthenticationManager(
            secureEnclave: MockSecureEnclave(),
            keychain: keychain,
            privateKeyControlStore: privateKeyControlStore
        )
    }

    private func savePermanentRecoveryBundle(
        in keychain: MockKeychain,
        fingerprint: String
    ) throws {
        let account = KeychainConstants.defaultAccount
        try keychain.save(
            Data("permanent-se-key".utf8),
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
        try keychain.save(
            Data("permanent-salt".utf8),
            service: KeychainConstants.saltService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
        try keychain.save(
            Data("permanent-sealed".utf8),
            service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
    }

    private func savePendingRecoveryBundle(
        in keychain: MockKeychain,
        fingerprint: String
    ) throws {
        let account = KeychainConstants.defaultAccount
        try keychain.save(
            Data("pending-se-key".utf8),
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
        try keychain.save(
            Data("pending-salt".utf8),
            service: KeychainConstants.pendingSaltService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
        try keychain.save(
            Data("pending-sealed".utf8),
            service: KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
    }

    private func savePartialPendingRecoveryBundle(
        in keychain: MockKeychain,
        fingerprint: String
    ) throws {
        try keychain.save(
            Data("partial-pending-se-key".utf8),
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
    }

    func test_appStartupCoordinator_deletedKeyDoesNotRestoreInterruptedModifyExpiryBundle() async throws {
        let engine = PgpEngine()
        let mockSE = MockSecureEnclave()
        let mockKC = MockKeychain()
        let suiteName = "com.cypherair.startup.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.removePersistentDomain(forName: suiteName)
        defer { defaults.removePersistentDomain(forName: suiteName) }

        let setupAuthManager = AuthenticationManager(
            secureEnclave: mockSE,
            keychain: mockKC,
            defaults: defaults
        )
        let setupPrivateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        setupAuthManager.configurePrivateKeyControlStore(setupPrivateKeyControlStore)
        let setupKeyManagement = KeyManagementService(
            engine: engine,
            secureEnclave: mockSE,
            keychain: mockKC,
            authenticator: setupAuthManager,
            defaults: defaults,
            privateKeyControlStore: setupPrivateKeyControlStore
        )

        let identity = try await setupKeyManagement.generateKey(
            name: "Startup Test",
            email: "startup@example.com",
            expirySeconds: nil,
            profile: .universal,
            authMode: .standard
        )
        let fingerprint = identity.fingerprint
        let account = KeychainConstants.defaultAccount

        let seKeyData = try mockKC.load(
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: account
        )
        let saltData = try mockKC.load(
            service: KeychainConstants.saltService(fingerprint: fingerprint),
            account: account
        )
        let sealedData = try mockKC.load(
            service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
            account: account
        )

        try mockKC.save(
            seKeyData,
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
        try mockKC.save(
            saltData,
            service: KeychainConstants.pendingSaltService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
        try mockKC.save(
            sealedData,
            service: KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )

        defaults.set(true, forKey: AuthPreferences.modifyExpiryInProgressKey)
        defaults.set(fingerprint, forKey: AuthPreferences.modifyExpiryFingerprintKey)

        try setupKeyManagement.deleteKey(fingerprint: fingerprint)

        let authPromptCoordinator = CypherAir.AuthenticationPromptCoordinator()
        let authManager = AuthenticationManager(
            secureEnclave: mockSE,
            keychain: mockKC,
            defaults: defaults,
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let keyManagementPrivateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        authManager.configurePrivateKeyControlStore(keyManagementPrivateKeyControlStore)
        let keyManagement = KeyManagementService(
            engine: engine,
            secureEnclave: mockSE,
            keychain: mockKC,
            authenticator: authManager,
            defaults: defaults,
            authenticationPromptCoordinator: authPromptCoordinator,
            privateKeyControlStore: keyManagementPrivateKeyControlStore
        )
        let config = AppConfiguration(defaults: defaults)
        let contactDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirStartupTests-\(UUID().uuidString)", isDirectory: true)
        let protectedDataBaseDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirProtectedDataStartupTests-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: contactDirectory) }
        defer { try? FileManager.default.removeItem(at: protectedDataBaseDirectory) }
        let protectedDataStorageRoot = CypherAir.ProtectedDataStorageRoot(baseDirectory: protectedDataBaseDirectory)
        let protectedDomainKeyManager = CypherAir.ProtectedDomainKeyManager(storageRoot: protectedDataStorageRoot)
        let protectedDataRegistryStore = CypherAir.ProtectedDataRegistryStore(
            storageRoot: protectedDataStorageRoot,
            sharedRightIdentifier: CypherAir.ProtectedDataRightIdentifiers.productionSharedRightIdentifier
        )
        let protectedDomainRecoveryCoordinator = CypherAir.ProtectedDomainRecoveryCoordinator(
            registryStore: protectedDataRegistryStore
        )
        let protectedDataSessionCoordinator = CypherAir.ProtectedDataSessionCoordinator(
            rootSecretStore: CypherAir.MockProtectedDataRootSecretStore(),
            legacyRightStoreClient: CypherAir.ProtectedDataRightStoreClient(),
            domainKeyManager: protectedDomainKeyManager,
            sharedRightIdentifier: CypherAir.ProtectedDataRightIdentifiers.productionSharedRightIdentifier,
            appSessionPolicyProvider: { config.appSessionAuthenticationPolicy },
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let protectedSettingsStore = ProtectedSettingsStore(
            defaults: defaults,
            storageRoot: protectedDataStorageRoot,
            registryStore: protectedDataRegistryStore,
            domainKeyManager: protectedDomainKeyManager,
            currentWrappingRootKey: {
                try protectedDataSessionCoordinator.wrappingRootKeyData()
            }
        )
        let protectedDataFrameworkSentinelStore = ProtectedDataFrameworkSentinelStore(
            storageRoot: protectedDataStorageRoot,
            registryStore: protectedDataRegistryStore,
            domainKeyManager: protectedDomainKeyManager,
            currentWrappingRootKey: {
                try protectedDataSessionCoordinator.wrappingRootKeyData()
            }
        )
        let privateKeyControlStore = PrivateKeyControlStore(
            defaults: defaults,
            storageRoot: protectedDataStorageRoot,
            registryStore: protectedDataRegistryStore,
            domainKeyManager: protectedDomainKeyManager,
            currentWrappingRootKey: {
                try protectedDataSessionCoordinator.wrappingRootKeyData()
            }
        )
        authManager.configurePrivateKeyControlStore(privateKeyControlStore)
        protectedDataSessionCoordinator.registerRelockParticipant(privateKeyControlStore)
        protectedDataSessionCoordinator.registerRelockParticipant(protectedSettingsStore)
        protectedDataSessionCoordinator.registerRelockParticipant(protectedDataFrameworkSentinelStore)
        let appSessionOrchestrator = CypherAir.AppSessionOrchestrator(
            currentRegistryProvider: {
                try protectedDomainRecoveryCoordinator.loadCurrentRegistry()
            },
            shouldBypassPrivacyAuthentication: { false },
            gracePeriodProvider: { config.gracePeriod },
            evaluateAppAuthentication: { reason in
                try await authManager.evaluateAppSession(
                    policy: config.appSessionAuthenticationPolicy,
                    reason: reason
                )
            },
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            authenticationPromptCoordinator: authPromptCoordinator
        )
        let contactService = ContactService(engine: engine, contactsDirectory: contactDirectory)
        let encryptionService = EncryptionService(
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let decryptionService = DecryptionService(
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let passwordMessageService = PasswordMessageService(
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let signingService = SigningService(
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let certificateSignatureService = CertificateSignatureService(
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService
        )
        let qrService = QRService(engine: engine)
        let selfTestService = SelfTestService(engine: engine)
        let localDataResetService = LocalDataResetService(
            keychain: mockKC,
            protectedDataStorageRoot: protectedDataStorageRoot,
            contactsDirectory: contactDirectory,
            defaults: defaults,
            defaultsDomainName: suiteName,
            config: config,
            authManager: authManager,
            keyManagement: keyManagement,
            contactService: contactService,
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            appSessionOrchestrator: appSessionOrchestrator
        )
        let container = AppContainer(
            authLifecycleTraceStore: nil,
            authenticationShieldCoordinator: CypherAir.AuthenticationShieldCoordinator(),
            authPromptCoordinator: authPromptCoordinator,
            secureEnclave: mockSE,
            keychain: mockKC,
            authManager: authManager,
            config: config,
            protectedDataStorageRoot: protectedDataStorageRoot,
            protectedDataRegistryStore: protectedDataRegistryStore,
            protectedDomainKeyManager: protectedDomainKeyManager,
            protectedDomainRecoveryCoordinator: protectedDomainRecoveryCoordinator,
            protectedDataSessionCoordinator: protectedDataSessionCoordinator,
            privateKeyControlStore: privateKeyControlStore,
            protectedSettingsStore: protectedSettingsStore,
            protectedDataFrameworkSentinelStore: protectedDataFrameworkSentinelStore,
            appSessionOrchestrator: appSessionOrchestrator,
            engine: engine,
            keyManagement: keyManagement,
            contactService: contactService,
            encryptionService: encryptionService,
            decryptionService: decryptionService,
            passwordMessageService: passwordMessageService,
            signingService: signingService,
            certificateSignatureService: certificateSignatureService,
            qrService: qrService,
            selfTestService: selfTestService,
            localDataResetService: localDataResetService,
            contactsDirectory: contactDirectory,
            defaultsSuiteName: suiteName
        )

        let result = AppStartupCoordinator().performStartup(using: container)

        XCTAssertNil(result.loadError)
        XCTAssertTrue(keyManagement.keys.isEmpty)
        XCTAssertTrue(defaults.bool(forKey: AuthPreferences.modifyExpiryInProgressKey))
        XCTAssertEqual(defaults.string(forKey: AuthPreferences.modifyExpiryFingerprintKey), fingerprint)
        XCTAssertFalse(mockKC.exists(
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: account
        ))
        XCTAssertFalse(mockKC.exists(
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: account
        ))
    }

    func test_importedTextInputState_preservesRawData_untilVisibleTextChanges() {
        var state = ImportedTextInputState()
        let text = "-----BEGIN PGP MESSAGE-----\nVersion: Test\n\nabc\n-----END PGP MESSAGE-----"
        let data = Data(text.utf8)

        state.setImportedFile(data: data, fileName: "encrypted.asc", text: text)

        XCTAssertTrue(state.hasImportedFile)
        XCTAssertEqual(state.rawData, data)
        XCTAssertEqual(state.fileName, "encrypted.asc")
        XCTAssertEqual(state.textSnapshot, text)
        XCTAssertFalse(state.invalidateIfEditedTextDiffers(text))
        XCTAssertEqual(state.rawData, data)

        XCTAssertTrue(state.invalidateIfEditedTextDiffers(text + "\n"))
        XCTAssertFalse(state.hasImportedFile)
        XCTAssertNil(state.rawData)
        XCTAssertNil(state.fileName)
        XCTAssertNil(state.textSnapshot)
    }

    func test_importedTextInputState_clear_removesAuthoritativeData() {
        var state = ImportedTextInputState()
        let text = "-----BEGIN PGP SIGNED MESSAGE-----\n\nhello"
        state.setImportedFile(data: Data(text.utf8), fileName: "signed.asc", text: text)

        state.clear()

        XCTAssertFalse(state.hasImportedFile)
        XCTAssertNil(state.rawData)
        XCTAssertNil(state.fileName)
        XCTAssertNil(state.textSnapshot)
    }

    func test_importedTextInputState_reimport_replacesPreviousBytesAndSnapshot() {
        var state = ImportedTextInputState()
        state.setImportedFile(
            data: Data("old".utf8),
            fileName: "old.asc",
            text: "old"
        )

        state.setImportedFile(
            data: Data("new".utf8),
            fileName: "new.asc",
            text: "new"
        )

        XCTAssertTrue(state.hasImportedFile)
        XCTAssertEqual(state.rawData, Data("new".utf8))
        XCTAssertEqual(state.fileName, "new.asc")
        XCTAssertEqual(state.textSnapshot, "new")
    }

    func test_armoredTextMessageClassifier_armoredEncryptedMessage_matches() throws {
        let data = try FixtureLoader.loadData("gpg_encrypted_message", ext: "asc")

        let result = ArmoredTextMessageClassifier.classify(fileSize: data.count, data: data)

        XCTAssertEqual(result, .encryptedTextMessage)
    }

    func test_armoredTextMessageClassifier_cleartextSignedMessage_doesNotMatch() throws {
        let data = try FixtureLoader.loadData("gpg_cleartext_signed", ext: "asc")

        let result = ArmoredTextMessageClassifier.classify(fileSize: data.count, data: data)

        XCTAssertEqual(result, .other)
    }

    func test_armoredTextMessageClassifier_binaryMessage_doesNotMatch() throws {
        let data = try FixtureLoader.loadData("gpg_encrypted_message", ext: "gpg")

        let result = ArmoredTextMessageClassifier.classify(fileSize: data.count, data: data)

        XCTAssertEqual(result, .other)
    }

    func test_armoredTextMessageClassifier_oversizedArmoredMessage_doesNotMatch() {
        let oversizedText =
            "-----BEGIN PGP MESSAGE-----\n"
            + String(repeating: "A", count: ArmoredTextMessageClassifier.maxInspectableFileSize + 1)
        let data = Data(oversizedText.utf8)

        let result = ArmoredTextMessageClassifier.classify(fileSize: data.count, data: data)

        XCTAssertEqual(result, .other)
    }

    private func waitUntil(
        _ description: String,
        timeoutNanoseconds: UInt64 = 1_000_000_000,
        condition: @escaping @MainActor () async -> Bool
    ) async {
        let deadline = DispatchTime.now().uptimeNanoseconds + timeoutNanoseconds
        while DispatchTime.now().uptimeNanoseconds < deadline {
            if await condition() {
                return
            }
            try? await Task.sleep(nanoseconds: 1_000_000)
        }
        XCTFail("Timed out waiting for \(description)")
    }
}
