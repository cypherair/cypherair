import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir

/// Tests for the app-session-authentication concerns `AppSessionOrchestrator`
/// owns: the authenticated-`LAContext` handoff custody, the
/// `lastAuthenticationDate` record, the view-observed `contentClearGeneration`
/// signal, and the Local Data Reset hook.
///
/// The lock state machine (lock/cover/grace/away/foreground) lives in
/// `AppLockController`; its behavior is covered by `AppLockControllerTests`. The
/// Protected App-Data access gate is covered by `ProtectedDataAccessGatePostUnlockTests`.
@MainActor
final class ProtectedDataAppSessionOrchestratorTests: ProtectedDataFrameworkTestCase {
    private func makeOrchestrator() -> AppSessionOrchestrator {
        let storageRoot = ProtectedDataTestAppProtectedDataStorageRoot(
            baseDirectory: makeTemporaryDirectory("OrchestratorCustody")
        )
        let keyManager = ProtectedDataTestAppProtectedDomainKeyManager(storageRoot: storageRoot, keychain: MockKeychain())
        let rightStoreClient = RecordingProtectedDataRootSecretStore()
        let coordinator = ProtectedDataTestAppProtectedDataSessionCoordinator(
            rootSecretStore: rightStoreClient,
            domainKeyManager: keyManager,
            sharedRightIdentifier: "com.cypherair.tests.orchestrator.custody",
            authenticationPromptCoordinator: AuthenticationPromptCoordinator()
        )
        return AppSessionOrchestrator(
            currentRegistryProvider: { throw ProtectedDataError.invalidRegistry("not needed") },
            protectedDataSessionCoordinator: coordinator
        )
    }

    func test_recordSuccessfulAuthentication_storesHandoffContextAndRecordsDate() {
        let orchestrator = makeOrchestrator()
        XCTAssertNil(orchestrator.lastAuthenticationDate)
        XCTAssertFalse(orchestrator.hasProtectedDataAuthorizationHandoffContext)

        let context = LAContext()
        orchestrator.recordSuccessfulAppSessionAuthentication(context: context)

        XCTAssertNotNil(orchestrator.lastAuthenticationDate)
        XCTAssertTrue(orchestrator.hasProtectedDataAuthorizationHandoffContext)
    }

    func test_consumeAuthenticatedContext_returnsContextExactlyOnce() {
        let orchestrator = makeOrchestrator()
        let context = LAContext()
        orchestrator.recordSuccessfulAppSessionAuthentication(context: context)

        XCTAssertTrue(orchestrator.consumeAuthenticatedContextForProtectedData() === context)
        XCTAssertFalse(orchestrator.hasProtectedDataAuthorizationHandoffContext)
        XCTAssertNil(orchestrator.consumeAuthenticatedContextForProtectedData())
    }

    func test_requestContentClear_discardsContextAndBumpsGeneration() {
        let orchestrator = makeOrchestrator()
        orchestrator.recordSuccessfulAppSessionAuthentication(context: LAContext())
        let generation = orchestrator.contentClearGeneration

        orchestrator.requestContentClear()

        XCTAssertEqual(orchestrator.contentClearGeneration, generation + 1)
        XCTAssertFalse(orchestrator.hasProtectedDataAuthorizationHandoffContext)
        XCTAssertNil(orchestrator.consumeAuthenticatedContextForProtectedData())
    }

    func test_discardHandoffContext_failClosed() {
        let orchestrator = makeOrchestrator()
        orchestrator.recordSuccessfulAppSessionAuthentication(context: LAContext())

        orchestrator.discardAuthorizationHandoffContext(reason: "test")

        XCTAssertFalse(orchestrator.hasProtectedDataAuthorizationHandoffContext)
    }

    func test_discardForPolicyChange_clearsContext() {
        let orchestrator = makeOrchestrator()
        orchestrator.recordSuccessfulAppSessionAuthentication(context: LAContext())

        orchestrator.discardProtectedDataAuthorizationHandoffContextForPolicyChange()

        XCTAssertFalse(orchestrator.hasProtectedDataAuthorizationHandoffContext)
    }

    func test_resetAfterLocalDataReset_clearsAuthenticationAndContext() {
        let orchestrator = makeOrchestrator()
        orchestrator.recordSuccessfulAppSessionAuthentication(context: LAContext())
        let generation = orchestrator.contentClearGeneration

        orchestrator.resetAfterLocalDataReset(preserveAuthentication: false)

        XCTAssertNil(orchestrator.lastAuthenticationDate)
        XCTAssertFalse(orchestrator.hasProtectedDataAuthorizationHandoffContext)
        XCTAssertEqual(orchestrator.contentClearGeneration, generation + 1)
    }

    func test_resetAfterLocalDataReset_preserveAuthentication_keepsDate() {
        let orchestrator = makeOrchestrator()

        orchestrator.resetAfterLocalDataReset(preserveAuthentication: true)

        XCTAssertNotNil(orchestrator.lastAuthenticationDate)
    }
}
