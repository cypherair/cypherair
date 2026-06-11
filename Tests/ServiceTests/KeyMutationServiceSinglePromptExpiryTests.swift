import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir

/// P3′ stage 2 — single-prompt modify-expiry (TARGET §4).
///
/// Positive: with the expiry authenticator wired, the flow authenticates exactly
/// once and threads the SAME context into both Secure Enclave operations (the
/// unwrap reconstruct and the new wrapping key's generation).
/// Negative: a declined authentication aborts before any Secure Enclave
/// operation, pending bundle, or journal entry, and the flow remains usable.
/// Legacy: with no authenticator wired (other platforms, default), both SE
/// operations receive a nil context — byte-for-byte the prior behavior.
final class KeyMutationServiceSinglePromptExpiryTests: XCTestCase {
    /// Counts invalidations so tests can pin "exactly one invalidate after the
    /// action completes" (TARGET §6: the per-action context is confined and
    /// invalidated).
    private final class TrackingLAContext: LAContext {
        private(set) var invalidateCount = 0
        override func invalidate() {
            invalidateCount += 1
            super.invalidate()
        }
    }

    private final class StubExpiryAuthenticator {
        private(set) var calls = 0
        private(set) var reasons: [String] = []
        var errorToThrow: Error?
        let context = TrackingLAContext()

        func authenticate(_: SecAccessControl, _ reason: String) async throws -> LAContext {
            calls += 1
            reasons.append(reason)
            if let errorToThrow {
                throw errorToThrow
            }
            return context
        }
    }

    private enum TestError: Error {
        case declined
    }

    func test_modifyExpiry_authenticatesOnce_andThreadsSameContextIntoBothSEOperations() async throws {
        let stub = StubExpiryAuthenticator()
        let made = TestHelpers.makeKeyManagement(expiryAuthenticator: stub.authenticate)
        let identity = try await made.service.generateKey(
            name: "Expiry Test",
            email: "expiry@example.com",
            expirySeconds: 60 * 60 * 24 * 365,
            profile: .universal
        )
        XCTAssertEqual(stub.calls, 0, "Generation must not consult the expiry authenticator.")

        let updated = try await made.service.modifyExpiry(
            fingerprint: identity.fingerprint,
            newExpirySeconds: 60 * 60 * 24 * 30
        )

        XCTAssertEqual(stub.calls, 1, "Exactly one authentication for the whole action.")
        XCTAssertFalse(stub.reasons[0].isEmpty)
        XCTAssertTrue(
            made.mockSE.lastReconstructAuthenticationContext === stub.context,
            "The unwrap must consume the pre-authenticated context."
        )
        XCTAssertTrue(
            made.mockSE.lastGenerateAuthenticationContext === stub.context,
            "The new wrapping key must be generated with the SAME context (covers the wrap's first self-ECDH)."
        )
        XCTAssertEqual(updated.fingerprint, identity.fingerprint)
        XCTAssertEqual(
            stub.context.invalidateCount,
            1,
            "The per-action context is invalidated exactly once when the action completes."
        )
    }

    func test_modifyExpiry_declinedAuthentication_abortsBeforeAnySEOperationOrJournal() async throws {
        let stub = StubExpiryAuthenticator()
        stub.errorToThrow = TestError.declined
        let controlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        let made = TestHelpers.makeKeyManagement(
            privateKeyControlStore: controlStore,
            expiryAuthenticator: stub.authenticate
        )
        let identity = try await made.service.generateKey(
            name: "Expiry Decline",
            email: nil,
            expirySeconds: nil,
            profile: .universal
        )
        let generatesAfterProvisioning = made.mockSE.generateCallCount

        do {
            _ = try await made.service.modifyExpiry(
                fingerprint: identity.fingerprint,
                newExpirySeconds: 60 * 60
            )
            XCTFail("Expected the declined authentication to abort the flow")
        } catch is TestError {
        }

        XCTAssertEqual(made.mockSE.reconstructCallCount, 0, "No unwrap after a declined prompt.")
        XCTAssertEqual(
            made.mockSE.generateCallCount,
            generatesAfterProvisioning,
            "No new wrapping key after a declined prompt."
        )
        XCTAssertNil(
            try controlStore.recoveryJournal().modifyExpiry,
            "No journal entry: the decline aborted before any mutation began."
        )

        // The flow stays usable: a subsequent allowed attempt succeeds.
        stub.errorToThrow = nil
        let updated = try await made.service.modifyExpiry(
            fingerprint: identity.fingerprint,
            newExpirySeconds: 60 * 60
        )
        XCTAssertEqual(updated.fingerprint, identity.fingerprint)
        XCTAssertEqual(stub.calls, 2)
        XCTAssertEqual(
            stub.context.invalidateCount,
            1,
            "Only the successful attempt's completion invalidates the context (the declined attempt never received it)."
        )
    }

    func test_modifyExpiry_withoutAuthenticator_keepsImplicitNilContexts() async throws {
        let made = TestHelpers.makeKeyManagement()
        let identity = try await made.service.generateKey(
            name: "Expiry Legacy",
            email: nil,
            expirySeconds: nil,
            profile: .universal
        )

        let updated = try await made.service.modifyExpiry(
            fingerprint: identity.fingerprint,
            newExpirySeconds: 60 * 60 * 24
        )

        XCTAssertEqual(updated.fingerprint, identity.fingerprint)
        XCTAssertNil(
            made.mockSE.lastReconstructAuthenticationContext,
            "Un-wired flow keeps the implicit prompt (nil context) — the non-macOS/test posture."
        )
        XCTAssertNil(made.mockSE.lastGenerateAuthenticationContext)
    }
}
