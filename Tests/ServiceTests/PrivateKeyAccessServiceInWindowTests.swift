import LocalAuthentication
import XCTest
@testable import CypherAir

#if os(macOS)
/// macOS in-window per-operation route tests for `PrivateKeyAccessService` (P3).
///
/// Positive: when the presenter + control store are wired, `unwrapPrivateKey`
/// authenticates through the presentation seam exactly once and threads the
/// presenter's context into the Secure Enclave reconstruction.
/// Negative: a failed/declined presentation aborts before any SE operation; a
/// locked control store aborts before any prompt; an un-wired service keeps the
/// implicit-authentication behavior (nil context).
final class PrivateKeyAccessServiceInWindowTests: XCTestCase {
    private enum TestError: Error, Equatable {
        case presentationDeclined
    }

    /// Seam stub: records the request and hands the caller's context back without
    /// running the evaluation closure (which would drive real LocalAuthentication).
    /// Successful evaluations are simulated as `true` / `Void` — matching the
    /// per-operation route's `evaluateAccessControl` shape.
    private final class StubAuthenticationPresenter: AuthenticationPresenting, @unchecked Sendable {
        private(set) var requests: [AuthenticationPresentationRequest] = []
        private(set) var lastContext: LAContext?
        var errorToThrow: Error?

        func presentingEvaluation<T: Sendable>(
            context: LAContext,
            request: AuthenticationPresentationRequest,
            _ evaluation: @Sendable @escaping (LAContext) async throws -> T
        ) async throws -> T {
            requests.append(request)
            lastContext = context
            if let errorToThrow {
                throw errorToThrow
            }
            if let success = (true as Any) as? T {
                return success
            }
            guard let unit = (() as Any) as? T else {
                fatalError("StubAuthenticationPresenter supports Bool/Void evaluations only")
            }
            return unit
        }
    }

    private struct Fixture {
        let secureEnclave: MockSecureEnclave
        let bundleStore: KeyBundleStore
        let fingerprint: String
        let privateKey: Data
    }

    private func makeFixture() throws -> Fixture {
        let secureEnclave = MockSecureEnclave()
        let bundleStore = KeyBundleStore(keychain: MockKeychain())
        let fingerprint = "abcdef0123456789abcdef0123456789abcdef01"
        let privateKey = Data("in-window-route-test-key".utf8)
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let bundle = try secureEnclave.wrap(
            privateKey: privateKey,
            using: handle,
            fingerprint: fingerprint
        )
        try bundleStore.saveBundle(bundle, fingerprint: fingerprint)
        return Fixture(
            secureEnclave: secureEnclave,
            bundleStore: bundleStore,
            fingerprint: fingerprint,
            privateKey: privateKey
        )
    }

    private func makeService(
        fixture: Fixture,
        presenter: (any AuthenticationPresenting)?,
        controlStore: (any PrivateKeyControlStoreProtocol)?
    ) -> PrivateKeyAccessService {
        PrivateKeyAccessService(
            secureEnclave: fixture.secureEnclave,
            bundleStore: fixture.bundleStore,
            authenticationPromptCoordinator: AuthenticationPromptCoordinator(),
            authenticationPresenter: presenter,
            privateKeyControlStore: controlStore,
            traceStore: nil
        )
    }

    func test_unwrap_routesThroughPresenterOnce_andThreadsContextIntoReconstruct() async throws {
        let fixture = try makeFixture()
        let presenter = StubAuthenticationPresenter()
        let service = makeService(
            fixture: fixture,
            presenter: presenter,
            controlStore: InMemoryPrivateKeyControlStore(mode: .standard)
        )

        let unwrapped = try await service.unwrapPrivateKey(fingerprint: fixture.fingerprint)

        XCTAssertEqual(unwrapped, fixture.privateKey)
        XCTAssertEqual(presenter.requests.count, 1, "Exactly one prompt per operation")
        XCTAssertEqual(presenter.requests.first?.purpose, .perOperation)
        XCTAssertEqual(presenter.requests.first?.source, "privateKey.unwrap")
        XCTAssertEqual(fixture.secureEnclave.reconstructCallCount, 1)
        XCTAssertNotNil(presenter.lastContext)
        XCTAssertTrue(
            fixture.secureEnclave.lastReconstructAuthenticationContext === presenter.lastContext,
            "The presenter-authenticated context must be the one threaded into reconstructKey"
        )
    }

    func test_unwrap_presentationFailure_abortsBeforeAnySecureEnclaveOperation() async throws {
        let fixture = try makeFixture()
        let presenter = StubAuthenticationPresenter()
        presenter.errorToThrow = TestError.presentationDeclined
        let service = makeService(
            fixture: fixture,
            presenter: presenter,
            controlStore: InMemoryPrivateKeyControlStore(mode: .highSecurity)
        )

        do {
            _ = try await service.unwrapPrivateKey(fingerprint: fixture.fingerprint)
            XCTFail("Expected the presentation failure to propagate")
        } catch let error as TestError {
            XCTAssertEqual(error, .presentationDeclined)
        }
        XCTAssertEqual(
            fixture.secureEnclave.reconstructCallCount,
            0,
            "A declined authentication must not reach the Secure Enclave"
        )
        XCTAssertEqual(fixture.secureEnclave.unwrapCallCount, 0)
    }

    func test_unwrap_lockedControlStore_abortsBeforeAnyPrompt() async throws {
        let fixture = try makeFixture()
        let presenter = StubAuthenticationPresenter()
        let service = makeService(
            fixture: fixture,
            presenter: presenter,
            controlStore: InMemoryPrivateKeyControlStore(mode: nil)
        )

        do {
            _ = try await service.unwrapPrivateKey(fingerprint: fixture.fingerprint)
            XCTFail("Expected the locked control store to abort the unwrap")
        } catch let error as PrivateKeyControlError {
            XCTAssertEqual(error, .locked)
        }
        XCTAssertTrue(presenter.requests.isEmpty, "No prompt may be presented while locked")
        XCTAssertEqual(fixture.secureEnclave.reconstructCallCount, 0)
    }

    func test_unwrap_withoutWiredPresenter_usesImplicitAuthentication() async throws {
        let fixture = try makeFixture()
        let service = makeService(fixture: fixture, presenter: nil, controlStore: nil)

        let unwrapped = try await service.unwrapPrivateKey(fingerprint: fixture.fingerprint)

        XCTAssertEqual(unwrapped, fixture.privateKey)
        XCTAssertEqual(fixture.secureEnclave.reconstructCallCount, 1)
        XCTAssertNil(
            fixture.secureEnclave.lastReconstructAuthenticationContext,
            "Without the seam wired, the Secure Enclave authenticates implicitly (nil context)"
        )
    }
}
#endif
