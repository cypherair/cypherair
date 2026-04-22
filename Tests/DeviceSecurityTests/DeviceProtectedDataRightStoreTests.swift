import LocalAuthentication
import XCTest
@testable import CypherAir

final class DeviceProtectedDataRightStoreTests: XCTestCase {
    private var rightStoreClient: ProtectedDataRightStoreClient!
    private var trackedRightIdentifiers: [String] = []

    override func setUp() async throws {
        try await super.setUp()
        rightStoreClient = ProtectedDataRightStoreClient()
    }

    override func tearDown() async throws {
        try await cleanupTrackedRightIdentifiers()
        rightStoreClient = nil
        try await super.tearDown()
    }

    func test_persistedRight_saveLoadAuthorizeAndDeauthorize_usesTestOnlyIdentifier() async throws {
        let identifier = try await makeTestRightIdentifier(functionName: #function)
        XCTAssertNotEqual(identifier, ProtectedDataRightIdentifiers.productionSharedRightIdentifier)

        let savedRight = try await rightStoreClient.saveRight(
            LARight(requirement: .default),
            identifier: identifier,
            secret: Data(repeating: 0x5A, count: 32)
        )
        let loadedRight = try await rightStoreClient.right(forIdentifier: identifier)

        XCTAssertEqual(savedRight.identifier, identifier)
        XCTAssertEqual(loadedRight.identifier, identifier)

        try await settleAuthenticationSession()
        try await loadedRight.authorize(
            localizedReason: "Authenticate to validate CypherAir protected-data right access."
        )

        let secretData = try await loadedRight.rawSecretData()
        XCTAssertEqual(secretData, Data(repeating: 0x5A, count: 32))

        await loadedRight.deauthorize()
    }

    private func makeTestRightIdentifier(functionName: String) async throws -> String {
        let sanitizedFunctionName = functionName
            .replacingOccurrences(of: "[^A-Za-z0-9]+", with: "-", options: .regularExpression)
            .trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        let identifier = "com.cypherair.tests.protected-data.\(sanitizedFunctionName).\(UUID().uuidString)"

        try? await rightStoreClient.removeRight(forIdentifier: identifier)

        trackedRightIdentifiers.append(identifier)
        return identifier
    }

    private func cleanupTrackedRightIdentifiers() async throws {
        for identifier in trackedRightIdentifiers {
            do {
                try await rightStoreClient.removeRight(forIdentifier: identifier)
            } catch {
                XCTFail("Failed to clean up protected-data test right \(identifier): \(error)")
            }
        }

        trackedRightIdentifiers.removeAll()
    }

    private func settleAuthenticationSession() async throws {
        try await Task.sleep(for: .seconds(2))
    }
}
