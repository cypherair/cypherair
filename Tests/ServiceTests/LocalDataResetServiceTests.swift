import Foundation
import XCTest
@testable import CypherAir

@MainActor
final class LocalDataResetServiceTests: XCTestCase {
    func test_resetAllLocalData_removesStorageAndClearsMemoryState() async throws {
        let container = AppContainer.makeUITest(authTraceEnabled: true)
        defer {
            if let contactsDirectory = container.contactsDirectory {
                try? FileManager.default.removeItem(at: contactsDirectory)
            }
            if let defaultsSuiteName = container.defaultsSuiteName {
                UserDefaults(suiteName: defaultsSuiteName)?.removePersistentDomain(forName: defaultsSuiteName)
            }
        }

        let metadataService = KeychainConstants.metadataService(fingerprint: "ABCDEF")
        try container.keychain.save(
            Data([0x01]),
            service: metadataService,
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
        try container.keychain.save(
            Data([0x05]),
            service: metadataService,
            account: KeychainConstants.metadataAccount,
            accessControl: nil
        )
        try container.keychain.save(
            Data([0x02]),
            service: ProtectedDataRightIdentifiers.productionSharedRightIdentifier,
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )

        try container.protectedDataStorageRoot.ensureRootDirectoryExists()
        let protectedMarker = container.protectedDataStorageRoot.rootURL
            .appendingPathComponent("reset-marker.txt")
        try Data([0x03]).write(to: protectedMarker)

        let contactsDirectory = try XCTUnwrap(container.contactsDirectory)
        try FileManager.default.createDirectory(at: contactsDirectory, withIntermediateDirectories: true)
        let contactMarker = contactsDirectory.appendingPathComponent("contact.gpg")
        try Data([0x04]).write(to: contactMarker)

        container.config.hasCompletedOnboarding = true
        container.config.encryptToSelf = false

        let summary = try await container.localDataResetService.resetAllLocalData()

        XCTAssertGreaterThanOrEqual(summary.deletedKeychainItemCount, 3)
        XCTAssertFalse(container.keychain.exists(service: metadataService, account: KeychainConstants.defaultAccount))
        XCTAssertFalse(container.keychain.exists(service: metadataService, account: KeychainConstants.metadataAccount))
        XCTAssertFalse(container.keychain.exists(
            service: ProtectedDataRightIdentifiers.productionSharedRightIdentifier,
            account: KeychainConstants.defaultAccount
        ))
        XCTAssertFalse(FileManager.default.fileExists(atPath: container.protectedDataStorageRoot.rootURL.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: contactsDirectory.path))
        XCTAssertFalse(container.config.hasCompletedOnboarding)
        XCTAssertTrue(container.config.encryptToSelf)
        XCTAssertTrue(container.keyManagement.keys.isEmpty)
        XCTAssertTrue(container.contactService.contacts.isEmpty)

        let traceNames = container.authLifecycleTraceStore?.recentEntries.map(\.name) ?? []
        XCTAssertTrue(traceNames.contains("localDataReset.start"))
        XCTAssertTrue(traceNames.contains("localDataReset.finish"))
        XCTAssertTrue(traceNames.contains("localDataReset.validation.finish"))
    }
}
