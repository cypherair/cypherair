import Foundation
import XCTest
@testable import CypherAir

private typealias AppAppContainer = CypherAir.AppContainer
private typealias AppProtectedDataRegistryStore = CypherAir.ProtectedDataRegistryStore
private typealias AppProtectedDataStorageRoot = CypherAir.ProtectedDataStorageRoot
private typealias AppProtectedDataStorageValidationMode = CypherAir.ProtectedDataStorageValidationMode
private typealias AppProtectedDomainBootstrapMetadata = CypherAir.ProtectedDomainBootstrapMetadata
private typealias AppProtectedDomainBootstrapStore = CypherAir.ProtectedDomainBootstrapStore

final class ProtectedDataStorageRootTests: XCTestCase {
    private let fileManager = FileManager.default

    func test_defaultRoot_usesApplicationSupportProtectedDataDirectory() {
        let storageRoot = AppProtectedDataStorageRoot()
        let applicationSupportDirectory = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .standardizedFileURL

        XCTAssertEqual(
            storageRoot.rootURL.standardizedFileURL,
            applicationSupportDirectory.appendingPathComponent("ProtectedData", isDirectory: true).standardizedFileURL
        )
    }

    func test_makeUITest_placesProtectedDataRootInsideApplicationSupport() {
        let container = AppAppContainer.makeUITest()
        defer { cleanupUITestContainer(container) }

        let applicationSupportDirectory = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .standardizedFileURL
        let temporaryDirectory = fileManager.temporaryDirectory.standardizedFileURL
        let documentsDirectory = fileManager.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .standardizedFileURL
        let rootURL = container.protectedDataStorageRoot.rootURL.standardizedFileURL

        XCTAssertTrue(rootURL.path.hasPrefix(applicationSupportDirectory.path + "/"))
        XCTAssertFalse(rootURL.path.hasPrefix(temporaryDirectory.path + "/"))
        XCTAssertFalse(rootURL.path.hasPrefix(documentsDirectory.path + "/"))
    }

    func test_registryBootstrap_writesRegistryWithCompleteFileProtection() throws {
        let baseDirectory = try makeApplicationSupportTestDirectory("ProtectedDataRegistryProtection")
        defer { try? fileManager.removeItem(at: baseDirectory) }

        let storageRoot = makeProductionStorageRoot(baseDirectory: baseDirectory)
        let store = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.registry-protection"
        )

        _ = try store.performSynchronousBootstrap()

        try assertCompleteFileProtection(at: storageRoot.registryURL)
    }

    func test_bootstrapMetadataSave_writesMetadataWithCompleteFileProtection() throws {
        let baseDirectory = try makeApplicationSupportTestDirectory("ProtectedDataBootstrapMetadata")
        defer { try? fileManager.removeItem(at: baseDirectory) }

        let storageRoot = makeProductionStorageRoot(baseDirectory: baseDirectory)
        let bootstrapStore = AppProtectedDomainBootstrapStore(storageRoot: storageRoot)

        try bootstrapStore.saveMetadata(
            AppProtectedDomainBootstrapMetadata(
                schemaVersion: 1,
                expectedCurrentGenerationIdentifier: "current-1",
                coarseRecoveryReason: nil,
                wrappedDomainMasterKeyRecordVersion: 1
            ),
            for: "settings"
        )

        try assertCompleteFileProtection(at: storageRoot.bootstrapMetadataURL(for: "settings"))
    }

    func test_wrappedDMKStagedWriteAndPromotion_keepCompleteFileProtection() throws {
        let baseDirectory = try makeApplicationSupportTestDirectory("ProtectedDataWrappedDMK")
        defer { try? fileManager.removeItem(at: baseDirectory) }

        let storageRoot = makeProductionStorageRoot(baseDirectory: baseDirectory)
        let domainID: ProtectedDataDomainID = "settings"
        let stagedURL = storageRoot.stagedWrappedDomainMasterKeyURL(for: domainID)
        let committedURL = storageRoot.committedWrappedDomainMasterKeyURL(for: domainID)

        try storageRoot.writeProtectedData(Data("wrapped-dmk".utf8), to: stagedURL)
        try assertCompleteFileProtection(at: stagedURL)

        try storageRoot.promoteStagedFile(from: stagedURL, to: committedURL)

        XCTAssertFalse(fileManager.fileExists(atPath: stagedURL.path))
        try assertCompleteFileProtection(at: committedURL)
    }

    func test_productionContract_rootOutsideApplicationSupport_failsClosedBeforeBootstrap() throws {
        let temporaryDirectory = makeTemporaryDirectory("ProtectedDataInvalidRoot")
        defer { try? fileManager.removeItem(at: temporaryDirectory) }

        let storageRoot = AppProtectedDataStorageRoot(
            baseDirectory: temporaryDirectory,
            validationMode: .enforceAppSupportContainment
        )
        let store = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.invalid-root"
        )

        XCTAssertThrowsError(try store.performSynchronousBootstrap()) { error in
            XCTAssertEqual(error as? ProtectedDataError, .storageRootOutsideApplicationSupport)
        }
        XCTAssertFalse(fileManager.fileExists(atPath: storageRoot.rootURL.path))
    }

    func test_productionContract_unsupportedFileProtection_failsClosedBeforeBootstrap() throws {
        let baseDirectory = try makeApplicationSupportTestDirectory("ProtectedDataUnsupportedProtection")
        defer { try? fileManager.removeItem(at: baseDirectory) }

        let storageRoot = AppProtectedDataStorageRoot(
            baseDirectory: baseDirectory,
            validationMode: .enforceAppSupportContainment,
            fileProtectionCapabilityProvider: { _ in false }
        )
        let store = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.unsupported-protection"
        )

        XCTAssertThrowsError(try store.performSynchronousBootstrap()) { error in
            XCTAssertEqual(error as? ProtectedDataError, .fileProtectionUnsupported)
        }
        XCTAssertFalse(fileManager.fileExists(atPath: storageRoot.rootURL.path))
    }

    func test_productionContract_rootSymlinkEscapingApplicationSupport_failsClosedBeforeBootstrap() throws {
        let baseDirectory = try makeApplicationSupportTestDirectory("ProtectedDataRootSymlinkEscape")
        let outsideTarget = makeTemporaryDirectory("ProtectedDataRootSymlinkOutside")
        defer { try? fileManager.removeItem(at: baseDirectory) }
        defer { try? fileManager.removeItem(at: outsideTarget) }

        try fileManager.createSymbolicLink(
            at: baseDirectory.appendingPathComponent("ProtectedData", isDirectory: true),
            withDestinationURL: outsideTarget
        )

        let storageRoot = makeProductionStorageRoot(baseDirectory: baseDirectory)
        let store = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.root-symlink-escape"
        )

        XCTAssertThrowsError(try store.performSynchronousBootstrap()) { error in
            XCTAssertEqual(error as? ProtectedDataError, .storageRootOutsideApplicationSupport)
        }
        try assertDirectoryIsEmpty(outsideTarget)
    }

    func test_productionContract_baseDirectorySymlinkEscapingApplicationSupport_failsClosedBeforeBootstrap() throws {
        let applicationSupportDirectory = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let symlinkBaseDirectory = applicationSupportDirectory.appendingPathComponent(
            "ProtectedDataBaseSymlinkEscape-\(UUID().uuidString)",
            isDirectory: true
        )
        let outsideTarget = makeTemporaryDirectory("ProtectedDataBaseSymlinkOutside")
        defer { try? fileManager.removeItem(at: symlinkBaseDirectory) }
        defer { try? fileManager.removeItem(at: outsideTarget) }

        try fileManager.createSymbolicLink(at: symlinkBaseDirectory, withDestinationURL: outsideTarget)

        let storageRoot = AppProtectedDataStorageRoot(
            baseDirectory: symlinkBaseDirectory,
            validationMode: .enforceAppSupportContainment
        )
        let store = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.base-symlink-escape"
        )

        XCTAssertThrowsError(try store.performSynchronousBootstrap()) { error in
            XCTAssertEqual(error as? ProtectedDataError, .storageRootOutsideApplicationSupport)
        }
        try assertDirectoryIsEmpty(outsideTarget)
    }

    func test_productionContract_rootSymlinkResolvingInsideApplicationSupport_bootstrapsSuccessfully() throws {
        let baseDirectory = try makeApplicationSupportTestDirectory("ProtectedDataRootSymlinkContained")
        let applicationSupportDirectory = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let containedTarget = applicationSupportDirectory.appendingPathComponent(
            "ProtectedDataRootSymlinkTarget-\(UUID().uuidString)",
            isDirectory: true
        )
        defer { try? fileManager.removeItem(at: baseDirectory) }
        defer { try? fileManager.removeItem(at: containedTarget) }

        try fileManager.createDirectory(at: containedTarget, withIntermediateDirectories: true)
        try fileManager.createSymbolicLink(
            at: baseDirectory.appendingPathComponent("ProtectedData", isDirectory: true),
            withDestinationURL: containedTarget
        )

        let storageRoot = makeProductionStorageRoot(baseDirectory: baseDirectory)
        let store = AppProtectedDataRegistryStore(
            storageRoot: storageRoot,
            sharedRightIdentifier: "com.cypherair.tests.protected-data.root-symlink-contained"
        )

        XCTAssertNoThrow(try store.performSynchronousBootstrap())
        XCTAssertTrue(
            fileManager.fileExists(
                atPath: containedTarget.appendingPathComponent("ProtectedDataRegistry.plist").path
            )
        )
    }

    private func makeProductionStorageRoot(baseDirectory: URL) -> AppProtectedDataStorageRoot {
        AppProtectedDataStorageRoot(
            baseDirectory: baseDirectory,
            validationMode: .enforceAppSupportContainment
        )
    }

    private func makeApplicationSupportTestDirectory(_ prefix: String) throws -> URL {
        let applicationSupportDirectory = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let url = applicationSupportDirectory.appendingPathComponent(
            "\(prefix)-\(UUID().uuidString)",
            isDirectory: true
        )
        try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func makeTemporaryDirectory(_ prefix: String) -> URL {
        let url = fileManager.temporaryDirectory.appendingPathComponent(
            "\(prefix)-\(UUID().uuidString)",
            isDirectory: true
        )
        try? fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func assertCompleteFileProtection(at url: URL, file: StaticString = #filePath, line: UInt = #line) throws {
        let attributes = try fileManager.attributesOfItem(atPath: url.path)
        XCTAssertEqual(
            attributes[.protectionKey] as? FileProtectionType,
            .complete,
            file: file,
            line: line
        )
    }

    private func assertDirectoryIsEmpty(
        _ url: URL,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let contents = try fileManager.contentsOfDirectory(at: url, includingPropertiesForKeys: nil)
        XCTAssertTrue(contents.isEmpty, file: file, line: line)
    }

    private func cleanupUITestContainer(_ container: AppAppContainer) {
        if let contactsDirectory = container.contactsDirectory {
            try? fileManager.removeItem(at: contactsDirectory)
        }
        try? fileManager.removeItem(at: container.protectedDataStorageRoot.rootURL.deletingLastPathComponent())
        if let defaultsSuiteName = container.defaultsSuiteName {
            UserDefaults.standard.removePersistentDomain(forName: defaultsSuiteName)
        }
    }
}
