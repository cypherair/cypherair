import Foundation
import XCTest
@testable import CypherAir

@MainActor
final class ProtectedDataDomainKeyKeychainStoreTests: ProtectedDataFrameworkTestCase {
    func test_keychainServiceNamesUsePrefixDefaultAccountAndDomainID() {
        let domainID: ProtectedDataDomainID = "contacts"

        XCTAssertEqual(
            KeychainConstants.protectedDataDomainKeyService(domainID: domainID),
            "com.cypherair.v5.protected-data.domain-key.contacts"
        )
        XCTAssertEqual(
            KeychainConstants.stagedProtectedDataDomainKeyService(domainID: domainID),
            "com.cypherair.v5.protected-data.domain-key.staged.contacts"
        )
        XCTAssertEqual(KeychainConstants.defaultAccount, "com.cypherair")
    }

    func test_writeTransactionStoresCommittedKeychainRowAndRemovesStagedRow() throws {
        let harness = try makeDomainKeyHarness("DomainKeyKeychainCommitted")
        defer { cleanup(harness) }

        let domainMasterKey = Data(repeating: 0x42, count: 32)
        let record = try harness.manager.wrapDomainMasterKey(
            domainMasterKey,
            for: harness.domainID,
            wrappingRootKey: harness.wrappingRootKey
        )

        try harness.manager.writeWrappedDomainMasterKeyRecordTransaction(
            record,
            wrappingRootKey: harness.wrappingRootKey
        )

        XCTAssertTrue(harness.keychain.exists(
            service: KeychainConstants.protectedDataDomainKeyService(domainID: harness.domainID),
            account: KeychainConstants.defaultAccount
        ))
        XCTAssertFalse(harness.keychain.exists(
            service: KeychainConstants.stagedProtectedDataDomainKeyService(domainID: harness.domainID),
            account: KeychainConstants.defaultAccount
        ))
        XCTAssertFalse(
            harness.keychain.saveCalls
                .filter { $0.service.hasPrefix(KeychainConstants.protectedDataDomainKeyServicePrefix) }
                .contains { $0.hasAccessControl }
        )
        let loadedRecord = try XCTUnwrap(
            try harness.manager.loadWrappedDomainMasterKeyRecord(for: harness.domainID)
        )
        let loadedDomainMasterKey = try harness.manager.unwrapDomainMasterKey(
            from: loadedRecord,
            wrappingRootKey: harness.wrappingRootKey
        )
        XCTAssertEqual(loadedDomainMasterKey, domainMasterKey)
    }

    func test_writeTransactionReplacesStaleStagedRowAndUpdatesDuplicateCommittedRow() throws {
        let harness = try makeDomainKeyHarness("DomainKeyKeychainStale")
        defer { cleanup(harness) }
        let stagedService = KeychainConstants.stagedProtectedDataDomainKeyService(domainID: harness.domainID)
        let committedService = KeychainConstants.protectedDataDomainKeyService(domainID: harness.domainID)
        try harness.keychain.save(
            Data("stale staged".utf8),
            service: stagedService,
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
        try harness.keychain.save(
            Data("old committed".utf8),
            service: committedService,
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )

        let replacementDomainMasterKey = Data(repeating: 0x51, count: 32)
        let replacementRecord = try harness.manager.wrapDomainMasterKey(
            replacementDomainMasterKey,
            for: harness.domainID,
            wrappingRootKey: harness.wrappingRootKey
        )
        try harness.manager.writeWrappedDomainMasterKeyRecordTransaction(
            replacementRecord,
            wrappingRootKey: harness.wrappingRootKey
        )

        XCTAssertFalse(harness.keychain.exists(
            service: stagedService,
            account: KeychainConstants.defaultAccount
        ))
        XCTAssertTrue(harness.keychain.updateCalls.contains {
            $0.service == committedService && !$0.hasAuthenticationContext
        })
        let loadedRecord = try XCTUnwrap(
            try harness.manager.loadWrappedDomainMasterKeyRecord(for: harness.domainID)
        )
        let loadedDomainMasterKey = try harness.manager.unwrapDomainMasterKey(
            from: loadedRecord,
            wrappingRootKey: harness.wrappingRootKey
        )
        XCTAssertEqual(loadedDomainMasterKey, replacementDomainMasterKey)
    }

    func test_loadMissingCommittedKeychainRowReturnsNilAndUsesNoAuthenticationContext() throws {
        let harness = try makeDomainKeyHarness("DomainKeyKeychainMissing")
        defer { cleanup(harness) }

        let loadedRecord = try harness.manager.loadWrappedDomainMasterKeyRecord(for: harness.domainID)

        XCTAssertNil(loadedRecord)
        XCTAssertEqual(harness.keychain.loadCalls.last?.service, KeychainConstants.protectedDataDomainKeyService(domainID: harness.domainID))
        XCTAssertEqual(harness.keychain.loadCalls.last?.hasAuthenticationContext, false)
    }

    func test_corruptCommittedKeychainRowFailsClosed() throws {
        let harness = try makeDomainKeyHarness("DomainKeyKeychainCorrupt")
        defer { cleanup(harness) }
        try harness.keychain.save(
            Data("not a wrapped dmk plist".utf8),
            service: KeychainConstants.protectedDataDomainKeyService(domainID: harness.domainID),
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )

        XCTAssertThrowsError(
            try harness.manager.loadWrappedDomainMasterKeyRecord(for: harness.domainID)
        )
    }

    private func makeDomainKeyHarness(
        _ prefix: String,
        domainID: ProtectedDataDomainID = "contacts"
    ) throws -> (
        storageRoot: ProtectedDataStorageRoot,
        keychain: MockKeychain,
        manager: ProtectedDomainKeyManager,
        domainID: ProtectedDataDomainID,
        wrappingRootKey: Data
    ) {
        let storageRoot = ProtectedDataStorageRoot(baseDirectory: makeTemporaryDirectory(prefix))
        try storageRoot.ensureRootDirectoryExists()
        let keychain = MockKeychain()
        let manager = ProtectedDomainKeyManager(storageRoot: storageRoot, keychain: keychain)
        return (
            storageRoot: storageRoot,
            keychain: keychain,
            manager: manager,
            domainID: domainID,
            wrappingRootKey: Data(repeating: 0xA5, count: 32)
        )
    }

    private func cleanup(
        _ harness: (
            storageRoot: ProtectedDataStorageRoot,
            keychain: MockKeychain,
            manager: ProtectedDomainKeyManager,
            domainID: ProtectedDataDomainID,
            wrappingRootKey: Data
        )
    ) {
        try? FileManager.default.removeItem(at: harness.storageRoot.rootURL.deletingLastPathComponent())
    }
}
