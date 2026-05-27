import XCTest
@testable import CypherAir

final class SecureEnclaveCustodyHandleStoreTests: XCTestCase {
    func test_createHandlePair_generatesDistinctSigningAndAgreementHandles() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let store = makeStore(keyStore: keyStore, handleSetIdentifier: "phase3a")

        let pair = try store.createHandlePair()

        XCTAssertEqual(pair.handleSetIdentifier, "phase3a")
        XCTAssertEqual(pair.signing.role, .signing)
        XCTAssertEqual(pair.keyAgreement.role, .keyAgreement)
        XCTAssertNotEqual(pair.signing.publicKeyX963, pair.keyAgreement.publicKeyX963)
        XCTAssertEqual(keyStore.storedHandleCount(), 2)
        XCTAssertEqual(
            Set(keyStore.applicationTagStrings()),
            [
                "com.cypherair.v1.secure-enclave-custody.phase3a.signing",
                "com.cypherair.v1.secure-enclave-custody.phase3a.keyAgreement"
            ]
        )
    }

    func test_createHandlePair_requestsCustodySpecificAccessPolicy() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let store = makeStore(keyStore: keyStore, handleSetIdentifier: "policy")

        _ = try store.createHandlePair()

        XCTAssertEqual(keyStore.createRequests.count, 2)
        XCTAssertEqual(
            keyStore.createRequests.map { $0.accessPolicy },
            [
                .privateKeyUsageBiometryAny,
                .privateKeyUsageBiometryAny
            ]
        )
        let policy = try XCTUnwrap(keyStore.createRequests.first?.accessPolicy)
        XCTAssertTrue(policy.requiresPrivateKeyUsage)
        XCTAssertTrue(policy.requiresBiometryAny)
        XCTAssertFalse(policy.permitsDevicePasscodeFallback)
    }

    func test_createHandlePair_secondCreateFailureRollsBackSigningHandle() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.failCreateRole = .keyAgreement
        let store = makeStore(keyStore: keyStore, handleSetIdentifier: "rollback")

        XCTAssertThrowsError(try store.createHandlePair()) { error in
            XCTAssertEqual(
                (error as? SecureEnclaveCustodyHandleError)?.failureCategory,
                .privateHandleInaccessible
            )
        }

        XCTAssertEqual(keyStore.storedHandleCount(), 0)
        XCTAssertEqual(keyStore.deleteRequests.map(\.role), [.signing])
    }

    func test_loadHandlePair_requiresRoleAndPublicKeyBinding() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let store = makeStore(keyStore: keyStore, handleSetIdentifier: "load")
        let pair = try store.createHandlePair()

        let loaded = try store.loadHandlePair(expected: pair)

        XCTAssertEqual(loaded.signing.binding, pair.signing)
        XCTAssertEqual(loaded.keyAgreement.binding, pair.keyAgreement)
    }

    func test_loadHandleFailsClosedForWrongRole() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore)
        let signingReference = try reference("wrongrole", .signing)
        let keyAgreementReference = try reference("wrongrole", .keyAgreement)
        let wrongRoleBinding = try binding(keyAgreementReference, byte: 0x21)
        let wrongRoleHandle = SecureEnclaveCustodyLoadedHandle(
            binding: wrongRoleBinding,
            privateKey: nil
        )
        keyStore.insert(wrongRoleHandle, for: signingReference)

        XCTAssertThrowsError(
            try store.loadHandle(
                reference: signingReference,
                expectedPublicKeyX963: wrongRoleBinding.publicKeyX963
            )
        ) { error in
            XCTAssertEqual(
                error as? SecureEnclaveCustodyHandleError,
                .privateOperationRoleMismatch(expected: .signing, actual: .keyAgreement)
            )
            XCTAssertEqual(
                (error as? SecureEnclaveCustodyHandleError)?.failureCategory,
                .privateOperationRoleMismatch
            )
        }
    }

    func test_loadHandleFailsClosedForWrongPublicKeyBinding() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let store = makeStore(keyStore: keyStore, handleSetIdentifier: "pubbinding")
        let pair = try store.createHandlePair()
        let expectedWrongPublicKey = makePublicKey(byte: 0xEE)

        XCTAssertThrowsError(
            try store.loadHandle(
                reference: pair.signing.reference,
                expectedPublicKeyX963: expectedWrongPublicKey
            )
        ) { error in
            XCTAssertEqual(
                error as? SecureEnclaveCustodyHandleError,
                .handlePublicKeyBindingMismatch(.signing)
            )
            XCTAssertEqual(
                (error as? SecureEnclaveCustodyHandleError)?.failureCategory,
                .handlePublicKeyBindingMismatch
            )
        }
    }

    func test_missingAndPartialHandlePairsAreClassified() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore)
        let signingReference = try reference("partial", .signing)
        let signingHandle = SecureEnclaveCustodyLoadedHandle(
            binding: try binding(signingReference, byte: 0x41),
            privateKey: nil
        )

        XCTAssertEqual(store.inspectHandlePair(handleSetIdentifier: "missing"), .missing)

        keyStore.insert(signingHandle)

        XCTAssertEqual(
            store.inspectHandlePair(handleSetIdentifier: "partial"),
            .partial(presentRoles: [.signing])
        )
        XCTAssertThrowsError(
            try store.loadHandle(
                reference: try reference("missing", .signing),
                expectedPublicKeyX963: makePublicKey(byte: 0x99)
            )
        ) { error in
            XCTAssertEqual(
                (error as? SecureEnclaveCustodyHandleError)?.failureCategory,
                .privateHandleMissing
            )
        }
    }

    func test_duplicateHandleMatchFailsClosedAsInaccessible() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore)
        let signingReference = try reference("duplicate", .signing)
        let firstHandle = SecureEnclaveCustodyLoadedHandle(
            binding: try binding(signingReference, byte: 0x51),
            privateKey: nil
        )
        let secondHandle = SecureEnclaveCustodyLoadedHandle(
            binding: try binding(signingReference, byte: 0x52),
            privateKey: nil
        )
        keyStore.insert(firstHandle)
        keyStore.insert(secondHandle, allowingDuplicate: true)

        XCTAssertThrowsError(
            try store.loadHandle(
                reference: signingReference,
                expectedPublicKeyX963: firstHandle.binding.publicKeyX963
            )
        ) { error in
            XCTAssertEqual(
                error as? SecureEnclaveCustodyHandleError,
                .ambiguousPrivateHandle(.signing)
            )
            XCTAssertEqual(
                (error as? SecureEnclaveCustodyHandleError)?.failureCategory,
                .privateHandleInaccessible
            )
        }
        XCTAssertEqual(
            store.inspectHandlePair(handleSetIdentifier: "duplicate"),
            .invalid(.ambiguousPrivateHandle(.signing))
        )
    }

    func test_deleteHandlePairIsIdempotentForMissingAndReportsCleanupFailure() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let store = makeStore(keyStore: keyStore, handleSetIdentifier: "delete")
        let pair = try store.createHandlePair()

        try store.deleteHandlePair(pair)
        XCTAssertEqual(keyStore.storedHandleCount(), 0)
        XCTAssertNoThrow(try store.deleteHandlePair(pair))

        let failingKeyStore = MockSecureEnclaveCustodyKeyStore()
        let failingStore = makeStore(keyStore: failingKeyStore, handleSetIdentifier: "deletefail")
        let failingPair = try failingStore.createHandlePair()
        failingKeyStore.failDeleteRole = .signing

        XCTAssertThrowsError(try failingStore.deleteHandlePair(failingPair)) { error in
            XCTAssertEqual(
                error as? SecureEnclaveCustodyHandleError,
                .cleanupOrRollbackFailed
            )
            XCTAssertEqual(
                (error as? SecureEnclaveCustodyHandleError)?.failureCategory,
                .cleanupOrRollbackFailure
            )
        }
    }

    func test_storeDoesNotUseLegacySoftwareWrappingServiceNames() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let store = makeStore(keyStore: keyStore, handleSetIdentifier: "nolegacy")

        _ = try store.createHandlePair()

        let tags = keyStore.applicationTagStrings()
        XCTAssertTrue(tags.allSatisfy { $0.hasPrefix(SecureEnclaveCustodyHandleReference.applicationTagPrefix) })
        XCTAssertFalse(tags.contains { $0.contains(".se-key.") })
        XCTAssertFalse(tags.contains { $0.contains(".salt.") })
        XCTAssertFalse(tags.contains { $0.contains(".sealed-key.") })
    }

    func test_authTraceMetadataSanitizesSecureEnclaveCustodyHandleTags() throws {
        let signingReference = try reference("traceid", .signing)
        let keyAgreementReference = try reference("traceid", .keyAgreement)

        XCTAssertEqual(
            AuthTraceMetadata.keychainServiceKind(for: signingReference.applicationTagString),
            "secureEnclaveCustodySigningHandle"
        )
        XCTAssertEqual(
            AuthTraceMetadata.keychainServiceKind(for: keyAgreementReference.applicationTagString),
            "secureEnclaveCustodyKeyAgreementHandle"
        )
        XCTAssertEqual(
            AuthTraceMetadata.keychainServiceKind(forPrefix: SecureEnclaveCustodyHandleReference.applicationTagPrefix),
            "secureEnclaveCustodyHandle"
        )
        XCTAssertFalse(
            AuthTraceMetadata.keychainServiceKind(for: signingReference.applicationTagString).contains("traceid")
        )
    }

    private func makeStore(
        keyStore: MockSecureEnclaveCustodyKeyStore,
        handleSetIdentifier: String
    ) -> SecureEnclaveCustodyHandleStore {
        SecureEnclaveCustodyHandleStore(
            keyStore: keyStore,
            handleSetIdentifierGenerator: { handleSetIdentifier }
        )
    }

    private func reference(
        _ handleSetIdentifier: String,
        _ role: PGPPrivateOperationRole
    ) throws -> SecureEnclaveCustodyHandleReference {
        try SecureEnclaveCustodyHandleReference(
            handleSetIdentifier: handleSetIdentifier,
            role: role
        )
    }

    private func binding(
        _ reference: SecureEnclaveCustodyHandleReference,
        byte: UInt8
    ) throws -> SecureEnclaveCustodyHandlePublicBinding {
        try SecureEnclaveCustodyHandlePublicBinding(
            reference: reference,
            publicKeyX963: makePublicKey(byte: byte)
        )
    }

    private func makePublicKey(byte: UInt8) -> Data {
        var data = Data([0x04])
        data.append(Data(repeating: byte, count: 64))
        return data
    }
}
