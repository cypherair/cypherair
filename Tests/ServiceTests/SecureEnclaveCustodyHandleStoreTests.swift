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

    func test_inventorySummaryClassifiesCompletePartialAmbiguousAndMalformedHandles() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let store = makeStore(keyStore: keyStore, handleSetIdentifier: "complete")
        _ = try store.createHandlePair()

        let partialReference = try reference("partial", .signing)
        keyStore.insert(
            SecureEnclaveCustodyLoadedHandle(
                binding: try binding(partialReference, byte: 0x61),
                privateKey: nil
            )
        )

        let ambiguousReference = try reference("ambiguous", .signing)
        keyStore.insert(
            SecureEnclaveCustodyLoadedHandle(
                binding: try binding(ambiguousReference, byte: 0x62),
                privateKey: nil
            )
        )
        keyStore.insert(
            SecureEnclaveCustodyLoadedHandle(
                binding: try binding(ambiguousReference, byte: 0x63),
                privateKey: nil
            ),
            allowingDuplicate: true
        )
        keyStore.insertMalformedApplicationTag(
            "\(SecureEnclaveCustodyHandleReference.applicationTagPrefix).malformed"
        )

        let summary = try store.inventorySummaryForLocalRecovery()

        XCTAssertEqual(summary.totalHandleCount, 6)
        XCTAssertEqual(summary.completeSetCount, 1)
        XCTAssertEqual(summary.partialSetCount, 1)
        XCTAssertEqual(summary.ambiguousSetCount, 1)
        XCTAssertEqual(summary.malformedHandleCount, 1)
    }

    func test_cleanupAllHandlesForLocalDataResetDeletesKnownPartialAndMalformedHandles() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let store = makeStore(keyStore: keyStore, handleSetIdentifier: "cleanup")
        _ = try store.createHandlePair()
        let partialReference = try reference("cleanup-partial", .signing)
        keyStore.insert(
            SecureEnclaveCustodyLoadedHandle(
                binding: try binding(partialReference, byte: 0x71),
                privateKey: nil
            )
        )
        keyStore.insertMalformedApplicationTag(
            "\(SecureEnclaveCustodyHandleReference.applicationTagPrefix).cleanup-malformed"
        )

        let result = store.cleanupAllHandlesForLocalDataReset()

        XCTAssertTrue(result.succeeded)
        XCTAssertEqual(result.inspectedHandleCount, 4)
        XCTAssertEqual(result.deletedHandleCount, 4)
        XCTAssertEqual(keyStore.storedHandleCount(), 0)
        XCTAssertTrue(store.cleanupAllHandlesForLocalDataReset().succeeded)
    }

    func test_cleanupAllHandlesForLocalDataResetFailsClosedForListOrDeleteFailure() throws {
        let inventoryFailureKeyStore = MockSecureEnclaveCustodyKeyStore()
        inventoryFailureKeyStore.failInventory = true
        let inventoryFailureStore = SecureEnclaveCustodyHandleStore(keyStore: inventoryFailureKeyStore)

        XCTAssertEqual(
            inventoryFailureStore.cleanupAllHandlesForLocalDataReset().failureCategory,
            .cleanupOrRollbackFailure
        )

        let deleteFailureKeyStore = MockSecureEnclaveCustodyKeyStore()
        let deleteFailureStore = makeStore(keyStore: deleteFailureKeyStore, handleSetIdentifier: "deletefailure")
        _ = try deleteFailureStore.createHandlePair()
        deleteFailureKeyStore.failDeleteRole = .signing

        let result = deleteFailureStore.cleanupAllHandlesForLocalDataReset()

        XCTAssertEqual(result.failureCategory, .cleanupOrRollbackFailure)
        XCTAssertEqual(try deleteFailureStore.remainingHandleCountForLocalDataReset(), 1)
    }

    func test_classifyHandleAvailabilityMapsMetadataHandleDisagreement() throws {
        let availableKeyStore = MockSecureEnclaveCustodyKeyStore()
        let availableStore = makeStore(keyStore: availableKeyStore, handleSetIdentifier: "available")
        let availablePair = try availableStore.createHandlePair()
        XCTAssertEqual(availableStore.classifyHandleAvailability(expected: availablePair), .available)

        try availableStore.deleteHandlePair(availablePair)
        XCTAssertEqual(
            availableStore.classifyHandleAvailability(expected: availablePair),
            .unavailable(.privateHandleMissing)
        )

        let partialKeyStore = MockSecureEnclaveCustodyKeyStore()
        let partialStore = makeStore(keyStore: partialKeyStore, handleSetIdentifier: "partialclass")
        let partialPair = try partialStore.createHandlePair()
        try partialKeyStore.deleteKey(reference: partialPair.keyAgreement.reference)
        XCTAssertEqual(
            partialStore.classifyHandleAvailability(expected: partialPair),
            .unavailable(.migrationOrRecoveryRequired)
        )

        let publicMismatchKeyStore = MockSecureEnclaveCustodyKeyStore()
        let publicMismatchStore = makeStore(keyStore: publicMismatchKeyStore, handleSetIdentifier: "publicmismatch")
        let publicMismatchPair = try publicMismatchStore.createHandlePair()
        let wrongPublicPair = try SecureEnclaveCustodyHandlePair(
            signing: try binding(publicMismatchPair.signing.reference, byte: 0xE1),
            keyAgreement: publicMismatchPair.keyAgreement
        )
        XCTAssertEqual(
            publicMismatchStore.classifyHandleAvailability(expected: wrongPublicPair),
            .unavailable(.handlePublicKeyBindingMismatch)
        )

        let ambiguousKeyStore = MockSecureEnclaveCustodyKeyStore()
        let ambiguousStore = makeStore(keyStore: ambiguousKeyStore, handleSetIdentifier: "ambiguousclass")
        let ambiguousPair = try ambiguousStore.createHandlePair()
        ambiguousKeyStore.insert(
            SecureEnclaveCustodyLoadedHandle(
                binding: try binding(ambiguousPair.signing.reference, byte: 0xE2),
                privateKey: nil
            ),
            allowingDuplicate: true
        )
        XCTAssertEqual(
            ambiguousStore.classifyHandleAvailability(expected: ambiguousPair),
            .unavailable(.privateHandleInaccessible)
        )

        let wrongRoleKeyStore = MockSecureEnclaveCustodyKeyStore()
        let wrongRoleStore = SecureEnclaveCustodyHandleStore(keyStore: wrongRoleKeyStore)
        let signingReference = try reference("wrongroleclass", .signing)
        let keyAgreementReference = try reference("wrongroleclass", .keyAgreement)
        let wrongRoleSigning = try binding(keyAgreementReference, byte: 0xE3)
        let expectedPair = try SecureEnclaveCustodyHandlePair(
            signing: try binding(signingReference, byte: 0xE4),
            keyAgreement: try binding(keyAgreementReference, byte: 0xE5)
        )
        wrongRoleKeyStore.insert(
            SecureEnclaveCustodyLoadedHandle(binding: wrongRoleSigning, privateKey: nil),
            for: signingReference
        )
        wrongRoleKeyStore.insert(
            SecureEnclaveCustodyLoadedHandle(binding: expectedPair.keyAgreement, privateKey: nil)
        )
        XCTAssertEqual(
            wrongRoleStore.classifyHandleAvailability(expected: expectedPair),
            .unavailable(.privateOperationRoleMismatch)
        )

        try assertAvailabilityClassification(
            loadError: .hardwareUnavailable,
            expectedCategory: .hardwareUnavailable,
            handleSetIdentifier: "hardwareclass"
        )
        try assertAvailabilityClassification(
            loadError: .localAuthenticationFailed(.signing),
            expectedCategory: .localAuthenticationFailed,
            handleSetIdentifier: "authclass"
        )
        try assertAvailabilityClassification(
            loadError: .privateHandleInaccessible(.signing),
            expectedCategory: .privateHandleInaccessible,
            handleSetIdentifier: "inaccessibleclass"
        )
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

    private func assertAvailabilityClassification(
        loadError: SecureEnclaveCustodyHandleError,
        expectedCategory: PGPKeyOperationFailureCategory,
        handleSetIdentifier: String
    ) throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let store = makeStore(keyStore: keyStore, handleSetIdentifier: handleSetIdentifier)
        let pair = try store.createHandlePair()
        keyStore.failLoadError = loadError

        XCTAssertEqual(
            store.classifyHandleAvailability(expected: pair),
            .unavailable(expectedCategory)
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
