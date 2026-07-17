import LocalAuthentication
import XCTest
@testable import CypherAir

final class SecureEnclaveCustodyHandleStoreTests: XCTestCase {
    func test_createLoadedHandlePair_generatesDistinctSigningAndAgreementHandles() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256)

        let pair = try store.createLoadedHandlePair(authenticationContext: nil)

        XCTAssertEqual(pair.signing.role, .signing)
        XCTAssertEqual(pair.keyAgreement.role, .keyAgreement)
        XCTAssertEqual(
            pair.signing.reference.handleSetIdentifier,
            pair.keyAgreement.reference.handleSetIdentifier
        )
        XCTAssertEqual(pair.signing.reference.tier, .classicalP256)
        XCTAssertNotEqual(pair.signing.binding.publicKeyRaw, pair.keyAgreement.binding.publicKeyRaw)
        XCTAssertEqual(keyStore.createRequests.count, 2)
    }

    func test_createLoadedHandlePair_requestsCustodySpecificAccessPolicy() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256)

        _ = try store.createLoadedHandlePair(authenticationContext: nil)

        XCTAssertEqual(keyStore.createRequests.count, 2)
        for request in keyStore.createRequests {
            XCTAssertEqual(request.accessPolicy, .privateKeyUsageBiometryAny)
        }
    }

    func test_createLoadedHandlePair_secondCreateFailureRollsBackBothReferences() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        keyStore.failCreateRole = .keyAgreement
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256)

        XCTAssertThrowsError(try store.createLoadedHandlePair(authenticationContext: nil))

        XCTAssertEqual(keyStore.deleteRequests.count, 2)
        XCTAssertEqual(keyStore.storedHandleCount(), 0)
    }

    func test_createLoadedHandlePair_pairAssemblyFailureRollsBackBothCreatedHandles() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        // Identical public keys make the pair invariant fail after both
        // creations succeed.
        let sharedPublicKey = Data([0x04]) + Data(repeating: 0x7F, count: 64)
        keyStore.publicKeyResponses = [sharedPublicKey, sharedPublicKey]
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256)

        XCTAssertThrowsError(try store.createLoadedHandlePair(authenticationContext: nil)) { error in
            XCTAssertEqual(
                error as? SecureEnclaveCustodyHandleError,
                .handlePublicKeyBindingMismatch(.keyAgreement)
            )
        }
        XCTAssertEqual(keyStore.storedHandleCount(), 0)
    }

    func test_loadHandle_threadsAuthenticationContextToKeyStore() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256)
        let pair = try store.createLoadedHandlePair(authenticationContext: nil)
        let context = LAContext()

        _ = try store.loadHandle(
            reference: pair.signing.reference,
            expectedPublicKeyRaw: pair.signing.binding.publicKeyRaw,
            authenticationContext: context
        )

        XCTAssertEqual(keyStore.loadRequests.count, 1)
        XCTAssertTrue(keyStore.loadRequests[0].authenticationContext === context)
    }

    func test_loadHandle_failsClosedForMissingHandle() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256)
        let reference = try SecureEnclaveCustodyHandleReference(
            handleSetIdentifier: "0badc0de",
            role: .signing,
            tier: .classicalP256
        )

        XCTAssertThrowsError(try store.loadHandle(
            reference: reference,
            expectedPublicKeyRaw: Data([0x04]) + Data(repeating: 0x11, count: 64),
            authenticationContext: nil
        )) { error in
            XCTAssertEqual(
                error as? SecureEnclaveCustodyHandleError,
                .privateHandleMissing(.signing)
            )
        }
    }

    func test_loadHandle_failsClosedForWrongPublicKeyBinding() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256)
        let pair = try store.createLoadedHandlePair(authenticationContext: nil)

        XCTAssertThrowsError(try store.loadHandle(
            reference: pair.signing.reference,
            expectedPublicKeyRaw: Data([0x04]) + Data(repeating: 0x55, count: 64),
            authenticationContext: nil
        )) { error in
            XCTAssertEqual(
                error as? SecureEnclaveCustodyHandleError,
                .handlePublicKeyBindingMismatch(.signing)
            )
        }
    }

    func test_loadHandle_rejectsMalformedExpectedPublicKeyShape() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256)
        let reference = try SecureEnclaveCustodyHandleReference(
            handleSetIdentifier: "0badc0de",
            role: .keyAgreement,
            tier: .classicalP256
        )

        XCTAssertThrowsError(try store.loadHandle(
            reference: reference,
            expectedPublicKeyRaw: Data(repeating: 0x11, count: 64),
            authenticationContext: nil
        )) { error in
            XCTAssertEqual(
                error as? SecureEnclaveCustodyHandleError,
                .invalidPublicKey(.keyAgreement)
            )
        }
        XCTAssertTrue(keyStore.loadRequests.isEmpty)
    }

    func test_publicBindingShapeChecksPerTierAndRole() {
        var validX963 = Data([0x04])
        validX963.append(Data(repeating: 0x21, count: 64))
        XCTAssertTrue(SecureEnclaveCustodyHandlePublicBinding.hasExpectedPublicKeyShape(
            validX963, role: .signing, tier: .classicalP256
        ))
        XCTAssertFalse(SecureEnclaveCustodyHandlePublicBinding.hasExpectedPublicKeyShape(
            Data(repeating: 0x21, count: 65), role: .signing, tier: .classicalP256
        ))
        XCTAssertFalse(SecureEnclaveCustodyHandlePublicBinding.hasExpectedPublicKeyShape(
            Data([0x04]) + Data(repeating: 0, count: 64), role: .signing, tier: .classicalP256
        ))
        XCTAssertTrue(SecureEnclaveCustodyHandlePublicBinding.hasExpectedPublicKeyShape(
            Data(repeating: 0x21, count: 1952), role: .signing, tier: .postQuantum
        ))
        XCTAssertTrue(SecureEnclaveCustodyHandlePublicBinding.hasExpectedPublicKeyShape(
            Data(repeating: 0x21, count: 1568), role: .keyAgreement, tier: .postQuantumHigh
        ))
        XCTAssertFalse(SecureEnclaveCustodyHandlePublicBinding.hasExpectedPublicKeyShape(
            Data(repeating: 0x21, count: 1184), role: .keyAgreement, tier: .postQuantumHigh
        ))
    }

    func test_inspectHandlePair_classifiesMissingPartialCompleteAndInvalid() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256)

        XCTAssertEqual(store.inspectHandlePair(handleSetIdentifier: "0badc0de"), .missing)
        XCTAssertEqual(
            store.inspectHandlePair(handleSetIdentifier: "NOT-VALID"),
            .invalid(.invalidHandleSetIdentifier)
        )

        let pair = try store.createLoadedHandlePair(authenticationContext: nil)
        let identifier = pair.signing.reference.handleSetIdentifier
        guard case .complete(let inspected) = store.inspectHandlePair(handleSetIdentifier: identifier) else {
            return XCTFail("Expected complete state")
        }
        XCTAssertEqual(inspected.handleSetIdentifier, identifier)

        try keyStore.deleteKey(reference: pair.keyAgreement.reference)
        XCTAssertEqual(
            store.inspectHandlePair(handleSetIdentifier: identifier),
            .partial(presentRoles: [.signing])
        )
    }

    func test_locateHandlePair_findsUniqueExactPublicBinding() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256)
        let created = try store.createLoadedHandlePair(authenticationContext: nil)
        _ = try store.createLoadedHandlePair(authenticationContext: nil)

        let located = try store.locateHandlePair(
            signingPublicKeyRaw: created.signing.binding.publicKeyRaw,
            keyAgreementPublicKeyRaw: created.keyAgreement.binding.publicKeyRaw
        )

        XCTAssertEqual(located.signing, created.signing.binding)
        XCTAssertEqual(located.keyAgreement, created.keyAgreement.binding)
    }

    func test_locateHandlePair_failsClosedForMissingMismatchedAndPartialMatches() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256)
        let created = try store.createLoadedHandlePair(authenticationContext: nil)
        let unknownKey = Data([0x04]) + Data(repeating: 0x66, count: 64)

        XCTAssertThrowsError(try store.locateHandlePair(
            signingPublicKeyRaw: unknownKey,
            keyAgreementPublicKeyRaw: Data([0x04]) + Data(repeating: 0x67, count: 64)
        )) { error in
            XCTAssertEqual(
                error as? SecureEnclaveCustodyHandleError,
                .privateHandleMissing(.signing)
            )
        }

        XCTAssertThrowsError(try store.locateHandlePair(
            signingPublicKeyRaw: created.signing.binding.publicKeyRaw,
            keyAgreementPublicKeyRaw: unknownKey
        )) { error in
            XCTAssertEqual(
                error as? SecureEnclaveCustodyHandleError,
                .handlePublicKeyBindingMismatch(.keyAgreement)
            )
        }

        XCTAssertThrowsError(try store.locateHandlePair(
            signingPublicKeyRaw: unknownKey,
            keyAgreementPublicKeyRaw: created.keyAgreement.binding.publicKeyRaw
        )) { error in
            XCTAssertEqual(
                error as? SecureEnclaveCustodyHandleError,
                .handlePublicKeyBindingMismatch(.signing)
            )
        }

        XCTAssertThrowsError(try store.locateHandlePair(
            signingPublicKeyRaw: Data(repeating: 0x01, count: 10),
            keyAgreementPublicKeyRaw: created.keyAgreement.binding.publicKeyRaw
        )) { error in
            XCTAssertEqual(
                error as? SecureEnclaveCustodyHandleError,
                .invalidPublicKey(.signing)
            )
        }

        try keyStore.deleteKey(reference: created.keyAgreement.reference)
        XCTAssertThrowsError(try store.locateHandlePair(
            signingPublicKeyRaw: created.signing.binding.publicKeyRaw,
            keyAgreementPublicKeyRaw: unknownKey
        )) { error in
            XCTAssertEqual(
                error as? SecureEnclaveCustodyHandleError,
                .partialHandlePair
            )
        }
    }

    func test_locateHandlePair_ignoresOtherTierBindings() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let classicalStore = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256)
        let compositeStore = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .postQuantum)
        let compositePair = try compositeStore.createLoadedHandlePair(authenticationContext: nil)

        XCTAssertThrowsError(try classicalStore.locateHandlePair(
            signingPublicKeyRaw: Data([0x04]) + Data(repeating: 0x66, count: 64),
            keyAgreementPublicKeyRaw: Data([0x04]) + Data(repeating: 0x67, count: 64)
        )) { error in
            XCTAssertEqual(
                error as? SecureEnclaveCustodyHandleError,
                .privateHandleMissing(.signing)
            )
        }
        _ = try compositeStore.locateHandlePair(
            signingPublicKeyRaw: compositePair.signing.binding.publicKeyRaw,
            keyAgreementPublicKeyRaw: compositePair.keyAgreement.binding.publicKeyRaw
        )
    }

    func test_deleteHandlePair_isIdempotentForMissingAndReportsCleanupFailure() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let store = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256)
        let created = try store.createLoadedHandlePair(authenticationContext: nil)
        let pair = try SecureEnclaveCustodyHandlePair(
            signing: created.signing.binding,
            keyAgreement: created.keyAgreement.binding
        )

        try store.deleteHandlePair(pair)
        XCTAssertEqual(keyStore.storedHandleCount(), 0)
        // Missing handles are tolerated so deletion converges.
        try store.deleteHandlePair(pair)

        let failing = try store.createLoadedHandlePair(authenticationContext: nil)
        let failingPair = try SecureEnclaveCustodyHandlePair(
            signing: failing.signing.binding,
            keyAgreement: failing.keyAgreement.binding
        )
        keyStore.failDeleteRole = .signing
        XCTAssertThrowsError(try store.deleteHandlePair(failingPair)) { error in
            XCTAssertEqual(
                error as? SecureEnclaveCustodyHandleError,
                .cleanupOrRollbackFailed
            )
        }
    }

    func test_deleteHandles_convergesAcrossTiersByPublicKeyBytes() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let baseStore = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .postQuantum)
        let highStore = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .postQuantumHigh)
        let highPair = try highStore.createLoadedHandlePair(authenticationContext: nil)

        // The identity-deletion path holds one store instance; matching runs on
        // raw public-key bytes across the full inventory, so it converges for
        // either tier's handles.
        try baseStore.deleteHandles(
            signingPublicKeyRaw: highPair.signing.binding.publicKeyRaw,
            keyAgreementPublicKeyRaw: highPair.keyAgreement.binding.publicKeyRaw
        )

        XCTAssertEqual(keyStore.storedHandleCount(), 0)
        // No matches left: deletion stays converged.
        try baseStore.deleteHandles(
            signingPublicKeyRaw: highPair.signing.binding.publicKeyRaw,
            keyAgreementPublicKeyRaw: highPair.keyAgreement.binding.publicKeyRaw
        )
    }

    func test_inventorySummaryClassifiesCompletePartialAndMalformedAcrossTiers() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let classicalStore = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256)
        let compositeStore = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .postQuantum)

        _ = try classicalStore.createLoadedHandlePair(authenticationContext: nil)
        let partial = try compositeStore.createLoadedHandlePair(authenticationContext: nil)
        try keyStore.deleteKey(reference: partial.keyAgreement.reference)
        keyStore.insertMalformedRow()

        let summary = try classicalStore.inventorySummaryForLocalRecovery()

        XCTAssertEqual(summary.totalHandleCount, 4)
        XCTAssertEqual(summary.completeSetCount, 1)
        XCTAssertEqual(summary.partialSetCount, 1)
        XCTAssertEqual(summary.malformedHandleCount, 1)
    }

    func test_cleanupForLocalDataResetSweepsAllTiersIncludingMalformedRows() throws {
        let keyStore = MockSecureEnclaveCustodyKeyStore()
        let classicalStore = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .classicalP256)
        let highStore = SecureEnclaveCustodyHandleStore(keyStore: keyStore, tier: .postQuantumHigh)
        _ = try classicalStore.createLoadedHandlePair(authenticationContext: nil)
        _ = try highStore.createLoadedHandlePair(authenticationContext: nil)
        keyStore.insertMalformedRow(tier: .postQuantum, role: .signing)

        let result = classicalStore.cleanupAllHandlesForLocalDataReset()

        XCTAssertTrue(result.succeeded)
        XCTAssertEqual(result.inspectedHandleCount, 5)
        XCTAssertEqual(result.deletedHandleCount, 5)
        XCTAssertEqual(try classicalStore.remainingHandleCountForLocalDataReset(), 0)
    }

    func test_cleanupForLocalDataResetFailsClosedForInventoryOrSweepFailure() throws {
        let inventoryFailing = MockSecureEnclaveCustodyKeyStore()
        inventoryFailing.failInventory = true
        let inventoryFailingStore = SecureEnclaveCustodyHandleStore(
            keyStore: inventoryFailing,
            tier: .classicalP256
        )
        let inventoryResult = inventoryFailingStore.cleanupAllHandlesForLocalDataReset()
        XCTAssertEqual(inventoryResult.failureCategory, .cleanupOrRollbackFailure)

        let sweepFailing = MockSecureEnclaveCustodyKeyStore()
        let sweepFailingStore = SecureEnclaveCustodyHandleStore(
            keyStore: sweepFailing,
            tier: .classicalP256
        )
        _ = try sweepFailingStore.createLoadedHandlePair(authenticationContext: nil)
        sweepFailing.failDeleteAllKeys = true
        let sweepResult = sweepFailingStore.cleanupAllHandlesForLocalDataReset()
        XCTAssertEqual(sweepResult.failureCategory, .cleanupOrRollbackFailure)
    }

    func test_handleSetIdentifierGeneratorEmitsValidLowercaseHex() throws {
        let identifier = try SecureEnclaveCustodyHandleReference.generateHandleSetIdentifier()
        XCTAssertEqual(identifier.count, 32)
        XCTAssertTrue(SecureEnclaveCustodyHandleReference.isValidHandleSetIdentifier(identifier))
        XCTAssertFalse(SecureEnclaveCustodyHandleReference.isValidHandleSetIdentifier("UPPER"))
        XCTAssertFalse(SecureEnclaveCustodyHandleReference.isValidHandleSetIdentifier("with-dash"))
        XCTAssertFalse(SecureEnclaveCustodyHandleReference.isValidHandleSetIdentifier(""))
    }

    func test_referenceServiceStringsAreTierAndRoleNamespaced() throws {
        let signing = try SecureEnclaveCustodyHandleReference(
            handleSetIdentifier: "0badc0de",
            role: .signing,
            tier: .classicalP256
        )
        let keyAgreement = try SecureEnclaveCustodyHandleReference(
            handleSetIdentifier: "0badc0de",
            role: .keyAgreement,
            tier: .postQuantumHigh
        )
        XCTAssertEqual(
            signing.serviceString,
            "com.cypherair.v1.secure-enclave-custody.p256.signing"
        )
        XCTAssertEqual(
            keyAgreement.serviceString,
            "com.cypherair.v1.secure-enclave-custody.post-quantum-high.keyAgreement"
        )
    }

}
