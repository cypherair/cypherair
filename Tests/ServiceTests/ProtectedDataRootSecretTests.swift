import CryptoKit
import Foundation
import LocalAuthentication
import XCTest
@testable import CypherAir

@MainActor
final class ProtectedDataRootSecretTests: ProtectedDataFrameworkTestCase {
    func test_rootSecretEnvelope_roundTripsWithMockDeviceBindingProvider() throws {
        let provider = MockProtectedDataDeviceBindingProvider()
        let rootSecret = Data(repeating: 0x42, count: ProtectedDataRootSecretEnvelope.expectedRootSecretLength)
        let envelope = try provider.sealRootSecret(rootSecret, sharedRightIdentifier: envelopeTestSharedRight)
        let encoded = try ProtectedDataRootSecretEnvelopeCodec.encode(envelope)
        let decoded = try ProtectedDataRootSecretEnvelopeCodec.decode(
            encoded,
            expectedSharedRightIdentifier: envelopeTestSharedRight
        )

        var openedSecret = try provider.openRootSecret(
            envelope: decoded,
            expectedSharedRightIdentifier: envelopeTestSharedRight
        )
        defer {
            openedSecret.protectedDataZeroize()
        }

        XCTAssertEqual(decoded.magic, ProtectedDataRootSecretEnvelope.magic)
        XCTAssertEqual(decoded.formatVersion, ProtectedDataRootSecretEnvelope.currentFormatVersion)
        XCTAssertEqual(decoded.aadVersion, ProtectedDataRootSecretEnvelope.currentAADVersion)
        XCTAssertEqual(ProtectedDataRootSecretEnvelope.currentAADVersion, 2)
        XCTAssertEqual(decoded.algorithmID, ProtectedDataRootSecretEnvelope.algorithmID)
        XCTAssertEqual(decoded.hkdfSalt.count, ProtectedDataRootSecretEnvelope.expectedSaltLength)
        XCTAssertEqual(decoded.nonce.count, ProtectedDataRootSecretEnvelope.expectedNonceLength)
        XCTAssertEqual(decoded.tag.count, ProtectedDataRootSecretEnvelope.expectedAuthenticationTagLength)
        XCTAssertEqual(decoded.ciphertext.count, ProtectedDataRootSecretEnvelope.expectedRootSecretLength)
        XCTAssertEqual(openedSecret, rootSecret)
    }

    func test_rootSecretEnvelope_rejectsTamperedAuthenticatedFields() throws {
        let provider = MockProtectedDataDeviceBindingProvider()
        let rootSecret = Data(repeating: 0x24, count: ProtectedDataRootSecretEnvelope.expectedRootSecretLength)
        let envelope = try provider.sealRootSecret(rootSecret, sharedRightIdentifier: envelopeTestSharedRight)

        let tamperedEnvelopes = [
            replacing(envelope, hkdfSalt: flippedFirstByte(envelope.hkdfSalt)),
            replacing(envelope, nonce: flippedFirstByte(envelope.nonce)),
            replacing(envelope, ciphertext: flippedFirstByte(envelope.ciphertext)),
            replacing(envelope, tag: flippedFirstByte(envelope.tag)),
            replacing(envelope, deviceBindingPublicKeyX963: flippedFirstByte(envelope.deviceBindingPublicKeyX963)),
            replacing(envelope, ephemeralPublicKeyX963: flippedFirstByte(envelope.ephemeralPublicKeyX963))
        ]

        for tamperedEnvelope in tamperedEnvelopes {
            XCTAssertThrowsError(
                try provider.openRootSecret(
                    envelope: tamperedEnvelope,
                    expectedSharedRightIdentifier: envelopeTestSharedRight
                )
            )
        }
    }

    func test_rootSecretEnvelope_aadV2BindsEphemeralPublicKeyAndRejectsAADV1() throws {
        let provider = MockProtectedDataDeviceBindingProvider()
        let rootSecret = Data(repeating: 0x26, count: ProtectedDataRootSecretEnvelope.expectedRootSecretLength)
        let envelope = try provider.sealRootSecret(rootSecret, sharedRightIdentifier: envelopeTestSharedRight)
        let substituteEphemeralPublicKey = P256.KeyAgreement.PrivateKey().publicKey.x963Representation

        let originalAAD = try ProtectedDataRootSecretEnvelopeCodec.rootSecretEnvelopeAAD(
            sharedRightIdentifier: envelope.sharedRightIdentifier,
            deviceBindingKeyIdentifier: envelope.deviceBindingKeyIdentifier,
            deviceBindingPublicKeyX963: envelope.deviceBindingPublicKeyX963,
            ephemeralPublicKeyX963: envelope.ephemeralPublicKeyX963,
            rootSecretLength: envelope.ciphertext.count
        )
        let substitutedAAD = try ProtectedDataRootSecretEnvelopeCodec.rootSecretEnvelopeAAD(
            sharedRightIdentifier: envelope.sharedRightIdentifier,
            deviceBindingKeyIdentifier: envelope.deviceBindingKeyIdentifier,
            deviceBindingPublicKeyX963: envelope.deviceBindingPublicKeyX963,
            ephemeralPublicKeyX963: substituteEphemeralPublicKey,
            rootSecretLength: envelope.ciphertext.count
        )

        XCTAssertNotEqual(originalAAD, substitutedAAD)

        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        let aadV1Payload = try encoder.encode(replacing(envelope, aadVersion: 1))
        XCTAssertThrowsError(try ProtectedDataRootSecretEnvelopeCodec.decode(
            aadV1Payload,
            expectedSharedRightIdentifier: envelopeTestSharedRight
        ))
    }

    func test_rootSecretEnvelope_rejectsMalformedContractAndUnsupportedFields() throws {
        let provider = MockProtectedDataDeviceBindingProvider()
        let rootSecret = Data(repeating: 0x35, count: ProtectedDataRootSecretEnvelope.expectedRootSecretLength)
        let envelope = try provider.sealRootSecret(rootSecret, sharedRightIdentifier: envelopeTestSharedRight)

        XCTAssertThrowsError(try ProtectedDataRootSecretEnvelopeCodec.encode(replacing(envelope, magic: "CAPDSEV1")))
        XCTAssertThrowsError(try ProtectedDataRootSecretEnvelopeCodec.encode(replacing(envelope, formatVersion: 1)))
        XCTAssertThrowsError(try ProtectedDataRootSecretEnvelopeCodec.encode(replacing(envelope, algorithmID: "other")))
        XCTAssertThrowsError(try ProtectedDataRootSecretEnvelopeCodec.encode(replacing(envelope, hkdfSalt: Data(repeating: 0x00, count: 31))))
        XCTAssertThrowsError(try ProtectedDataRootSecretEnvelopeCodec.encode(replacing(envelope, nonce: Data(repeating: 0x00, count: 11))))
        XCTAssertThrowsError(try ProtectedDataRootSecretEnvelopeCodec.encode(replacing(envelope, tag: Data(repeating: 0x00, count: 15))))
        XCTAssertThrowsError(try ProtectedDataRootSecretEnvelopeCodec.encode(replacing(envelope, ciphertext: Data(repeating: 0x00, count: 31))))
        XCTAssertThrowsError(try ProtectedDataRootSecretEnvelopeCodec.decode(
            try encodedEnvelopeWithUnsupportedField(from: envelope),
            expectedSharedRightIdentifier: envelopeTestSharedRight
        ))
    }

    func test_rootSecretEnvelope_rejectsWrongSharedRightIdentifier() throws {
        let provider = MockProtectedDataDeviceBindingProvider()
        let rootSecret = Data(repeating: 0x53, count: ProtectedDataRootSecretEnvelope.expectedRootSecretLength)
        let envelope = try provider.sealRootSecret(rootSecret, sharedRightIdentifier: envelopeTestSharedRight)

        XCTAssertThrowsError(
            try ProtectedDataRootSecretEnvelopeCodec.decode(
                try ProtectedDataRootSecretEnvelopeCodec.encode(envelope),
                expectedSharedRightIdentifier: "\(envelopeTestSharedRight).wrong"
            )
        )
        XCTAssertThrowsError(
            try provider.openRootSecret(
                envelope: envelope,
                expectedSharedRightIdentifier: "\(envelopeTestSharedRight).wrong"
            )
        )
    }

    func test_rootSecretStore_migratesLegacyRawPayloadAndWritesFormatFloor() throws {
        let account = "ProtectedDataRootSecretTests.\(#function).\(UUID().uuidString)"
        let identifier = "\(envelopeTestSharedRight).migration.\(UUID().uuidString)"
        let legacySecret = Data(repeating: 0x61, count: ProtectedDataRootSecretEnvelope.expectedRootSecretLength)
        try insertLegacyRootSecret(legacySecret, identifier: identifier, account: account)
        defer {
            deleteRootSecretPayload(identifier: identifier, account: account)
        }

        let floorKeychain = MockKeychain()
        try floorKeychain.save(
            Data([0x91]),
            service: KeychainConstants.protectedDataRootSecretLegacyCleanupService,
            account: account,
            accessControl: nil
        )
        let floorStore = ProtectedDataRootSecretFormatFloorStore(keychain: floorKeychain, account: account)
        let store = KeychainProtectedDataRootSecretStore(
            account: account,
            supportKeychain: floorKeychain,
            deviceBindingProvider: MockProtectedDataDeviceBindingProvider(),
            formatFloorStore: floorStore
        )

        var result = try store.loadRootSecret(
            identifier: identifier,
            authenticationContext: LAContext(),
            minimumEnvelopeVersion: nil
        )
        defer {
            result.secretData.protectedDataZeroize()
        }

        XCTAssertEqual(result.secretData, legacySecret)
        XCTAssertEqual(result.storageFormat, .envelopeV2)
        XCTAssertTrue(result.didMigrate)
        XCTAssertEqual(
            try floorStore.readMinimumEnvelopeVersion(sharedRightIdentifier: identifier),
            ProtectedDataRootSecretEnvelope.currentFormatVersion
        )
        XCTAssertFalse(floorKeychain.exists(
            service: KeychainConstants.protectedDataRootSecretLegacyCleanupService,
            account: account
        ))

        let migratedPayload = try loadRootSecretPayload(identifier: identifier, account: account)
        XCTAssertNotEqual(migratedPayload.count, ProtectedDataRootSecretEnvelope.expectedRootSecretLength)
        XCTAssertNoThrow(try ProtectedDataRootSecretEnvelopeCodec.decode(
            migratedPayload,
            expectedSharedRightIdentifier: identifier
        ))
    }

    func test_rootSecretStore_legacyMigrationFloorWriteFailureThrowsAfterMigratingPayload() throws {
        let account = "ProtectedDataRootSecretTests.\(#function).\(UUID().uuidString)"
        let identifier = "\(envelopeTestSharedRight).migration-floor-failure.\(UUID().uuidString)"
        let legacySecret = Data(repeating: 0x63, count: ProtectedDataRootSecretEnvelope.expectedRootSecretLength)
        try insertLegacyRootSecret(legacySecret, identifier: identifier, account: account)
        defer {
            deleteRootSecretPayload(identifier: identifier, account: account)
        }

        let floorKeychain = MockKeychain()
        try floorKeychain.save(
            Data([0x91]),
            service: KeychainConstants.protectedDataRootSecretLegacyCleanupService,
            account: account,
            accessControl: nil
        )
        floorKeychain.failOnSaveNumber = 2
        let floorStore = ProtectedDataRootSecretFormatFloorStore(keychain: floorKeychain, account: account)
        let store = KeychainProtectedDataRootSecretStore(
            account: account,
            supportKeychain: floorKeychain,
            deviceBindingProvider: MockProtectedDataDeviceBindingProvider(),
            formatFloorStore: floorStore
        )

        XCTAssertThrowsError(try store.loadRootSecret(
            identifier: identifier,
            authenticationContext: LAContext(),
            minimumEnvelopeVersion: nil
        ))
        XCTAssertNil(try floorStore.readMinimumEnvelopeVersion(sharedRightIdentifier: identifier))
        let migratedPayload = try loadRootSecretPayload(identifier: identifier, account: account)
        XCTAssertNotEqual(migratedPayload.count, ProtectedDataRootSecretEnvelope.expectedRootSecretLength)
    }

    func test_rootSecretStore_rejectsLegacyDowngradeAfterFormatFloor() throws {
        let account = "ProtectedDataRootSecretTests.\(#function).\(UUID().uuidString)"
        let identifier = "\(envelopeTestSharedRight).downgrade.\(UUID().uuidString)"
        let legacySecret = Data(repeating: 0x72, count: ProtectedDataRootSecretEnvelope.expectedRootSecretLength)
        try insertLegacyRootSecret(legacySecret, identifier: identifier, account: account)
        defer {
            deleteRootSecretPayload(identifier: identifier, account: account)
        }

        let floorKeychain = MockKeychain()
        let floorStore = ProtectedDataRootSecretFormatFloorStore(keychain: floorKeychain, account: account)
        let store = KeychainProtectedDataRootSecretStore(
            account: account,
            supportKeychain: floorKeychain,
            deviceBindingProvider: MockProtectedDataDeviceBindingProvider(),
            formatFloorStore: floorStore
        )

        var migratedResult = try store.loadRootSecret(
            identifier: identifier,
            authenticationContext: LAContext(),
            minimumEnvelopeVersion: nil
        )
        migratedResult.secretData.protectedDataZeroize()

        try replaceRootSecretPayload(legacySecret, identifier: identifier, account: account)

        XCTAssertThrowsError(
            try store.loadRootSecret(
                identifier: identifier,
                authenticationContext: LAContext(),
                minimumEnvelopeVersion: nil
            )
        )
    }
}
