import CryptoKit
import Foundation
import XCTest
@testable import CypherAir

/// Positive and negative coverage for the private-key Secure Enclave envelope.
///
/// The full seal → encode → decode → open path is exercised through
/// `MockSecureEnclave`, which performs the same ephemeral-static ECDH + HKDF +
/// AES-GCM construction as production using a software P-256 key. Contract-level
/// rejection is exercised directly against `PrivateKeyEnvelopeCodec`.
final class PrivateKeyEnvelopeTests: XCTestCase {
    private let fingerprint = "0123456789abcdef0123456789abcdef01234567"
    private var secureEnclave: MockSecureEnclave!

    override func setUp() {
        super.setUp()
        secureEnclave = MockSecureEnclave()
    }

    override func tearDown() {
        secureEnclave = nil
        super.tearDown()
    }

    // MARK: - Positive round-trip

    func test_envelope_roundTripsThroughSecureEnclave() throws {
        let privateKey = Data(repeating: 0xAB, count: 57) // Ed448-size secret material
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let bundle = try secureEnclave.wrap(
            privateKey: SensitiveBuffer(copying: privateKey),
            using: handle,
            fingerprint: fingerprint,
            payloadKind: .softwareSecretCertificate
        )

        let decoded = try PrivateKeyEnvelopeCodec.decode(
            bundle.envelope,
            expectedFingerprint: fingerprint,
            expectedPayloadKind: .softwareSecretCertificate
        )
        XCTAssertEqual(decoded.magic, PrivateKeyEnvelope.magic)
        XCTAssertEqual(decoded.magic, "CAPKEV1")
        XCTAssertEqual(decoded.fingerprint, fingerprint)
        XCTAssertEqual(decoded.seKeyData, handle.dataRepresentation)
        XCTAssertEqual(decoded.hkdfSalt.count, PrivateKeyEnvelope.expectedSaltLength)
        XCTAssertEqual(decoded.nonce.count, PrivateKeyEnvelope.expectedNonceLength)
        XCTAssertEqual(decoded.tag.count, PrivateKeyEnvelope.expectedAuthenticationTagLength)
        XCTAssertEqual(decoded.seKeyPublicKeyX963.count, PrivateKeyEnvelope.expectedP256X963Length)
        XCTAssertEqual(decoded.ephemeralPublicKeyX963.count, PrivateKeyEnvelope.expectedP256X963Length)
        XCTAssertEqual(decoded.ciphertext.count, privateKey.count)

        let unwrapped = try secureEnclave.unwrap(
            bundle: bundle,
            using: handle,
            fingerprint: fingerprint,
            payloadKind: .softwareSecretCertificate
        ).copiedBytes()
        XCTAssertEqual(unwrapped, privateKey)
    }

    func test_envelope_freshSealUsesDistinctEphemeralKeyAndNonce() throws {
        let privateKey = Data(repeating: 0x11, count: 32)
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)

        let first = try decodedSoftwareEnvelope(sealing: privateKey, using: handle)
        let second = try decodedSoftwareEnvelope(sealing: privateKey, using: handle)

        XCTAssertNotEqual(first.ephemeralPublicKeyX963, second.ephemeralPublicKeyX963)
        XCTAssertNotEqual(first.hkdfSalt, second.hkdfSalt)
        XCTAssertNotEqual(first.nonce, second.nonce)
        XCTAssertNotEqual(first.ciphertext, second.ciphertext)
    }

    func test_envelope_largePayloadPastFormerLimit_roundTrips() throws {
        // The wrapped payload is a full transferable secret key — a real imported key with a
        // photo-UID attribute or many third-party certifications can be tens of KiB, far past
        // the former 16 KiB guard. It must seal, encode, decode, and unwrap cleanly with the
        // exact length authenticated in the AAD.
        let largePrivateKey = Data((0..<(64 * 1024)).map { UInt8(truncatingIfNeeded: $0) })
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let bundle = try secureEnclave.wrap(
            privateKey: SensitiveBuffer(copying: largePrivateKey),
            using: handle,
            fingerprint: fingerprint,
            payloadKind: .softwareSecretCertificate
        )

        let decoded = try PrivateKeyEnvelopeCodec.decode(
            bundle.envelope,
            expectedFingerprint: fingerprint,
            expectedPayloadKind: .softwareSecretCertificate
        )
        XCTAssertEqual(decoded.ciphertext.count, largePrivateKey.count)

        let unwrapped = try secureEnclave.unwrap(
            bundle: bundle,
            using: handle,
            fingerprint: fingerprint,
            payloadKind: .softwareSecretCertificate
        ).copiedBytes()
        XCTAssertEqual(unwrapped, largePrivateKey)
    }

    // MARK: - Tamper / wrong-binding

    func test_envelope_rejectsTamperedAuthenticatedFields() throws {
        let privateKey = Data(repeating: 0x24, count: 32)
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let envelope = try decodedSoftwareEnvelope(sealing: privateKey, using: handle)

        let substitutePublicKey = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        let tampered: [PrivateKeyEnvelope] = [
            replacing(envelope, hkdfSalt: flippedFirstByte(envelope.hkdfSalt)),
            replacing(envelope, nonce: flippedFirstByte(envelope.nonce)),
            replacing(envelope, ciphertext: flippedFirstByte(envelope.ciphertext)),
            replacing(envelope, tag: flippedFirstByte(envelope.tag)),
            replacing(envelope, ephemeralPublicKeyX963: substitutePublicKey)
        ]

        for tamperedEnvelope in tampered {
            let encoded = try PrivateKeyEnvelopeCodec.encode(tamperedEnvelope)
            assertThrowsError(
                try secureEnclave.unwrap(
                    bundle: WrappedKeyBundle(envelope: encoded),
                    using: handle,
                    fingerprint: fingerprint,
                    payloadKind: .softwareSecretCertificate
                ),
                "Tampered authenticated field must fail closed"
            )
        }
    }

    func test_envelope_wrongBoundPublicKey_failsClosedBeforeKeyAgreement() throws {
        let privateKey = Data(repeating: 0x42, count: 32)
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let envelope = try decodedSoftwareEnvelope(sealing: privateKey, using: handle)

        // Re-bind the envelope to a different (valid) SE public key, then unwrap with the
        // original handle → the bound-key guard fires before any ECDH.
        let rebound = replacing(envelope, seKeyPublicKeyX963: P256.KeyAgreement.PrivateKey().publicKey.x963Representation)
        assertThrowsError(
            try secureEnclave.unwrap(
                bundle: WrappedKeyBundle(envelope: try PrivateKeyEnvelopeCodec.encode(rebound)),
                using: handle,
                fingerprint: fingerprint,
                payloadKind: .softwareSecretCertificate
            )
        ) { error in
            XCTAssertEqual(error as? PrivateKeyEnvelopeError, .deviceBindingMismatch)
        }
    }

    func test_envelope_wrongHandle_failsClosed() throws {
        let privateKey = Data(repeating: 0x53, count: 32)
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let otherHandle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let bundle = try secureEnclave.wrap(
            privateKey: SensitiveBuffer(copying: privateKey),
            using: handle,
            fingerprint: fingerprint,
            payloadKind: .softwareSecretCertificate
        )

        assertThrowsError(
            try secureEnclave.unwrap(
                bundle: bundle,
                using: otherHandle,
                fingerprint: fingerprint,
                payloadKind: .softwareSecretCertificate
            )
        )
    }

    func test_envelope_wrongFingerprint_failsClosed() throws {
        let privateKey = Data(repeating: 0x64, count: 32)
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let bundle = try secureEnclave.wrap(
            privateKey: SensitiveBuffer(copying: privateKey),
            using: handle,
            fingerprint: fingerprint,
            payloadKind: .softwareSecretCertificate
        )

        let otherFingerprint = "fedcba9876543210fedcba9876543210fedcba98"
        assertThrowsError(
            try secureEnclave.unwrap(
                bundle: bundle,
                using: handle,
                fingerprint: otherFingerprint,
                payloadKind: .softwareSecretCertificate
            )
        )
        XCTAssertThrowsError(
            try PrivateKeyEnvelopeCodec.decode(
                bundle.envelope,
                expectedFingerprint: otherFingerprint,
                expectedPayloadKind: .softwareSecretCertificate
            )
        )
    }

    // MARK: - Contract rejection

    func test_envelope_rejectsMalformedContractAndUnsupportedFields() throws {
        let privateKey = Data(repeating: 0x35, count: 32)
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let envelope = try decodedSoftwareEnvelope(sealing: privateKey, using: handle)

        XCTAssertThrowsError(try PrivateKeyEnvelopeCodec.encode(replacing(envelope, magic: "CAPKEX1")))
        XCTAssertThrowsError(try PrivateKeyEnvelopeCodec.encode(replacing(envelope, fingerprint: "NOTHEX!!")))
        XCTAssertThrowsError(try PrivateKeyEnvelopeCodec.encode(replacing(envelope, fingerprint: "ABCDEF01")))
        XCTAssertThrowsError(try PrivateKeyEnvelopeCodec.encode(replacing(envelope, seKeyData: Data())))
        XCTAssertThrowsError(try PrivateKeyEnvelopeCodec.encode(replacing(envelope, hkdfSalt: Data(repeating: 0, count: 31))))
        XCTAssertThrowsError(try PrivateKeyEnvelopeCodec.encode(replacing(envelope, nonce: Data(repeating: 0, count: 11))))
        XCTAssertThrowsError(try PrivateKeyEnvelopeCodec.encode(replacing(envelope, tag: Data(repeating: 0, count: 15))))
        XCTAssertThrowsError(try PrivateKeyEnvelopeCodec.encode(replacing(envelope, ciphertext: Data())))
        XCTAssertThrowsError(
            try PrivateKeyEnvelopeCodec.decode(
                try encodedEnvelopeWithUnsupportedField(from: envelope),
                expectedFingerprint: fingerprint,
                expectedPayloadKind: .softwareSecretCertificate
            )
        )
    }

    func test_envelope_undecodableBlob_failsClosed() throws {
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let garbage = WrappedKeyBundle(envelope: Data("not-a-private-key-envelope".utf8))

        XCTAssertThrowsError(
            try PrivateKeyEnvelopeCodec.decode(
                garbage.envelope,
                expectedFingerprint: fingerprint,
                expectedPayloadKind: .softwareSecretCertificate
            )
        )
        assertThrowsError(
            try secureEnclave.unwrap(
                bundle: garbage,
                using: handle,
                fingerprint: fingerprint,
                payloadKind: .softwareSecretCertificate
            )
        )
    }

    // MARK: - Payload-kind separation

    func test_envelope_sealedAsOneKind_cannotBeOpenedAsTheOther() throws {
        let component = Data(repeating: 0x71, count: 64)
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let bundle = try secureEnclave.wrap(
            privateKey: SensitiveBuffer(copying: component),
            using: handle,
            fingerprint: fingerprint,
            payloadKind: .splitCustodyClassicalComponent
        )

        assertThrowsError(
            try secureEnclave.unwrap(
                bundle: bundle,
                using: handle,
                fingerprint: fingerprint,
                payloadKind: .softwareSecretCertificate
            ),
            "A classical component must not open as a software secret certificate"
        ) { error in
            XCTAssertEqual(error as? PrivateKeyEnvelopeError, .payloadKindMismatch)
        }
        XCTAssertThrowsError(
            try PrivateKeyEnvelopeCodec.seKeyData(
                from: bundle.envelope,
                expectedFingerprint: fingerprint,
                expectedPayloadKind: .softwareSecretCertificate
            ),
            "The kind must be rejected before any Secure Enclave reconstruct"
        ) { error in
            XCTAssertEqual(error as? PrivateKeyEnvelopeError, .payloadKindMismatch)
        }

        var opened = try secureEnclave.unwrap(
            bundle: bundle,
            using: handle,
            fingerprint: fingerprint,
            payloadKind: .splitCustodyClassicalComponent
        ).copiedBytes()
        defer { opened.zeroize() }
        XCTAssertEqual(opened, component)
    }

    func test_envelope_relabelledPayloadKind_failsTheAEAD() throws {
        // The contract check is not the only thing standing between the two
        // payload kinds: rewrite the stored field so contract validation passes,
        // and the AES-GCM AAD — which binds the kind — must still reject it.
        let component = Data(repeating: 0x72, count: 64)
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let sealed = try PrivateKeyEnvelopeCodec.decode(
            try secureEnclave.wrap(
                privateKey: SensitiveBuffer(copying: component),
                using: handle,
                fingerprint: fingerprint,
                payloadKind: .splitCustodyClassicalComponent
            ).envelope,
            expectedFingerprint: fingerprint,
            expectedPayloadKind: .splitCustodyClassicalComponent
        )

        let relabelled = replacing(sealed, payloadKind: .softwareSecretCertificate)
        let encoded = try PrivateKeyEnvelopeCodec.encode(relabelled)

        assertThrowsError(
            try secureEnclave.unwrap(
                bundle: WrappedKeyBundle(envelope: encoded),
                using: handle,
                fingerprint: fingerprint,
                payloadKind: .softwareSecretCertificate
            )
        ) { error in
            XCTAssertTrue(
                error is CryptoKitError,
                "Expected an AEAD failure, got \(error)"
            )
        }
    }

    // MARK: - Helpers

    private func decodedSoftwareEnvelope(
        sealing privateKey: Data,
        using handle: any SEKeyHandle
    ) throws -> PrivateKeyEnvelope {
        try PrivateKeyEnvelopeCodec.decode(
            try secureEnclave.wrap(
                privateKey: SensitiveBuffer(copying: privateKey),
                using: handle,
                fingerprint: fingerprint,
                payloadKind: .softwareSecretCertificate
            ).envelope,
            expectedFingerprint: fingerprint,
            expectedPayloadKind: .softwareSecretCertificate
        )
    }

    private func flippedFirstByte(_ data: Data) -> Data {
        var copy = data
        copy[copy.startIndex] ^= 0xFF
        return copy
    }

    private func encodedEnvelopeWithUnsupportedField(from envelope: PrivateKeyEnvelope) throws -> Data {
        let encoded = try PrivateKeyEnvelopeCodec.encode(envelope)
        var format = PropertyListSerialization.PropertyListFormat.binary
        guard var dictionary = try PropertyListSerialization.propertyList(
            from: encoded,
            options: [],
            format: &format
        ) as? [String: Any] else {
            throw PrivateKeyEnvelopeError.invalidEnvelope("Test payload is not a dictionary.")
        }
        dictionary["unsupportedField"] = Data([0x00])
        return try PropertyListSerialization.data(fromPropertyList: dictionary, format: .binary, options: 0)
    }

    // Each field is resolved into an explicitly typed local first: as one
    // expression, the chained `??` operators blow past the type-checker's budget.
    private func replacing(
        _ envelope: PrivateKeyEnvelope,
        magic: String? = nil,
        payloadKind: PrivateKeyEnvelopePayloadKind? = nil,
        fingerprint: String? = nil,
        seKeyData: Data? = nil,
        seKeyPublicKeyX963: Data? = nil,
        ephemeralPublicKeyX963: Data? = nil,
        hkdfSalt: Data? = nil,
        nonce: Data? = nil,
        ciphertext: Data? = nil,
        tag: Data? = nil
    ) -> PrivateKeyEnvelope {
        let resolvedMagic: String = magic ?? envelope.magic
        let resolvedPayloadKind: PrivateKeyEnvelopePayloadKind = payloadKind ?? envelope.payloadKind
        let resolvedFingerprint: String = fingerprint ?? envelope.fingerprint
        let resolvedSEKeyData: Data = seKeyData ?? envelope.seKeyData
        let resolvedSEKeyPublicKey: Data = seKeyPublicKeyX963 ?? envelope.seKeyPublicKeyX963
        let resolvedEphemeralPublicKey: Data = ephemeralPublicKeyX963 ?? envelope.ephemeralPublicKeyX963
        let resolvedSalt: Data = hkdfSalt ?? envelope.hkdfSalt
        let resolvedNonce: Data = nonce ?? envelope.nonce
        let resolvedCiphertext: Data = ciphertext ?? envelope.ciphertext
        let resolvedTag: Data = tag ?? envelope.tag

        return PrivateKeyEnvelope(
            magic: resolvedMagic,
            payloadKind: resolvedPayloadKind,
            fingerprint: resolvedFingerprint,
            seKeyData: resolvedSEKeyData,
            seKeyPublicKeyX963: resolvedSEKeyPublicKey,
            ephemeralPublicKeyX963: resolvedEphemeralPublicKey,
            hkdfSalt: resolvedSalt,
            nonce: resolvedNonce,
            ciphertext: resolvedCiphertext,
            tag: resolvedTag
        )
    }
}
