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
        let bundle = try secureEnclave.wrap(privateKey: privateKey, using: handle, fingerprint: fingerprint)

        let decoded = try PrivateKeyEnvelopeCodec.decode(bundle.envelope, expectedFingerprint: fingerprint)
        XCTAssertEqual(decoded.magic, PrivateKeyEnvelope.magic)
        XCTAssertEqual(decoded.formatVersion, PrivateKeyEnvelope.currentFormatVersion)
        XCTAssertEqual(decoded.aadVersion, PrivateKeyEnvelope.currentAADVersion)
        XCTAssertEqual(decoded.algorithmID, PrivateKeyEnvelope.algorithmID)
        XCTAssertEqual(decoded.fingerprint, fingerprint)
        XCTAssertEqual(decoded.seKeyData, handle.dataRepresentation)
        XCTAssertEqual(decoded.hkdfSalt.count, PrivateKeyEnvelope.expectedSaltLength)
        XCTAssertEqual(decoded.nonce.count, PrivateKeyEnvelope.expectedNonceLength)
        XCTAssertEqual(decoded.tag.count, PrivateKeyEnvelope.expectedAuthenticationTagLength)
        XCTAssertEqual(decoded.seKeyPublicKeyX963.count, PrivateKeyEnvelope.expectedP256X963Length)
        XCTAssertEqual(decoded.ephemeralPublicKeyX963.count, PrivateKeyEnvelope.expectedP256X963Length)
        XCTAssertEqual(decoded.ciphertext.count, privateKey.count)

        let unwrapped = try secureEnclave.unwrap(bundle: bundle, using: handle, fingerprint: fingerprint)
        XCTAssertEqual(unwrapped, privateKey)
    }

    func test_envelope_freshSealUsesDistinctEphemeralKeyAndNonce() throws {
        let privateKey = Data(repeating: 0x11, count: 32)
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)

        let first = try PrivateKeyEnvelopeCodec.decode(
            try secureEnclave.wrap(privateKey: privateKey, using: handle, fingerprint: fingerprint).envelope,
            expectedFingerprint: fingerprint
        )
        let second = try PrivateKeyEnvelopeCodec.decode(
            try secureEnclave.wrap(privateKey: privateKey, using: handle, fingerprint: fingerprint).envelope,
            expectedFingerprint: fingerprint
        )

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
        let bundle = try secureEnclave.wrap(privateKey: largePrivateKey, using: handle, fingerprint: fingerprint)

        let decoded = try PrivateKeyEnvelopeCodec.decode(bundle.envelope, expectedFingerprint: fingerprint)
        XCTAssertEqual(decoded.ciphertext.count, largePrivateKey.count)

        let unwrapped = try secureEnclave.unwrap(bundle: bundle, using: handle, fingerprint: fingerprint)
        XCTAssertEqual(unwrapped, largePrivateKey)
    }

    // MARK: - Tamper / wrong-binding

    func test_envelope_rejectsTamperedAuthenticatedFields() throws {
        let privateKey = Data(repeating: 0x24, count: 32)
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let envelope = try PrivateKeyEnvelopeCodec.decode(
            try secureEnclave.wrap(privateKey: privateKey, using: handle, fingerprint: fingerprint).envelope,
            expectedFingerprint: fingerprint
        )

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
            XCTAssertThrowsError(
                try secureEnclave.unwrap(
                    bundle: WrappedKeyBundle(envelope: encoded),
                    using: handle,
                    fingerprint: fingerprint
                ),
                "Tampered authenticated field must fail closed"
            )
        }
    }

    func test_envelope_wrongBoundPublicKey_failsClosedBeforeKeyAgreement() throws {
        let privateKey = Data(repeating: 0x42, count: 32)
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let envelope = try PrivateKeyEnvelopeCodec.decode(
            try secureEnclave.wrap(privateKey: privateKey, using: handle, fingerprint: fingerprint).envelope,
            expectedFingerprint: fingerprint
        )

        // Re-bind the envelope to a different (valid) SE public key, then unwrap with the
        // original handle → the bound-key guard fires before any ECDH.
        let rebound = replacing(envelope, seKeyPublicKeyX963: P256.KeyAgreement.PrivateKey().publicKey.x963Representation)
        XCTAssertThrowsError(
            try secureEnclave.unwrap(
                bundle: WrappedKeyBundle(envelope: try PrivateKeyEnvelopeCodec.encode(rebound)),
                using: handle,
                fingerprint: fingerprint
            )
        ) { error in
            XCTAssertEqual(error as? PrivateKeyEnvelopeError, .deviceBindingMismatch)
        }
    }

    func test_envelope_wrongHandle_failsClosed() throws {
        let privateKey = Data(repeating: 0x53, count: 32)
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let otherHandle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let bundle = try secureEnclave.wrap(privateKey: privateKey, using: handle, fingerprint: fingerprint)

        XCTAssertThrowsError(
            try secureEnclave.unwrap(bundle: bundle, using: otherHandle, fingerprint: fingerprint)
        )
    }

    func test_envelope_wrongFingerprint_failsClosed() throws {
        let privateKey = Data(repeating: 0x64, count: 32)
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let bundle = try secureEnclave.wrap(privateKey: privateKey, using: handle, fingerprint: fingerprint)

        let otherFingerprint = "fedcba9876543210fedcba9876543210fedcba98"
        XCTAssertThrowsError(
            try secureEnclave.unwrap(bundle: bundle, using: handle, fingerprint: otherFingerprint)
        )
        XCTAssertThrowsError(
            try PrivateKeyEnvelopeCodec.decode(bundle.envelope, expectedFingerprint: otherFingerprint)
        )
    }

    // MARK: - Contract rejection

    func test_envelope_rejectsMalformedContractAndUnsupportedFields() throws {
        let privateKey = Data(repeating: 0x35, count: 32)
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let envelope = try PrivateKeyEnvelopeCodec.decode(
            try secureEnclave.wrap(privateKey: privateKey, using: handle, fingerprint: fingerprint).envelope,
            expectedFingerprint: fingerprint
        )

        XCTAssertThrowsError(try PrivateKeyEnvelopeCodec.encode(replacing(envelope, magic: "CAPKEX5")))
        XCTAssertThrowsError(try PrivateKeyEnvelopeCodec.encode(replacing(envelope, formatVersion: 0)))
        XCTAssertThrowsError(try PrivateKeyEnvelopeCodec.encode(replacing(envelope, algorithmID: "other")))
        XCTAssertThrowsError(try PrivateKeyEnvelopeCodec.encode(replacing(envelope, aadVersion: 2)))
        XCTAssertThrowsError(try PrivateKeyEnvelopeCodec.encode(replacing(envelope, fingerprint: "NOTHEX!!")))
        XCTAssertThrowsError(try PrivateKeyEnvelopeCodec.encode(replacing(envelope, seKeyData: Data())))
        XCTAssertThrowsError(try PrivateKeyEnvelopeCodec.encode(replacing(envelope, hkdfSalt: Data(repeating: 0, count: 31))))
        XCTAssertThrowsError(try PrivateKeyEnvelopeCodec.encode(replacing(envelope, nonce: Data(repeating: 0, count: 11))))
        XCTAssertThrowsError(try PrivateKeyEnvelopeCodec.encode(replacing(envelope, tag: Data(repeating: 0, count: 15))))
        XCTAssertThrowsError(try PrivateKeyEnvelopeCodec.encode(replacing(envelope, ciphertext: Data())))
        XCTAssertThrowsError(
            try PrivateKeyEnvelopeCodec.decode(
                try encodedEnvelopeWithUnsupportedField(from: envelope),
                expectedFingerprint: fingerprint
            )
        )
    }

    func test_envelope_undecodableBlob_failsClosed() throws {
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil, authenticationContext: nil)
        let garbage = WrappedKeyBundle(envelope: Data("not-a-private-key-envelope".utf8))

        XCTAssertThrowsError(try PrivateKeyEnvelopeCodec.decode(garbage.envelope, expectedFingerprint: fingerprint))
        XCTAssertThrowsError(try secureEnclave.unwrap(bundle: garbage, using: handle, fingerprint: fingerprint))
    }

    // MARK: - Helpers

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

    private func replacing(
        _ envelope: PrivateKeyEnvelope,
        magic: String? = nil,
        formatVersion: Int? = nil,
        algorithmID: String? = nil,
        aadVersion: Int? = nil,
        fingerprint: String? = nil,
        seKeyData: Data? = nil,
        seKeyPublicKeyX963: Data? = nil,
        ephemeralPublicKeyX963: Data? = nil,
        hkdfSalt: Data? = nil,
        nonce: Data? = nil,
        ciphertext: Data? = nil,
        tag: Data? = nil
    ) -> PrivateKeyEnvelope {
        PrivateKeyEnvelope(
            magic: magic ?? envelope.magic,
            formatVersion: formatVersion ?? envelope.formatVersion,
            algorithmID: algorithmID ?? envelope.algorithmID,
            aadVersion: aadVersion ?? envelope.aadVersion,
            fingerprint: fingerprint ?? envelope.fingerprint,
            seKeyData: seKeyData ?? envelope.seKeyData,
            seKeyPublicKeyX963: seKeyPublicKeyX963 ?? envelope.seKeyPublicKeyX963,
            ephemeralPublicKeyX963: ephemeralPublicKeyX963 ?? envelope.ephemeralPublicKeyX963,
            hkdfSalt: hkdfSalt ?? envelope.hkdfSalt,
            nonce: nonce ?? envelope.nonce,
            ciphertext: ciphertext ?? envelope.ciphertext,
            tag: tag ?? envelope.tag
        )
    }
}
