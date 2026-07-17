import Foundation
import XCTest
@testable import CypherAir

final class ProtectedDomainEnvelopeCodecTests: XCTestCase {
    private let domainID: ProtectedDataDomainID = "contacts"
    private let domainMasterKey = Data(repeating: 0x5A, count: 32)
    private let plaintext = Data("protected-domain-payload".utf8)

    func test_sealThenOpen_roundTripsAndCarriesEnvelopeHeader() throws {
        let envelope = try seal(schemaVersion: 2, generationIdentifier: 7)

        XCTAssertEqual(envelope.magic, ProtectedDomainEnvelope.magic)
        XCTAssertEqual(envelope.magic, "CPDENV5")
        XCTAssertEqual(envelope.formatVersion, ProtectedDomainEnvelope.currentFormatVersion)
        XCTAssertEqual(envelope.formatVersion, 2)
        XCTAssertEqual(envelope.algorithmID, ProtectedDomainEnvelope.algorithmID)
        XCTAssertEqual(envelope.aadVersion, ProtectedDomainEnvelope.currentAADVersion)
        XCTAssertEqual(envelope.schemaVersion, 2)
        XCTAssertEqual(envelope.generationIdentifier, 7)
        XCTAssertEqual(envelope.nonce.count, ProtectedDomainEnvelope.expectedNonceLength)
        XCTAssertEqual(envelope.tag.count, ProtectedDomainEnvelope.expectedAuthenticationTagLength)

        var opened = try ProtectedDomainEnvelopeCodec.open(envelope: envelope, domainMasterKey: domainMasterKey)
        defer { opened.protectedDataZeroize() }
        XCTAssertEqual(opened, plaintext)
    }

    func test_encodeThenDecode_roundTrips() throws {
        let envelope = try seal(schemaVersion: 1, generationIdentifier: 1)
        let encoded = try ProtectedDomainEnvelopeCodec.encode(envelope)
        let decoded = try ProtectedDomainEnvelopeCodec.decode(encoded)

        XCTAssertEqual(decoded, envelope)
        var opened = try ProtectedDomainEnvelopeCodec.open(envelope: decoded, domainMasterKey: domainMasterKey)
        defer { opened.protectedDataZeroize() }
        XCTAssertEqual(opened, plaintext)
    }

    func test_freshSealsUseDistinctNonces() throws {
        let first = try seal(schemaVersion: 1, generationIdentifier: 1)
        let second = try seal(schemaVersion: 1, generationIdentifier: 1)
        XCTAssertNotEqual(first.nonce, second.nonce)
        XCTAssertNotEqual(first.ciphertext, second.ciphertext)
    }

    func test_open_rejectsWrongDomainMasterKey() throws {
        let envelope = try seal(schemaVersion: 1, generationIdentifier: 1)
        let wrongKey = Data(repeating: 0x5B, count: 32)
        XCTAssertThrowsError(try ProtectedDomainEnvelopeCodec.open(envelope: envelope, domainMasterKey: wrongKey))
    }

    func test_open_rejectsTamperedCiphertextAndReboundIdentity() throws {
        let envelope = try seal(schemaVersion: 3, generationIdentifier: 9)

        XCTAssertThrowsError(
            try ProtectedDomainEnvelopeCodec.open(
                envelope: replacing(envelope, ciphertext: flippedFirstByte(envelope.ciphertext)),
                domainMasterKey: domainMasterKey
            )
        )
        XCTAssertThrowsError(
            try ProtectedDomainEnvelopeCodec.open(
                envelope: replacing(envelope, tag: flippedFirstByte(envelope.tag)),
                domainMasterKey: domainMasterKey
            )
        )
        // domainID / schemaVersion / generationIdentifier are authenticated in the AAD,
        // so re-labelling an otherwise-intact envelope fails closed.
        XCTAssertThrowsError(
            try ProtectedDomainEnvelopeCodec.open(
                envelope: replacing(envelope, domainID: "settings"),
                domainMasterKey: domainMasterKey
            )
        )
        XCTAssertThrowsError(
            try ProtectedDomainEnvelopeCodec.open(
                envelope: replacing(envelope, schemaVersion: 4),
                domainMasterKey: domainMasterKey
            )
        )
        XCTAssertThrowsError(
            try ProtectedDomainEnvelopeCodec.open(
                envelope: replacing(envelope, generationIdentifier: 10),
                domainMasterKey: domainMasterKey
            )
        )
    }

    func test_encode_rejectsMalformedContract() throws {
        let envelope = try seal(schemaVersion: 1, generationIdentifier: 1)

        XCTAssertThrowsError(try ProtectedDomainEnvelopeCodec.encode(replacing(envelope, magic: "CPDENX5")))
        XCTAssertThrowsError(try ProtectedDomainEnvelopeCodec.encode(replacing(envelope, formatVersion: 1)))
        XCTAssertThrowsError(try ProtectedDomainEnvelopeCodec.encode(replacing(envelope, algorithmID: "other")))
        XCTAssertThrowsError(try ProtectedDomainEnvelopeCodec.encode(replacing(envelope, aadVersion: 1)))
        XCTAssertThrowsError(try ProtectedDomainEnvelopeCodec.encode(replacing(envelope, schemaVersion: 0)))
        XCTAssertThrowsError(try ProtectedDomainEnvelopeCodec.encode(replacing(envelope, generationIdentifier: 0)))
        XCTAssertThrowsError(try ProtectedDomainEnvelopeCodec.encode(replacing(envelope, nonce: Data(repeating: 0x00, count: 11))))
        XCTAssertThrowsError(try ProtectedDomainEnvelopeCodec.encode(replacing(envelope, tag: Data(repeating: 0x00, count: 15))))
        XCTAssertThrowsError(try ProtectedDomainEnvelopeCodec.encode(replacing(envelope, ciphertext: Data())))
    }

    func test_decode_rejectsUnsupportedField() throws {
        let envelope = try seal(schemaVersion: 1, generationIdentifier: 1)
        let encoded = try ProtectedDomainEnvelopeCodec.encode(envelope)

        var format = PropertyListSerialization.PropertyListFormat.binary
        var dictionary = try XCTUnwrap(
            PropertyListSerialization.propertyList(from: encoded, options: [], format: &format) as? [String: Any]
        )
        dictionary["unexpected"] = "value"
        let tampered = try PropertyListSerialization.data(fromPropertyList: dictionary, format: .binary, options: 0)

        XCTAssertThrowsError(try ProtectedDomainEnvelopeCodec.decode(tampered))
    }

    func test_decode_rejectsUndecodablePayload() {
        XCTAssertThrowsError(try ProtectedDomainEnvelopeCodec.decode(Data("not a protected-domain envelope".utf8)))
    }

    // MARK: - Helpers

    private func seal(schemaVersion: Int, generationIdentifier: Int) throws -> ProtectedDomainEnvelope {
        try ProtectedDomainEnvelopeCodec.seal(
            plaintext: plaintext,
            domainID: domainID,
            schemaVersion: schemaVersion,
            generationIdentifier: generationIdentifier,
            domainMasterKey: domainMasterKey
        )
    }

    private func replacing(
        _ envelope: ProtectedDomainEnvelope,
        magic: String? = nil,
        formatVersion: Int? = nil,
        algorithmID: String? = nil,
        aadVersion: Int? = nil,
        domainID: ProtectedDataDomainID? = nil,
        schemaVersion: Int? = nil,
        generationIdentifier: Int? = nil,
        nonce: Data? = nil,
        ciphertext: Data? = nil,
        tag: Data? = nil
    ) -> ProtectedDomainEnvelope {
        ProtectedDomainEnvelope(
            magic: magic ?? envelope.magic,
            formatVersion: formatVersion ?? envelope.formatVersion,
            algorithmID: algorithmID ?? envelope.algorithmID,
            aadVersion: aadVersion ?? envelope.aadVersion,
            domainID: domainID ?? envelope.domainID,
            schemaVersion: schemaVersion ?? envelope.schemaVersion,
            generationIdentifier: generationIdentifier ?? envelope.generationIdentifier,
            nonce: nonce ?? envelope.nonce,
            ciphertext: ciphertext ?? envelope.ciphertext,
            tag: tag ?? envelope.tag
        )
    }

    private func flippedFirstByte(_ data: Data) -> Data {
        var copy = data
        if let first = copy.indices.first {
            copy[first] ^= 0xFF
        }
        return copy
    }
}
