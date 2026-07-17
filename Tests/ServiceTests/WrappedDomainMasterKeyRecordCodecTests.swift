import Foundation
import XCTest
@testable import CypherAir

final class WrappedDomainMasterKeyRecordCodecTests: XCTestCase {
    private let domainID: ProtectedDataDomainID = "contacts"
    private let wrappingKey = Data(repeating: 0x5A, count: 32)

    func test_sealThenOpen_roundTripsAndCarriesEnvelopeHeader() throws {
        let domainMasterKey = Data(repeating: 0x42, count: 32)
        let record = try WrappedDomainMasterKeyRecordCodec.seal(
            domainMasterKey: domainMasterKey,
            domainID: domainID,
            domainWrappingKey: wrappingKey
        )

        XCTAssertEqual(record.magic, WrappedDomainMasterKeyRecord.magic)
        XCTAssertEqual(record.magic, "CADMKV5")
        XCTAssertEqual(record.formatVersion, WrappedDomainMasterKeyRecord.currentFormatVersion)
        XCTAssertEqual(record.formatVersion, 2)
        XCTAssertEqual(record.algorithmID, WrappedDomainMasterKeyRecord.algorithmID)
        XCTAssertEqual(record.aadVersion, WrappedDomainMasterKeyRecord.currentAADVersion)
        XCTAssertEqual(record.nonce.count, WrappedDomainMasterKeyRecord.expectedNonceLength)
        XCTAssertEqual(record.ciphertext.count, WrappedDomainMasterKeyRecord.expectedDomainMasterKeyLength)
        XCTAssertEqual(record.tag.count, WrappedDomainMasterKeyRecord.expectedAuthenticationTagLength)

        var opened = try WrappedDomainMasterKeyRecordCodec.open(record: record, domainWrappingKey: wrappingKey)
        defer { opened.protectedDataZeroize() }
        XCTAssertEqual(opened, domainMasterKey)
    }

    func test_encodeThenDecode_roundTrips() throws {
        let domainMasterKey = Data(repeating: 0x11, count: 32)
        let record = try WrappedDomainMasterKeyRecordCodec.seal(
            domainMasterKey: domainMasterKey,
            domainID: domainID,
            domainWrappingKey: wrappingKey
        )

        let encoded = try WrappedDomainMasterKeyRecordCodec.encode(record)
        let decoded = try WrappedDomainMasterKeyRecordCodec.decode(encoded)

        XCTAssertEqual(decoded, record)
        var opened = try WrappedDomainMasterKeyRecordCodec.open(record: decoded, domainWrappingKey: wrappingKey)
        defer { opened.protectedDataZeroize() }
        XCTAssertEqual(opened, domainMasterKey)
    }

    func test_freshSealsUseDistinctNonces() throws {
        let domainMasterKey = Data(repeating: 0x42, count: 32)
        let first = try WrappedDomainMasterKeyRecordCodec.seal(
            domainMasterKey: domainMasterKey,
            domainID: domainID,
            domainWrappingKey: wrappingKey
        )
        let second = try WrappedDomainMasterKeyRecordCodec.seal(
            domainMasterKey: domainMasterKey,
            domainID: domainID,
            domainWrappingKey: wrappingKey
        )
        XCTAssertNotEqual(first.nonce, second.nonce)
        XCTAssertNotEqual(first.ciphertext, second.ciphertext)
    }

    func test_open_rejectsWrongWrappingKey() throws {
        let record = try WrappedDomainMasterKeyRecordCodec.seal(
            domainMasterKey: Data(repeating: 0x22, count: 32),
            domainID: domainID,
            domainWrappingKey: wrappingKey
        )
        let wrongKey = Data(repeating: 0x23, count: 32)
        XCTAssertThrowsError(try WrappedDomainMasterKeyRecordCodec.open(record: record, domainWrappingKey: wrongKey))
    }

    func test_open_rejectsTamperedCiphertextAndCrossDomainAAD() throws {
        let record = try WrappedDomainMasterKeyRecordCodec.seal(
            domainMasterKey: Data(repeating: 0x33, count: 32),
            domainID: domainID,
            domainWrappingKey: wrappingKey
        )

        XCTAssertThrowsError(
            try WrappedDomainMasterKeyRecordCodec.open(
                record: replacing(record, ciphertext: flippedFirstByte(record.ciphertext)),
                domainWrappingKey: wrappingKey
            )
        )
        XCTAssertThrowsError(
            try WrappedDomainMasterKeyRecordCodec.open(
                record: replacing(record, tag: flippedFirstByte(record.tag)),
                domainWrappingKey: wrappingKey
            )
        )
        // The domainID is authenticated in the AAD, so a record moved to another
        // domain fails closed even though its ciphertext/tag are otherwise intact.
        XCTAssertThrowsError(
            try WrappedDomainMasterKeyRecordCodec.open(
                record: replacing(record, domainID: "settings"),
                domainWrappingKey: wrappingKey
            )
        )
    }

    func test_encode_rejectsMalformedContract() throws {
        let record = try WrappedDomainMasterKeyRecordCodec.seal(
            domainMasterKey: Data(repeating: 0x44, count: 32),
            domainID: domainID,
            domainWrappingKey: wrappingKey
        )

        XCTAssertThrowsError(try WrappedDomainMasterKeyRecordCodec.encode(replacing(record, magic: "CADMKX5")))
        XCTAssertThrowsError(try WrappedDomainMasterKeyRecordCodec.encode(replacing(record, formatVersion: 1)))
        XCTAssertThrowsError(try WrappedDomainMasterKeyRecordCodec.encode(replacing(record, algorithmID: "other")))
        XCTAssertThrowsError(try WrappedDomainMasterKeyRecordCodec.encode(replacing(record, aadVersion: 1)))
        XCTAssertThrowsError(try WrappedDomainMasterKeyRecordCodec.encode(replacing(record, nonce: Data(repeating: 0x00, count: 11))))
        XCTAssertThrowsError(try WrappedDomainMasterKeyRecordCodec.encode(replacing(record, ciphertext: Data(repeating: 0x00, count: 31))))
        XCTAssertThrowsError(try WrappedDomainMasterKeyRecordCodec.encode(replacing(record, tag: Data(repeating: 0x00, count: 15))))
    }

    func test_decode_rejectsUnsupportedField() throws {
        let record = try WrappedDomainMasterKeyRecordCodec.seal(
            domainMasterKey: Data(repeating: 0x55, count: 32),
            domainID: domainID,
            domainWrappingKey: wrappingKey
        )
        let encoded = try WrappedDomainMasterKeyRecordCodec.encode(record)

        var format = PropertyListSerialization.PropertyListFormat.binary
        var dictionary = try XCTUnwrap(
            PropertyListSerialization.propertyList(from: encoded, options: [], format: &format) as? [String: Any]
        )
        dictionary["unexpected"] = "value"
        let tampered = try PropertyListSerialization.data(fromPropertyList: dictionary, format: .binary, options: 0)

        XCTAssertThrowsError(try WrappedDomainMasterKeyRecordCodec.decode(tampered))
    }

    func test_decode_rejectsUndecodablePayload() {
        XCTAssertThrowsError(try WrappedDomainMasterKeyRecordCodec.decode(Data("not a wrapped dmk record".utf8)))
    }

    // MARK: - Helpers

    private func replacing(
        _ record: WrappedDomainMasterKeyRecord,
        magic: String? = nil,
        formatVersion: Int? = nil,
        algorithmID: String? = nil,
        aadVersion: Int? = nil,
        domainID: ProtectedDataDomainID? = nil,
        nonce: Data? = nil,
        ciphertext: Data? = nil,
        tag: Data? = nil
    ) -> WrappedDomainMasterKeyRecord {
        WrappedDomainMasterKeyRecord(
            magic: magic ?? record.magic,
            formatVersion: formatVersion ?? record.formatVersion,
            algorithmID: algorithmID ?? record.algorithmID,
            aadVersion: aadVersion ?? record.aadVersion,
            domainID: domainID ?? record.domainID,
            nonce: nonce ?? record.nonce,
            ciphertext: ciphertext ?? record.ciphertext,
            tag: tag ?? record.tag
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
