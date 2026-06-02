import XCTest
@testable import CypherAir

extension FFIIntegrationTests {
    func test_generateKeyRevocation_roundTrip_validatesAgainstSourceCert() throws {
        let key = try engine.generateKey(
            name: "Generated Revocation",
            email: nil,
            expirySeconds: nil,
            profile: .advanced
        )

        let generatedRevocation = try engine.generateKeyRevocation(secretCert: key.certData)
        let validation = try engine.parseRevocationCert(
            revData: generatedRevocation,
            certData: key.publicKeyData
        )

        XCTAssertTrue(validation.lowercased().contains(key.fingerprint.lowercased()))
    }

    func test_generateSubkeyRevocation_fixtureBinaryInput_returnsSignatureBytes() throws {
        let secretCert = try loadArmoredFixtureAsBinary("gpg_secretkey")
        let subkeyFingerprint = "6f579248c0931ba1480f2cf967ddeea6ef08b374"

        let revocation = try engine.generateSubkeyRevocation(
            secretCert: secretCert,
            subkeyFingerprint: subkeyFingerprint
        )

        XCTAssertFalse(revocation.isEmpty)
    }

    func test_generateSubkeyRevocation_fixtureUppercaseFingerprint_returnsSignatureBytes() throws {
        let secretCert = try loadArmoredFixtureAsBinary("gpg_secretkey")
        let subkeyFingerprint = "6F579248C0931BA1480F2CF967DDEEA6EF08B374"

        let revocation = try engine.generateSubkeyRevocation(
            secretCert: secretCert,
            subkeyFingerprint: subkeyFingerprint
        )

        XCTAssertFalse(revocation.isEmpty)
    }

    func test_generateUserIdRevocationBySelector_fixtureBinaryInput_returnsSignatureBytes() throws {
        let secretCert = try loadArmoredFixtureAsBinary("gpg_secretkey")

        let revocation = try engine.generateUserIdRevocationBySelector(
            secretCert: secretCert,
            userIdSelector: try userIdSelector(for: secretCert)
        )

        XCTAssertFalse(revocation.isEmpty)
    }

    func test_generateKeyRevocation_publicOnlyInput_throwsInvalidKeyData() throws {
        let publicCert = try loadArmoredFixtureAsBinary("gpg_pubkey")

        XCTAssertThrowsError(
            try engine.generateKeyRevocation(secretCert: publicCert)
        ) { error in
            guard case .InvalidKeyData = error as? PgpError else {
                return XCTFail("Expected InvalidKeyData, got \(error)")
            }
        }
    }

    func test_generateSubkeyRevocation_publicOnlyInput_throwsInvalidKeyData() throws {
        let publicCert = try loadArmoredFixtureAsBinary("gpg_pubkey")

        XCTAssertThrowsError(
            try engine.generateSubkeyRevocation(
                secretCert: publicCert,
                subkeyFingerprint: "6f579248c0931ba1480f2cf967ddeea6ef08b374"
            )
        ) { error in
            guard case .InvalidKeyData = error as? PgpError else {
                return XCTFail("Expected InvalidKeyData, got \(error)")
            }
        }
    }

    func test_generateUserIdRevocationBySelector_publicOnlyInput_throwsInvalidKeyData() throws {
        let publicCert = try loadArmoredFixtureAsBinary("gpg_pubkey")
        let selector = try userIdSelector(for: publicCert)

        XCTAssertThrowsError(
            try engine.generateUserIdRevocationBySelector(
                secretCert: publicCert,
                userIdSelector: selector
            )
        ) { error in
            guard case .InvalidKeyData = error as? PgpError else {
                return XCTFail("Expected InvalidKeyData, got \(error)")
            }
        }
    }

    func test_generateSubkeyRevocation_selectorMiss_throwsInvalidKeyData() throws {
        let secretCert = try loadArmoredFixtureAsBinary("gpg_secretkey")

        XCTAssertThrowsError(
            try engine.generateSubkeyRevocation(
                secretCert: secretCert,
                subkeyFingerprint: "0000000000000000000000000000000000000000"
            )
        ) { error in
            guard case .InvalidKeyData = error as? PgpError else {
                return XCTFail("Expected InvalidKeyData, got \(error)")
            }
        }
    }

    func test_generateUserIdRevocationBySelector_generatedKey_returnsSignatureBytes() throws {
        let generated = try engine.generateKey(
            name: "Selector Revocation",
            email: "selector-revocation@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        let discovered = try engine.discoverCertificateSelectors(certData: generated.certData)

        let revocation = try engine.generateUserIdRevocationBySelector(
            secretCert: generated.certData,
            userIdSelector: selectorInput(
                userIdData: discovered.userIds[0].userIdData,
                occurrenceIndex: discovered.userIds[0].occurrenceIndex
            )
        )

        XCTAssertFalse(revocation.isEmpty)
    }

    func test_generateUserIdRevocationBySelector_occurrenceIndexOutOfRange_throwsInvalidKeyData()
        throws
    {
        let generated = try engine.generateKey(
            name: "Selector Revocation Range",
            email: "selector-revocation-range@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        let discovered = try engine.discoverCertificateSelectors(certData: generated.certData)

        XCTAssertThrowsError(
            try engine.generateUserIdRevocationBySelector(
                secretCert: generated.certData,
                userIdSelector: selectorInput(
                    userIdData: discovered.userIds[0].userIdData,
                    occurrenceIndex: 99
                )
            )
        ) { error in
            guard case .InvalidKeyData = error as? PgpError else {
                return XCTFail("Expected InvalidKeyData, got \(error)")
            }
        }
    }

    func test_generateUserIdRevocationBySelector_bytesMismatch_throwsInvalidKeyData() throws {
        let generated = try engine.generateKey(
            name: "Selector Revocation Mismatch",
            email: "selector-revocation-mismatch@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        let discovered = try engine.discoverCertificateSelectors(certData: generated.certData)
        let mismatchedData = discovered.userIds[0].userIdData + Data("-mismatch".utf8)

        XCTAssertThrowsError(
            try engine.generateUserIdRevocationBySelector(
                secretCert: generated.certData,
                userIdSelector: selectorInput(
                    userIdData: mismatchedData,
                    occurrenceIndex: discovered.userIds[0].occurrenceIndex
                )
            )
        ) { error in
            guard case .InvalidKeyData = error as? PgpError else {
                return XCTFail("Expected InvalidKeyData, got \(error)")
            }
        }
    }
}
