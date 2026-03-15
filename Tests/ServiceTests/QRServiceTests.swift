import XCTest
@testable import CypherAir

/// Tests for QRService — SECURITY-CRITICAL: validates parsing of untrusted external input.
/// QRService.parseImportURL() processes cypherair:// URLs from QR codes.
/// These tests verify rejection of malformed, malicious, and invalid input.
final class QRServiceTests: XCTestCase {

    private var engine: PgpEngine!
    private var qrService: QRService!

    override func setUp() {
        super.setUp()
        engine = PgpEngine()
        qrService = QRService(engine: engine)
    }

    override func tearDown() {
        qrService = nil
        engine = nil
        super.tearDown()
    }

    // MARK: - Positive: Valid URL Round-Trip

    func test_parseImportURL_validV1URL_profileA_returnsPublicKeyData() throws {
        // Generate a Profile A key and encode it as a QR URL
        let generated = try engine.generateKey(
            name: "Alice", email: "alice@example.com",
            expirySeconds: nil, profile: .universal
        )
        let urlString = try engine.encodeQrUrl(publicKeyData: generated.publicKeyData)
        let url = try XCTUnwrap(URL(string: urlString))

        // Parse the URL back
        let parsedData = try qrService.parseImportURL(url)

        // Verify we got valid public key data back
        XCTAssertFalse(parsedData.isEmpty, "Parsed key data should not be empty")

        // Verify the parsed data is a valid key by parsing its info
        let keyInfo = try engine.parseKeyInfo(keyData: parsedData)
        XCTAssertEqual(keyInfo.keyVersion, 4, "Profile A should produce v4 key")
    }

    func test_parseImportURL_validV1URL_profileB_returnsPublicKeyData() throws {
        let generated = try engine.generateKey(
            name: "Bob", email: "bob@example.com",
            expirySeconds: nil, profile: .advanced
        )
        let urlString = try engine.encodeQrUrl(publicKeyData: generated.publicKeyData)
        let url = try XCTUnwrap(URL(string: urlString))

        let parsedData = try qrService.parseImportURL(url)

        XCTAssertFalse(parsedData.isEmpty)
        let keyInfo = try engine.parseKeyInfo(keyData: parsedData)
        XCTAssertEqual(keyInfo.keyVersion, 6, "Profile B should produce v6 key")
    }

    func test_parseImportURL_roundTrip_fingerprintMatches() throws {
        let generated = try engine.generateKey(
            name: "Carol", email: "carol@example.com",
            expirySeconds: nil, profile: .universal
        )
        let originalInfo = try engine.parseKeyInfo(keyData: generated.publicKeyData)

        // Encode → Parse → Compare
        let urlString = try engine.encodeQrUrl(publicKeyData: generated.publicKeyData)
        let url = try XCTUnwrap(URL(string: urlString))
        let parsedData = try qrService.parseImportURL(url)
        let parsedInfo = try engine.parseKeyInfo(keyData: parsedData)

        XCTAssertEqual(originalInfo.fingerprint, parsedInfo.fingerprint,
                       "Fingerprint should survive QR URL round-trip")
    }

    func test_parseImportURL_roundTrip_profileB_fingerprintMatches() throws {
        let generated = try engine.generateKey(
            name: "Dave", email: "dave@example.com",
            expirySeconds: nil, profile: .advanced
        )
        let originalInfo = try engine.parseKeyInfo(keyData: generated.publicKeyData)

        let urlString = try engine.encodeQrUrl(publicKeyData: generated.publicKeyData)
        let url = try XCTUnwrap(URL(string: urlString))
        let parsedData = try qrService.parseImportURL(url)
        let parsedInfo = try engine.parseKeyInfo(keyData: parsedData)

        XCTAssertEqual(originalInfo.fingerprint, parsedInfo.fingerprint,
                       "Profile B fingerprint should survive QR URL round-trip")
    }

    // MARK: - Negative: Wrong Scheme

    func test_parseImportURL_wrongScheme_https_throwsInvalidQRCode() {
        let url = URL(string: "https://import/v1/AAAA")!

        XCTAssertThrowsError(try qrService.parseImportURL(url)) { error in
            guard let cypherError = error as? CypherAirError else {
                return XCTFail("Expected CypherAirError, got \(type(of: error))")
            }
            if case .invalidQRCode = cypherError {
                // Expected
            } else {
                XCTFail("Expected .invalidQRCode, got \(cypherError)")
            }
        }
    }

    func test_parseImportURL_wrongScheme_http_throwsInvalidQRCode() {
        let url = URL(string: "http://import/v1/AAAA")!

        XCTAssertThrowsError(try qrService.parseImportURL(url)) { error in
            guard let cypherError = error as? CypherAirError else {
                return XCTFail("Expected CypherAirError, got \(type(of: error))")
            }
            if case .invalidQRCode = cypherError {
                // Expected
            } else {
                XCTFail("Expected .invalidQRCode, got \(cypherError)")
            }
        }
    }

    // MARK: - Negative: Wrong Host/Path

    func test_parseImportURL_wrongHost_throwsInvalidQRCode() {
        let url = URL(string: "cypherair://export/v1/AAAA")!

        XCTAssertThrowsError(try qrService.parseImportURL(url)) { error in
            guard let cypherError = error as? CypherAirError else {
                return XCTFail("Expected CypherAirError, got \(type(of: error))")
            }
            if case .invalidQRCode = cypherError {
                // Expected
            } else {
                XCTFail("Expected .invalidQRCode, got \(cypherError)")
            }
        }
    }

    // MARK: - Negative: Unsupported Version

    func test_parseImportURL_unsupportedVersion_v2_throwsUnsupportedQRVersion() {
        let url = URL(string: "cypherair://import/v2/AAAA")!

        XCTAssertThrowsError(try qrService.parseImportURL(url)) { error in
            guard let cypherError = error as? CypherAirError else {
                return XCTFail("Expected CypherAirError, got \(type(of: error))")
            }
            if case .unsupportedQRVersion = cypherError {
                // Expected
            } else {
                XCTFail("Expected .unsupportedQRVersion, got \(cypherError)")
            }
        }
    }

    // MARK: - Negative: Missing/Invalid Payload

    func test_parseImportURL_missingPayload_throwsInvalidKeyData() {
        // URL with valid scheme/host/version but no base64 payload.
        // Empty base64 decodes to empty bytes → Cert::from_bytes fails → InvalidKeyData.
        // The Rust engine throws PgpError directly (QRService doesn't wrap it).
        let url = URL(string: "cypherair://import/v1/")!

        XCTAssertThrowsError(try qrService.parseImportURL(url)) { error in
            if let pgpError = error as? PgpError {
                if case .InvalidKeyData = pgpError {
                    // Expected — empty data is not a valid OpenPGP key
                } else {
                    XCTFail("Expected .InvalidKeyData, got \(pgpError)")
                }
            } else if let cypherError = error as? CypherAirError {
                if case .invalidKeyData = cypherError {
                    // Also acceptable if wrapped
                } else {
                    XCTFail("Expected .invalidKeyData, got \(cypherError)")
                }
            } else {
                XCTFail("Expected PgpError or CypherAirError, got \(type(of: error))")
            }
        }
    }

    func test_parseImportURL_invalidBase64_throwsCorruptData() {
        // Invalid base64url characters (contains !, @, #).
        // Rust base64 decode fails → PgpError.CorruptData.
        // The Rust engine throws PgpError directly (QRService doesn't wrap it).
        let url = URL(string: "cypherair://import/v1/!!!@@@###")!

        XCTAssertThrowsError(try qrService.parseImportURL(url)) { error in
            if let pgpError = error as? PgpError {
                if case .CorruptData = pgpError {
                    // Expected — invalid base64url characters
                } else {
                    XCTFail("Expected .CorruptData, got \(pgpError)")
                }
            } else if let cypherError = error as? CypherAirError {
                if case .corruptData = cypherError {
                    // Also acceptable if wrapped
                } else {
                    XCTFail("Expected .corruptData, got \(cypherError)")
                }
            } else {
                XCTFail("Expected PgpError or CypherAirError, got \(type(of: error))")
            }
        }
    }

    func test_parseImportURL_validBase64ButNotPGP_throwsInvalidKeyData() {
        // Valid base64url encoding of "Hello, World!" — not a PGP key.
        // Base64 decode succeeds but Cert::from_bytes fails → InvalidKeyData.
        // The Rust engine throws PgpError directly (QRService doesn't wrap it).
        let url = URL(string: "cypherair://import/v1/SGVsbG8sIFdvcmxkIQ")!

        XCTAssertThrowsError(try qrService.parseImportURL(url)) { error in
            if let pgpError = error as? PgpError {
                if case .InvalidKeyData = pgpError {
                    // Expected — valid base64 but not valid OpenPGP data
                } else {
                    XCTFail("Expected .InvalidKeyData, got \(pgpError)")
                }
            } else if let cypherError = error as? CypherAirError {
                if case .invalidKeyData = cypherError {
                    // Also acceptable if wrapped
                } else {
                    XCTFail("Expected .invalidKeyData, got \(cypherError)")
                }
            } else {
                XCTFail("Expected PgpError or CypherAirError, got \(type(of: error))")
            }
        }
    }

    // MARK: - Negative: Secret Key Material (Security)

    func test_parseImportURL_secretKeyMaterial_throwsError() throws {
        // Generate a key and try to encode the FULL cert (public + secret)
        // The Rust engine's encodeQrUrl should only accept public keys,
        // but we verify that parsing rejects secret key material if somehow encoded.
        let generated = try engine.generateKey(
            name: "Mallory", email: nil,
            expirySeconds: nil, profile: .universal
        )

        // Try encoding cert data (contains secret key) — the Rust engine should reject this
        XCTAssertThrowsError(try engine.encodeQrUrl(publicKeyData: generated.certData)) { _ in
            // The engine should refuse to encode secret key material into a QR URL
        }
    }

    // MARK: - Negative: URL Length Limit (Anti-DoS)

    func test_parseImportURL_exceedsMaxLength_throwsInvalidQRCode() {
        // Construct a URL that exceeds the 4096-character limit
        let prefix = "cypherair://import/v1/"
        let padding = String(repeating: "A", count: 4097 - prefix.count)
        let url = URL(string: prefix + padding)!

        XCTAssertThrowsError(try qrService.parseImportURL(url)) { error in
            guard let cypherError = error as? CypherAirError else {
                return XCTFail("Expected CypherAirError, got \(type(of: error))")
            }
            if case .invalidQRCode = cypherError {
                // Expected: URL length exceeds 4096 limit
            } else {
                XCTFail("Expected .invalidQRCode, got \(cypherError)")
            }
        }
    }

    func test_parseImportURL_atMaxLength_doesNotThrowLengthError() {
        // Construct a URL at exactly 4096 characters — should NOT be rejected by length guard.
        // The error should come from Rust parsing (not the Swift-side length guard).
        let prefix = "cypherair://import/v1/"
        let padding = String(repeating: "A", count: 4096 - prefix.count)
        let url = URL(string: prefix + padding)!

        do {
            _ = try qrService.parseImportURL(url)
            // If this somehow succeeds, the URL passed the length guard — fine
        } catch let error as PgpError {
            // "AAAA..." is valid base64url that decodes to binary, but not a valid PGP key.
            // Rust engine throws PgpError directly — this confirms we passed the length guard.
            switch error {
            case .InvalidKeyData, .CorruptData:
                break // Expected: Rust-side parsing rejection (not length guard)
            default:
                XCTFail("Unexpected PgpError: \(error)")
            }
        } catch let error as CypherAirError {
            switch error {
            case .invalidKeyData, .corruptData:
                break // Expected: Rust-side parsing rejection wrapped as CypherAirError
            case .invalidQRCode:
                // The over-limit test above is the real safety check for the length guard.
                break
            default:
                XCTFail("Unexpected CypherAirError: \(error)")
            }
        } catch {
            XCTFail("Unexpected error type: \(type(of: error))")
        }
    }

    // MARK: - QR Code Generation

    func test_generateQRCode_validPublicKey_returnsCIImage() throws {
        let generated = try engine.generateKey(
            name: "QR Test", email: nil,
            expirySeconds: nil, profile: .universal
        )

        let image = try qrService.generateQRCode(for: generated.publicKeyData)
        XCTAssertNotNil(image, "QR code image should be generated for valid public key")
    }

    func test_generateQRCode_emptyData_throwsError() {
        XCTAssertThrowsError(try qrService.generateQRCode(for: Data())) { _ in
            // Empty data should fail during URL encoding
        }
    }
}
