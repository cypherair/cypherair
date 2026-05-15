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
        qrService = QRService(contactImportAdapter: PGPContactImportAdapter(engine: engine))
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

    func test_inspectImportablePublicCertificate_returnsAppOwnedInspection() throws {
        let generated = try engine.generateKey(
            name: "Import Display",
            email: "display@example.com",
            expirySeconds: nil,
            profile: .universal
        )
        let keyInfo = try engine.parseKeyInfo(keyData: generated.publicKeyData)

        let inspection = try qrService.inspectImportablePublicCertificate(
            keyData: generated.publicKeyData
        )

        XCTAssertEqual(inspection.publicCertData, generated.publicKeyData)
        XCTAssertEqual(inspection.metadata.fingerprint, keyInfo.fingerprint)
        XCTAssertEqual(inspection.metadata.userId, keyInfo.userId)
        XCTAssertEqual(inspection.metadata.profile, .universal)
        XCTAssertEqual(inspection.metadata.keyVersion, 4)
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

    func test_parseImportURL_missingPayload_throwsInvalidQRCode() {
        // URL with valid scheme/host/version but no base64 payload.
        // Empty base64 decodes to empty bytes → Cert::from_bytes fails →
        // QRService wraps as CypherAirError.invalidQRCode.
        let url = URL(string: "cypherair://import/v1/")!

        XCTAssertThrowsError(try qrService.parseImportURL(url)) { error in
            guard let cypherError = error as? CypherAirError else {
                return XCTFail("Expected CypherAirError, got \(type(of: error))")
            }
            guard case .invalidQRCode = cypherError else {
                return XCTFail("Expected .invalidQRCode, got \(cypherError)")
            }
        }
    }

    func test_parseImportURL_invalidBase64_throwsInvalidQRCode() {
        // Invalid base64url characters (contains !, @, #).
        // Rust base64 decode fails → QRService wraps as CypherAirError.invalidQRCode.
        let url = URL(string: "cypherair://import/v1/!!!@@@###")!

        XCTAssertThrowsError(try qrService.parseImportURL(url)) { error in
            guard let cypherError = error as? CypherAirError else {
                return XCTFail("Expected CypherAirError, got \(type(of: error))")
            }
            guard case .invalidQRCode = cypherError else {
                return XCTFail("Expected .invalidQRCode, got \(cypherError)")
            }
        }
    }

    func test_parseImportURL_validBase64ButNotPGP_throwsInvalidQRCode() {
        // Valid base64url encoding of "Hello, World!" — not a PGP key.
        // Base64 decode succeeds but Cert::from_bytes fails →
        // QRService wraps as CypherAirError.invalidQRCode.
        let url = URL(string: "cypherair://import/v1/SGVsbG8sIFdvcmxkIQ")!

        XCTAssertThrowsError(try qrService.parseImportURL(url)) { error in
            guard let cypherError = error as? CypherAirError else {
                return XCTFail("Expected CypherAirError, got \(type(of: error))")
            }
            guard case .invalidQRCode = cypherError else {
                return XCTFail("Expected .invalidQRCode, got \(cypherError)")
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

    func test_inspectImportablePublicCertificate_secretKeyMaterial_throwsSpecificContactImportError() throws {
        let generated = try engine.generateKey(
            name: "Import Secret Reject",
            email: nil,
            expirySeconds: nil,
            profile: .universal
        )

        XCTAssertThrowsError(try qrService.inspectImportablePublicCertificate(keyData: generated.certData)) { error in
            guard let cypherError = error as? CypherAirError else {
                return XCTFail("Expected CypherAirError, got \(type(of: error))")
            }
            guard case .contactImportRequiresPublicCertificate = cypherError else {
                return XCTFail("Expected .contactImportRequiresPublicCertificate, got \(cypherError)")
            }
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
        } catch let error as CypherAirError {
            // "AAAA..." is valid base64url that decodes to binary, but not a valid PGP key.
            // Rust engine rejects it → parseImportURL wraps all engine errors as .invalidQRCode.
            // This confirms we passed the Swift-side length guard.
            if case .invalidQRCode = error {
                // Expected: Rust-side parsing rejection wrapped as .invalidQRCode
            } else {
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

    // MARK: - QR Image Round-Trip

    func test_qrCodeRoundTrip_generateThenDecode_recoversPublicKey() async throws {
        let generated = try engine.generateKey(
            name: "QR Round-Trip", email: nil,
            expirySeconds: nil, profile: .universal
        )

        // Generate QR code image
        guard let qrImage = try qrService.generateQRCode(for: generated.publicKeyData) else {
            XCTFail("QR code generation returned nil"); return
        }

        // Scale up for reliable CIDetector detection.
        // CIFilter.qrCodeGenerator() outputs ~1px per module (~25×25 total).
        // CIDetector needs larger images to reliably detect QR codes.
        let scaledImage = qrImage.transformed(by: CGAffineTransform(scaleX: 10, y: 10))

        // Decode QR codes from the image
        let decodedStrings = try await qrService.decodeQRCodes(from: scaledImage)
        XCTAssertFalse(decodedStrings.isEmpty, "Should detect at least one QR code")

        guard let urlString = decodedStrings.first,
              let url = URL(string: urlString) else {
            XCTFail("No QR codes detected or invalid URL"); return
        }

        // Parse the decoded URL to recover the public key
        let recoveredKeyData = try qrService.parseImportURL(url)

        // Verify fingerprint matches
        let originalInfo = try engine.parseKeyInfo(keyData: generated.publicKeyData)
        let recoveredInfo = try engine.parseKeyInfo(keyData: recoveredKeyData)
        XCTAssertEqual(originalInfo.fingerprint, recoveredInfo.fingerprint,
                       "Recovered key fingerprint should match original")
    }
}
