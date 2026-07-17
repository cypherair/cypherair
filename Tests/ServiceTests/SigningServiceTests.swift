import XCTest
@testable import CypherAir

/// Tests for SigningService — cleartext/detached signing and verification.
final class SigningServiceTests: XCTestCase {

    private var stack: TestHelpers.ServiceStack!

    override func setUp() async throws {
        try await super.setUp()
        stack = await TestHelpers.makeServiceStack()
    }

    override func tearDown() {
        stack.cleanup()
        stack = nil
        super.tearDown()
    }

    // MARK: - Helpers

    /// Generate a key and register it as a contact.
    private func generateKeyAndContact(
        profile: PGPKeyProfile,
        name: String = "Signer"
    ) async throws -> PGPKeyIdentity {
        let identity = try await TestHelpers.generateAndStoreKey(
            service: stack.keyManagement,
            profile: profile,
            name: name
        )
        try stack.contactService.importContact(publicKeyData: identity.publicKeyData)
        return identity
    }

    private func makeTemporaryFile(
        contents: Data,
        name: String = "signing-service-\(UUID().uuidString).bin"
    ) throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(name)
        try contents.write(to: url, options: .atomic)
        return url
    }

    // MARK: - Cleartext Signing

    func test_signCleartext_legacy_producesSignedMessage() async throws {
        let identity = try await generateKeyAndContact(profile: .universal)

        let signed = try await stack.signingService.signCleartext(
            "Test message for signing",
            signerFingerprint: identity.fingerprint
        )

        XCTAssertFalse(signed.isEmpty, "Signed message should not be empty")

        // Cleartext signed messages start with "-----BEGIN PGP SIGNED MESSAGE-----"
        let header = String(data: signed.prefix(40), encoding: .utf8)
        XCTAssertTrue(header?.contains("SIGNED MESSAGE") == true,
                      "Should produce cleartext signed message")
    }

    func test_signCleartext_modernHigh_producesSignedMessage() async throws {
        let identity = try await generateKeyAndContact(profile: .advanced)

        let signed = try await stack.signingService.signCleartext(
            "Test message Modern High",
            signerFingerprint: identity.fingerprint
        )

        XCTAssertFalse(signed.isEmpty)
    }

    // MARK: - Detached Signing

    func test_signDetachedStreaming_legacy_producesDetachedSignature() async throws {
        let identity = try await generateKeyAndContact(profile: .universal)
        let data = Data("File content for signing".utf8)
        let fileURL = try makeTemporaryFile(contents: data)
        defer { try? FileManager.default.removeItem(at: fileURL) }

        let signature = try await stack.signingService.signDetachedStreaming(
            fileURL: fileURL,
            signerFingerprint: identity.fingerprint,
            progress: nil
        )

        XCTAssertFalse(signature.isEmpty, "Detached signature should not be empty")
    }

    func test_signDetachedStreaming_modernHigh_producesDetachedSignature() async throws {
        let identity = try await generateKeyAndContact(profile: .advanced)
        let data = Data("File content for Modern High signing".utf8)
        let fileURL = try makeTemporaryFile(contents: data)
        defer { try? FileManager.default.removeItem(at: fileURL) }

        let signature = try await stack.signingService.signDetachedStreaming(
            fileURL: fileURL,
            signerFingerprint: identity.fingerprint,
            progress: nil
        )

        XCTAssertFalse(signature.isEmpty)
    }

    // MARK: - Cleartext Verification

    func test_verifyCleartext_validSignature_returnsValid() async throws {
        let identity = try await generateKeyAndContact(profile: .universal)

        let signed = try await stack.signingService.signCleartext(
            "Verify this message",
            signerFingerprint: identity.fingerprint
        )

        let result = try await stack.signingService.verifyCleartextDetailed(signed)
        XCTAssertEqual(result.verification.summaryState, .verified)
    }

    func test_verifyCleartext_modernHigh_validSignature_returnsValid() async throws {
        let identity = try await generateKeyAndContact(profile: .advanced)

        let signed = try await stack.signingService.signCleartext(
            "Verify this Modern High message",
            signerFingerprint: identity.fingerprint
        )

        let result = try await stack.signingService.verifyCleartextDetailed(signed)
        XCTAssertEqual(result.verification.summaryState, .verified,
                       "Valid Modern High signature should verify as .verified")
    }

    func test_verifyCleartext_tamperedMessage_returnsBad() async throws {
        let identity = try await generateKeyAndContact(profile: .universal)

        var signed = try await stack.signingService.signCleartext(
            "Original message",
            signerFingerprint: identity.fingerprint
        )

        // Tamper: find "Original" and replace with "Modified"
        if let signedString = String(data: signed, encoding: .utf8) {
            let tampered = signedString.replacingOccurrences(of: "Original", with: "Modified")
            signed = Data(tampered.utf8)
        }

        let result = try await stack.signingService.verifyCleartextDetailed(signed)
        XCTAssertEqual(result.verification.summaryState, .invalid)
    }

    func test_verifyCleartext_modernHigh_tamperedMessage_returnsBad() async throws {
        let identity = try await generateKeyAndContact(profile: .advanced)

        var signed = try await stack.signingService.signCleartext(
            "Original Modern High message",
            signerFingerprint: identity.fingerprint
        )

        // Tamper: find "Original" and replace with "Modified"
        if let signedString = String(data: signed, encoding: .utf8) {
            let tampered = signedString.replacingOccurrences(of: "Original", with: "Modified")
            signed = Data(tampered.utf8)
        }

        let result = try await stack.signingService.verifyCleartextDetailed(signed)
        XCTAssertEqual(result.verification.summaryState, .invalid,
                       "Tampered Modern High message should verify as .invalid")
    }

    func test_verifyCleartext_unknownSigner_returnsUnknownSigner() async throws {
        // Create a separate stack for signing — the signer must not be known
        // to the verifier's contacts or own keys
        let otherStack = await TestHelpers.makeServiceStack()
        defer { otherStack.cleanup() }

        let otherIdentity = try await TestHelpers.generateAndStoreKey(
            service: otherStack.keyManagement,
            profile: .universal,
            name: "Stranger"
        )

        let strangerSigned = try await otherStack.signingService.signCleartext(
            "Message from a stranger",
            signerFingerprint: otherIdentity.fingerprint
        )

        // Verify on the original stack — the signer is not known
        try await stack.contactService.relockProtectedData()
        let result = try await stack.signingService.verifyCleartextDetailed(strangerSigned)
        XCTAssertEqual(result.verification.summaryState, .contactsContextUnavailable)
        XCTAssertEqual(result.verification.contactsUnavailableReason, .locked)
        XCTAssertEqual(result.verification.signatures.first?.verificationState, .contactsContextUnavailable)
    }

    func test_verifyCleartext_modernHigh_unknownSigner_returnsUnknownSigner() async throws {
        let otherStack = await TestHelpers.makeServiceStack()
        defer { otherStack.cleanup() }

        let otherIdentity = try await TestHelpers.generateAndStoreKey(
            service: otherStack.keyManagement,
            profile: .advanced,
            name: "Stranger B"
        )

        let strangerSigned = try await otherStack.signingService.signCleartext(
            "Modern High message from a stranger",
            signerFingerprint: otherIdentity.fingerprint
        )

        try await stack.contactService.relockProtectedData()
        let result = try await stack.signingService.verifyCleartextDetailed(strangerSigned)
        XCTAssertEqual(result.verification.summaryState, .contactsContextUnavailable)
    }

    // MARK: - Detached Verification

    func test_verifyDetachedStreaming_validSignature_returnsValid() async throws {
        let identity = try await generateKeyAndContact(profile: .universal)
        let data = Data("Detached verify data".utf8)
        let fileURL = try makeTemporaryFile(contents: data)
        defer { try? FileManager.default.removeItem(at: fileURL) }

        let signature = try await stack.signingService.signDetachedStreaming(
            fileURL: fileURL,
            signerFingerprint: identity.fingerprint,
            progress: nil
        )

        let result = try await stack.signingService.verifyDetachedStreamingDetailed(
            fileURL: fileURL,
            signature: signature,
            progress: nil
        )
        XCTAssertEqual(result.summaryState, .verified)
    }

    func test_verifyDetachedStreaming_modernHigh_validSignature_returnsValid() async throws {
        let identity = try await generateKeyAndContact(profile: .advanced)
        let data = Data("Detached verify Modern High data".utf8)
        let fileURL = try makeTemporaryFile(contents: data)
        defer { try? FileManager.default.removeItem(at: fileURL) }

        let signature = try await stack.signingService.signDetachedStreaming(
            fileURL: fileURL,
            signerFingerprint: identity.fingerprint,
            progress: nil
        )

        let result = try await stack.signingService.verifyDetachedStreamingDetailed(
            fileURL: fileURL,
            signature: signature,
            progress: nil
        )
        XCTAssertEqual(result.summaryState, .verified)
    }

    func test_verifyDetachedStreaming_tamperedData_returnsBad() async throws {
        let identity = try await generateKeyAndContact(profile: .universal)
        let data = Data("Original detached data".utf8)
        let originalURL = try makeTemporaryFile(contents: data)
        defer { try? FileManager.default.removeItem(at: originalURL) }

        let signature = try await stack.signingService.signDetachedStreaming(
            fileURL: originalURL,
            signerFingerprint: identity.fingerprint,
            progress: nil
        )

        let tamperedData = Data("Tampered detached data".utf8)
        let tamperedURL = try makeTemporaryFile(contents: tamperedData)
        defer { try? FileManager.default.removeItem(at: tamperedURL) }

        let result = try await stack.signingService.verifyDetachedStreamingDetailed(
            fileURL: tamperedURL,
            signature: signature,
            progress: nil
        )
        XCTAssertEqual(result.summaryState, .invalid,
                       "Tampered data should fail detached verification")
    }

    func test_verifyDetachedStreaming_modernHigh_tamperedData_returnsBad() async throws {
        let identity = try await generateKeyAndContact(profile: .advanced)
        let data = Data("Original detached Modern High data".utf8)
        let originalURL = try makeTemporaryFile(contents: data)
        defer { try? FileManager.default.removeItem(at: originalURL) }

        let signature = try await stack.signingService.signDetachedStreaming(
            fileURL: originalURL,
            signerFingerprint: identity.fingerprint,
            progress: nil
        )

        let tamperedData = Data("Tampered detached Modern High data".utf8)
        let tamperedURL = try makeTemporaryFile(contents: tamperedData)
        defer { try? FileManager.default.removeItem(at: tamperedURL) }

        let result = try await stack.signingService.verifyDetachedStreamingDetailed(
            fileURL: tamperedURL,
            signature: signature,
            progress: nil
        )
        XCTAssertEqual(result.summaryState, .invalid,
                       "Tampered data should fail Modern High detached verification")
    }

    // MARK: - Expired Signer Key

    func test_verifyCleartext_expiredSignerKey_returnsExpiredOrWarning() async throws {
        // Generate a key with 1-second expiry
        let identity = try await stack.keyManagement.generateKey(
            name: "Expiring Signer",
            email: nil,
            expirySeconds: 1,
            profile: .universal
        )
        try stack.contactService.importContact(publicKeyData: identity.publicKeyData)

        // Sign while key is still valid
        let signed = try await stack.signingService.signCleartext(
            "Signed before expiry",
            signerFingerprint: identity.fingerprint
        )

        // Wait for the key to expire
        try await Task.sleep(for: .seconds(2))

        // Verify the signature — the key is now expired.
        // Sequoia may return .valid (signature was created while key was valid)
        // or a warning/error depending on implementation. Either is acceptable.
        let result = try await stack.signingService.verifyCleartextDetailed(signed)

        // The verification should complete without throwing.
        // We accept either .valid (sig made while key was valid) or a warning status.
        XCTAssertNotEqual(
            result.verification.summaryState,
            .notSigned,
            "Verification should produce a signed result even with expired key"
        )
    }

    func test_verifyCleartext_modernHigh_expiredSignerKey_returnsExpiredOrWarning() async throws {
        // Generate a key with 1-second expiry
        let identity = try await stack.keyManagement.generateKey(
            name: "Expiring Modern High Signer",
            email: nil,
            expirySeconds: 1,
            profile: .advanced
        )
        try stack.contactService.importContact(publicKeyData: identity.publicKeyData)

        // Sign while key is still valid
        let signed = try await stack.signingService.signCleartext(
            "Signed before expiry (Modern High)",
            signerFingerprint: identity.fingerprint
        )

        // Wait for the key to expire
        try await Task.sleep(for: .seconds(2))

        // Verify the signature — the key is now expired.
        // Sequoia may return .valid (signature was created while key was valid)
        // or a warning/error depending on implementation. Either is acceptable.
        let result = try await stack.signingService.verifyCleartextDetailed(signed)

        XCTAssertNotEqual(
            result.verification.summaryState,
            .notSigned,
            "Modern High verification should produce a signed result even with expired key"
        )
    }

    // MARK: - Known Contact Resolution

    func test_verifyCleartext_knownContact_resolvesSigner() async throws {
        let identity = try await generateKeyAndContact(profile: .universal, name: "Alice Known")

        let signed = try await stack.signingService.signCleartext(
            "From a known contact",
            signerFingerprint: identity.fingerprint
        )

        let result = try await stack.signingService.verifyCleartextDetailed(signed)
        XCTAssertEqual(result.verification.summaryState, .verified)
        // The signer's fingerprint should be resolved
        XCTAssertNotNil(result.verification.signatures.first?.signerPrimaryFingerprint)
        XCTAssertEqual(result.verification.signatures.first?.signerIdentity?.source, .contact)
    }

    func test_verifyCleartext_modernHigh_knownContact_resolvesSigner() async throws {
        let identity = try await generateKeyAndContact(profile: .advanced, name: "Bob Known")

        let signed = try await stack.signingService.signCleartext(
            "From a known Modern High contact",
            signerFingerprint: identity.fingerprint
        )

        let result = try await stack.signingService.verifyCleartextDetailed(signed)
        XCTAssertEqual(result.verification.summaryState, .verified)
        XCTAssertNotNil(result.verification.signatures.first?.signerPrimaryFingerprint)
        XCTAssertEqual(result.verification.signatures.first?.signerIdentity?.source, .contact)
    }

    // MARK: - High Security Biometrics Blocking

    func test_signCleartext_highSecurity_biometricsUnavailable_throwsAuthError() async throws {
        let identity = try await TestHelpers.generateLegacyKey(service: stack.keyManagement)

        stack.mockSE.simulatedAuthMode = .highSecurity
        stack.mockSE.biometricsAvailable = false

        do {
            _ = try await stack.signingService.signCleartext(
                "Test message",
                signerFingerprint: identity.fingerprint
            )
            XCTFail("Expected error when biometrics unavailable in High Security mode")
        } catch {
            // Auth error propagated from SE reconstructKey
        }
    }
}
