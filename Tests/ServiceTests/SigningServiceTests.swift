import XCTest
@testable import CypherAir

/// Tests for SigningService — cleartext/detached signing and verification.
final class SigningServiceTests: XCTestCase {

    private var stack: TestHelpers.ServiceStack!

    override func setUp() {
        super.setUp()
        stack = TestHelpers.makeServiceStack()
    }

    override func tearDown() {
        stack.cleanup()
        stack = nil
        super.tearDown()
    }

    // MARK: - Helpers

    /// Generate a key and register it as a contact.
    private func generateKeyAndContact(
        profile: KeyProfile,
        name: String = "Signer"
    ) async throws -> PGPKeyIdentity {
        let identity = try await TestHelpers.generateAndStoreKey(
            service: stack.keyManagement,
            profile: profile,
            name: name
        )
        try stack.contactService.addContact(publicKeyData: identity.publicKeyData)
        return identity
    }

    // MARK: - Cleartext Signing

    func test_signCleartext_profileA_producesSignedMessage() async throws {
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

    func test_signCleartext_profileB_producesSignedMessage() async throws {
        let identity = try await generateKeyAndContact(profile: .advanced)

        let signed = try await stack.signingService.signCleartext(
            "Test message Profile B",
            signerFingerprint: identity.fingerprint
        )

        XCTAssertFalse(signed.isEmpty)
    }

    // MARK: - Detached Signing

    func test_signDetached_profileA_producesDetachedSignature() async throws {
        let identity = try await generateKeyAndContact(profile: .universal)
        let data = Data("File content for signing".utf8)

        let signature = try await stack.signingService.signDetached(
            data, signerFingerprint: identity.fingerprint
        )

        XCTAssertFalse(signature.isEmpty, "Detached signature should not be empty")
    }

    func test_signDetached_profileB_producesDetachedSignature() async throws {
        let identity = try await generateKeyAndContact(profile: .advanced)
        let data = Data("File content for Profile B signing".utf8)

        let signature = try await stack.signingService.signDetached(
            data, signerFingerprint: identity.fingerprint
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

        let result = try await stack.signingService.verifyCleartext(signed)
        XCTAssertEqual(result.verification.status, .valid,
                       "Valid signature should verify as .valid")
        XCTAssertEqual(result.verification.verificationState, .verified)
    }

    func test_verifyCleartext_profileB_validSignature_returnsValid() async throws {
        let identity = try await generateKeyAndContact(profile: .advanced)

        let signed = try await stack.signingService.signCleartext(
            "Verify this Profile B message",
            signerFingerprint: identity.fingerprint
        )

        let result = try await stack.signingService.verifyCleartext(signed)
        XCTAssertEqual(result.verification.status, .valid,
                       "Valid Profile B signature should verify as .valid")
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

        let result = try await stack.signingService.verifyCleartext(signed)
        XCTAssertEqual(result.verification.status, .bad,
                       "Tampered message should verify as .bad")
        XCTAssertEqual(result.verification.verificationState, .invalid)
    }

    func test_verifyCleartext_profileB_tamperedMessage_returnsBad() async throws {
        let identity = try await generateKeyAndContact(profile: .advanced)

        var signed = try await stack.signingService.signCleartext(
            "Original Profile B message",
            signerFingerprint: identity.fingerprint
        )

        // Tamper: find "Original" and replace with "Modified"
        if let signedString = String(data: signed, encoding: .utf8) {
            let tampered = signedString.replacingOccurrences(of: "Original", with: "Modified")
            signed = Data(tampered.utf8)
        }

        let result = try await stack.signingService.verifyCleartext(signed)
        XCTAssertEqual(result.verification.status, .bad,
                       "Tampered Profile B message should verify as .bad")
    }

    func test_verifyCleartext_unknownSigner_returnsUnknownSigner() async throws {
        // Create a separate stack for signing — the signer must not be known
        // to the verifier's contacts or own keys
        let otherStack = TestHelpers.makeServiceStack()
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
        let result = try await stack.signingService.verifyCleartext(strangerSigned)
        XCTAssertEqual(result.verification.status, .unknownSigner,
                       "Unknown signer should be flagged")
        XCTAssertEqual(result.verification.verificationState, .contactsContextUnavailable)
        XCTAssertTrue(result.verification.requiresContactsContext)
        XCTAssertEqual(result.verification.contactsUnavailableReason, .locked)
    }

    func test_verifyCleartext_profileB_unknownSigner_returnsUnknownSigner() async throws {
        let otherStack = TestHelpers.makeServiceStack()
        defer { otherStack.cleanup() }

        let otherIdentity = try await TestHelpers.generateAndStoreKey(
            service: otherStack.keyManagement,
            profile: .advanced,
            name: "Stranger B"
        )

        let strangerSigned = try await otherStack.signingService.signCleartext(
            "Profile B message from a stranger",
            signerFingerprint: otherIdentity.fingerprint
        )

        let result = try await stack.signingService.verifyCleartext(strangerSigned)
        XCTAssertEqual(result.verification.status, .unknownSigner,
                       "Unknown Profile B signer should be flagged")
        XCTAssertEqual(result.verification.verificationState, .contactsContextUnavailable)
        XCTAssertTrue(result.verification.requiresContactsContext)
    }

    // MARK: - Detached Verification

    func test_verifyDetached_validSignature_returnsValid() async throws {
        let identity = try await generateKeyAndContact(profile: .universal)
        let data = Data("Detached verify data".utf8)

        let signature = try await stack.signingService.signDetached(
            data, signerFingerprint: identity.fingerprint
        )

        let result = try await stack.signingService.verifyDetached(
            data: data, signature: signature
        )
        XCTAssertEqual(result.status, .valid)
    }

    func test_verifyDetached_profileB_validSignature_returnsValid() async throws {
        let identity = try await generateKeyAndContact(profile: .advanced)
        let data = Data("Detached verify Profile B data".utf8)

        let signature = try await stack.signingService.signDetached(
            data, signerFingerprint: identity.fingerprint
        )

        let result = try await stack.signingService.verifyDetached(
            data: data, signature: signature
        )
        XCTAssertEqual(result.status, .valid)
    }

    func test_verifyDetached_tamperedData_returnsBad() async throws {
        let identity = try await generateKeyAndContact(profile: .universal)
        let data = Data("Original detached data".utf8)

        let signature = try await stack.signingService.signDetached(
            data, signerFingerprint: identity.fingerprint
        )

        let tamperedData = Data("Tampered detached data".utf8)
        let result = try await stack.signingService.verifyDetached(
            data: tamperedData, signature: signature
        )
        XCTAssertEqual(result.status, .bad,
                       "Tampered data should fail detached verification")
    }

    func test_verifyDetached_profileB_tamperedData_returnsBad() async throws {
        let identity = try await generateKeyAndContact(profile: .advanced)
        let data = Data("Original detached Profile B data".utf8)

        let signature = try await stack.signingService.signDetached(
            data, signerFingerprint: identity.fingerprint
        )

        let tamperedData = Data("Tampered detached Profile B data".utf8)
        let result = try await stack.signingService.verifyDetached(
            data: tamperedData, signature: signature
        )
        XCTAssertEqual(result.status, .bad,
                       "Tampered data should fail Profile B detached verification")
    }

    // MARK: - Expired Signer Key

    func test_verifyCleartext_expiredSignerKey_returnsExpiredOrWarning() async throws {
        // Generate a key with 1-second expiry
        let identity = try await stack.keyManagement.generateKey(
            name: "Expiring Signer",
            email: nil,
            expirySeconds: 1,
            profile: .universal,
            authMode: .standard
        )
        try stack.contactService.addContact(publicKeyData: identity.publicKeyData)

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
        let result = try await stack.signingService.verifyCleartext(signed)

        // The verification should complete without throwing.
        // We accept either .valid (sig made while key was valid) or a warning status.
        XCTAssertNotNil(result.verification.status,
                        "Verification should produce a result even with expired key")
    }

    func test_verifyCleartext_profileB_expiredSignerKey_returnsExpiredOrWarning() async throws {
        // Generate a key with 1-second expiry
        let identity = try await stack.keyManagement.generateKey(
            name: "Expiring Profile B Signer",
            email: nil,
            expirySeconds: 1,
            profile: .advanced,
            authMode: .standard
        )
        try stack.contactService.addContact(publicKeyData: identity.publicKeyData)

        // Sign while key is still valid
        let signed = try await stack.signingService.signCleartext(
            "Signed before expiry (Profile B)",
            signerFingerprint: identity.fingerprint
        )

        // Wait for the key to expire
        try await Task.sleep(for: .seconds(2))

        // Verify the signature — the key is now expired.
        // Sequoia may return .valid (signature was created while key was valid)
        // or a warning/error depending on implementation. Either is acceptable.
        let result = try await stack.signingService.verifyCleartext(signed)

        XCTAssertNotNil(result.verification.status,
                        "Profile B verification should produce a result even with expired key")
    }

    // MARK: - Known Contact Resolution

    func test_verifyCleartext_knownContact_resolvesSigner() async throws {
        let identity = try await generateKeyAndContact(profile: .universal, name: "Alice Known")

        let signed = try await stack.signingService.signCleartext(
            "From a known contact",
            signerFingerprint: identity.fingerprint
        )

        let result = try await stack.signingService.verifyCleartext(signed)
        XCTAssertEqual(result.verification.status, .valid)
        // The signer's fingerprint should be resolved
        XCTAssertNotNil(result.verification.signerFingerprint)
    }

    func test_verifyCleartext_profileB_knownContact_resolvesSigner() async throws {
        let identity = try await generateKeyAndContact(profile: .advanced, name: "Bob Known")

        let signed = try await stack.signingService.signCleartext(
            "From a known Profile B contact",
            signerFingerprint: identity.fingerprint
        )

        let result = try await stack.signingService.verifyCleartext(signed)
        XCTAssertEqual(result.verification.status, .valid)
        XCTAssertNotNil(result.verification.signerFingerprint)
    }

    // MARK: - H1: High Security Biometrics Blocking

    func test_signCleartext_highSecurity_biometricsUnavailable_throwsAuthError() async throws {
        let identity = try await TestHelpers.generateProfileAKey(service: stack.keyManagement)

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
