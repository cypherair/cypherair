import XCTest
@testable import CypherAir

final class PasswordMessageServiceTests: XCTestCase {

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

    private func generateKeyAndContact(
        profile: PGPKeyProfile,
        name: String = "Password Test"
    ) async throws -> PGPKeyIdentity {
        let identity = try await TestHelpers.generateAndStoreKey(
            service: stack.keyManagement,
            profile: profile,
            name: name
        )
        try stack.contactService.addContact(publicKeyData: identity.publicKeyData)
        return identity
    }

    private func contactId(for identity: PGPKeyIdentity) throws -> String {
        try XCTUnwrap(stack.contactService.contactId(forFingerprint: identity.fingerprint))
    }

    private func findTargetedTamper(
        ciphertext: Data,
        password: String,
        acceptedErrors: [PgpError]
    ) throws -> Data {
        let positions = [
            max(ciphertext.count - 8, 0),
            max(ciphertext.count - 16, 0),
            max(ciphertext.count - 24, 0),
            max(ciphertext.count - 32, 0),
            max(ciphertext.count - 48, 0),
            max(ciphertext.count - 64, 0),
            ciphertext.count * 3 / 4,
        ]

        for position in positions where position < ciphertext.count {
            var tampered = ciphertext
            tampered[position] ^= 0x01

            do {
                _ = try stack.engine.decryptWithPassword(
                    ciphertext: tampered,
                    password: password,
                    verificationKeys: []
                )
            } catch let error as PgpError where acceptedErrors.contains(error) {
                return tampered
            } catch {
                continue
            }
        }

        XCTFail("Could not locate a deterministic password-message auth/integrity tamper position")
        return ciphertext
    }

    func test_encryptText_seipdv1_roundTripUnsigned() async throws {
        let ciphertext = try await stack.passwordMessageService.encryptText(
            "Service password message v1",
            password: "service-password-v1",
            format: .seipdv1,
            signWithFingerprint: nil
        )

        let outcome = try await stack.passwordMessageService.decryptMessageDetailed(
            ciphertext: ciphertext,
            password: "service-password-v1"
        )

        guard case let .decrypted(plaintext, verification) = outcome else {
            return XCTFail("Expected decrypted outcome")
        }

        XCTAssertEqual(String(data: plaintext, encoding: .utf8), "Service password message v1")
        XCTAssertEqual(verification.legacyStatus, .notSigned)
        XCTAssertTrue(verification.signatures.isEmpty)
    }

    func test_encryptText_seipdv2_withSignature_preservesSignature() async throws {
        let signer = try await generateKeyAndContact(profile: .advanced, name: "Password Signer")

        let ciphertext = try await stack.passwordMessageService.encryptText(
            "Signed password service message",
            password: "service-password-v2",
            format: .seipdv2,
            signWithFingerprint: signer.fingerprint
        )

        let outcome = try await stack.passwordMessageService.decryptMessageDetailed(
            ciphertext: ciphertext,
            password: "service-password-v2"
        )

        guard case let .decrypted(plaintext, verification) = outcome else {
            return XCTFail("Expected decrypted outcome")
        }

        XCTAssertEqual(String(data: plaintext, encoding: .utf8), "Signed password service message")
        XCTAssertEqual(verification.legacyStatus, .valid)
        XCTAssertEqual(verification.summaryState, .verified)
        XCTAssertEqual(verification.legacySignerFingerprint, signer.fingerprint)
        XCTAssertEqual(verification.signatures.first?.signerIdentity?.source, .contact)
    }

    func test_decryptMessage_signedByUnknownSignerWithLockedContactsKeepsContextUnavailable()
        async throws
    {
        let otherStack = TestHelpers.makeServiceStack()
        defer { otherStack.cleanup() }

        let signer = try await TestHelpers.generateAndStoreKey(
            service: otherStack.keyManagement,
            profile: .universal,
            name: "Password Stranger"
        )
        let ciphertext = try await otherStack.passwordMessageService.encryptText(
            "Password message from unknown signer",
            password: "unknown-signer-password",
            format: .seipdv1,
            signWithFingerprint: signer.fingerprint
        )

        try await stack.contactService.relockProtectedData()
        let outcome = try await stack.passwordMessageService.decryptMessageDetailed(
            ciphertext: ciphertext,
            password: "unknown-signer-password"
        )

        guard case let .decrypted(plaintext, verification) = outcome else {
            return XCTFail("Expected decrypted outcome")
        }

        XCTAssertEqual(
            String(data: plaintext, encoding: .utf8),
            "Password message from unknown signer"
        )
        XCTAssertEqual(verification.legacyStatus, .unknownSigner)
        XCTAssertEqual(verification.summaryState, .contactsContextUnavailable)
        XCTAssertEqual(verification.contactsUnavailableReason, .locked)
        XCTAssertEqual(verification.signatures.first?.verificationState, .contactsContextUnavailable)
    }

    func test_decryptMessage_noSkesk_returnsNoSkesk() async throws {
        let recipient = try await generateKeyAndContact(profile: .universal, name: "Recipient Only")
        let ciphertext = try await stack.encryptionService.encryptText(
            "recipient only",
            recipientContactIds: [try contactId(for: recipient)],
            signWithFingerprint: nil,
            encryptToSelf: false
        )

        let outcome = try await stack.passwordMessageService.decryptMessageDetailed(
            ciphertext: ciphertext,
            password: "irrelevant"
        )

        guard case .noSkesk = outcome else {
            return XCTFail("Expected noSkesk outcome")
        }
    }

    func test_decryptMessage_passwordRejected_isDeterministicForSkesk6() async throws {
        let ciphertext = try await stack.passwordMessageService.encryptBinary(
            Data("reject service password".utf8),
            password: "correct-service-password",
            format: .seipdv2,
            signWithFingerprint: nil
        )

        let outcome = try await stack.passwordMessageService.decryptMessageDetailed(
            ciphertext: ciphertext,
            password: "wrong-service-password"
        )

        guard case .passwordRejected = outcome else {
            return XCTFail("Expected passwordRejected outcome")
        }
    }

    func test_decryptMessage_tamperedSeipdv1_targeted_throwsIntegrityFailure() async throws {
        let ciphertext = try await stack.passwordMessageService.encryptBinary(
            Data("service tamper v1".utf8),
            password: "tamper-service-v1",
            format: .seipdv1,
            signWithFingerprint: nil
        )
        let tampered = try findTargetedTamper(
            ciphertext: ciphertext,
            password: "tamper-service-v1",
            acceptedErrors: [.IntegrityCheckFailed]
        )

        do {
            _ = try await stack.passwordMessageService.decryptMessageDetailed(
                ciphertext: tampered,
                password: "tamper-service-v1"
            )
            XCTFail("Expected tampered password message to fail")
        } catch let error as CypherAirError {
            if case .integrityCheckFailed = error {
                // Expected
            } else {
                XCTFail("Expected integrityCheckFailed, got \(error)")
            }
        }
    }

    func test_decryptMessage_tamperedSeipdv2_targeted_throwsFatalAuthFailure() async throws {
        let ciphertext = try await stack.passwordMessageService.encryptBinary(
            Data("service tamper v2".utf8),
            password: "tamper-service-v2",
            format: .seipdv2,
            signWithFingerprint: nil
        )
        let tampered = try findTargetedTamper(
            ciphertext: ciphertext,
            password: "tamper-service-v2",
            acceptedErrors: [.AeadAuthenticationFailed, .IntegrityCheckFailed]
        )

        do {
            _ = try await stack.passwordMessageService.decryptMessageDetailed(
                ciphertext: tampered,
                password: "tamper-service-v2"
            )
            XCTFail("Expected tampered password message to fail")
        } catch let error as CypherAirError {
            switch error {
            case .aeadAuthenticationFailed, .integrityCheckFailed:
                break
            default:
                XCTFail("Expected aeadAuthenticationFailed or integrityCheckFailed, got \(error)")
            }
        }
    }
}
