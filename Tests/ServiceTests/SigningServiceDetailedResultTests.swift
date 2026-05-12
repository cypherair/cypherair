import Foundation
import XCTest
@testable import CypherAir

/// Fixture provenance:
/// `cargo run --manifest-path pgp-mobile/Cargo.toml --example generate_detailed_signature_fixtures`
final class SigningServiceDetailedResultTests: XCTestCase {

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

    func test_verifyCleartextDetailed_fixtureMultiSigner_preservesEntriesAndLegacyBridge()
        async throws
    {
        let signerA = try loadFixture("ffi_detailed_signer_a")
        let signerB = try loadFixture("ffi_detailed_signer_b")
        let signerAInfo = try stack.engine.parseKeyInfo(keyData: signerA)
        let signerBInfo = try stack.engine.parseKeyInfo(keyData: signerB)
        let signedMessage = try loadFixture("ffi_detailed_multisig_cleartext", ext: "asc")

        try addContact(signerA)
        try addContact(signerB)

        let detailed = try await stack.signingService.verifyCleartextDetailed(signedMessage)
        let legacy = try await stack.signingService.verifyCleartext(signedMessage)

        XCTAssertEqual(detailed.text, legacy.text)
        XCTAssertEqual(detailed.verification.signatures.count, 2)
        XCTAssertEqual(detailed.verification.signatures[0].status, .valid)
        XCTAssertEqual(detailed.verification.signatures[1].status, .valid)
        XCTAssertEqual(
            detailed.verification.signatures[0].signerPrimaryFingerprint,
            signerBInfo.fingerprint
        )
        XCTAssertEqual(
            detailed.verification.signatures[1].signerPrimaryFingerprint,
            signerAInfo.fingerprint
        )
        XCTAssertEqual(detailed.verification.signatures[0].signerIdentity?.source, .contact)
        XCTAssertEqual(detailed.verification.signatures[1].signerIdentity?.source, .contact)
        assertLegacyVerificationEquivalent(
            detailed.verification.legacyVerification,
            legacy.verification
        )
    }

    func test_verifyDetachedDetailed_fixtureKnownPlusUnknown_preservesUnknownAndLegacyBridge()
        async throws
    {
        let signerA = try loadFixture("ffi_detailed_signer_a")
        let signerAInfo = try stack.engine.parseKeyInfo(keyData: signerA)
        let data = try loadFixture("ffi_detailed_detached_data", ext: "txt")
        let signature = try loadFixture("ffi_detailed_multisig_detached", ext: "sig")

        try addContact(signerA)

        let detailed = try await stack.signingService.verifyDetachedDetailed(
            data: data,
            signature: signature
        )
        let legacy = try await stack.signingService.verifyDetached(
            data: data,
            signature: signature
        )

        XCTAssertEqual(detailed.signatures.count, 2)
        XCTAssertEqual(detailed.signatures[0].status, .unknownSigner)
        XCTAssertEqual(detailed.signatures[0].verificationState, .signerCertificateUnavailable)
        XCTAssertNil(detailed.signatures[0].contactsUnavailableReason)
        XCTAssertNil(detailed.signatures[0].signerPrimaryFingerprint)
        XCTAssertNil(detailed.signatures[0].signerIdentity)
        XCTAssertEqual(detailed.signatures[1].status, .valid)
        XCTAssertEqual(detailed.signatures[1].verificationState, .verified)
        XCTAssertEqual(
            detailed.signatures[1].signerPrimaryFingerprint,
            signerAInfo.fingerprint
        )
        XCTAssertEqual(detailed.signatures[1].signerIdentity?.source, .contact)
        assertLegacyVerificationEquivalent(detailed.legacyVerification, legacy)
    }

    func test_verifyDetachedDetailed_fixtureRepeatedSigner_preservesRepeatedEntriesAndLegacyBridge()
        async throws
    {
        let signerA = try loadFixture("ffi_detailed_signer_a")
        let signerAInfo = try stack.engine.parseKeyInfo(keyData: signerA)
        let data = try loadFixture("ffi_detailed_detached_data", ext: "txt")
        let signature = try loadFixture("ffi_detailed_repeated_detached", ext: "sig")

        try addContact(signerA)

        let detailed = try await stack.signingService.verifyDetachedDetailed(
            data: data,
            signature: signature
        )
        let legacy = try await stack.signingService.verifyDetached(
            data: data,
            signature: signature
        )

        XCTAssertEqual(detailed.signatures.count, 2)
        XCTAssertEqual(detailed.signatures[0].status, .valid)
        XCTAssertEqual(detailed.signatures[1].status, .valid)
        XCTAssertEqual(
            detailed.signatures[0].signerPrimaryFingerprint,
            signerAInfo.fingerprint
        )
        XCTAssertEqual(
            detailed.signatures[1].signerPrimaryFingerprint,
            signerAInfo.fingerprint
        )
        XCTAssertEqual(detailed.signatures[0].signerIdentity?.source, .contact)
        XCTAssertEqual(detailed.signatures[1].signerIdentity?.source, .contact)
        assertLegacyVerificationEquivalent(detailed.legacyVerification, legacy)
    }

    func test_verifyCleartextDetailed_generatedExpiredSigner_preservesExpiredAndLegacyBridge()
        async throws
    {
        let identity = try await stack.keyManagement.generateKey(
            name: "Detailed Expiring Signer",
            email: "detailed-expiring@example.com",
            expirySeconds: 1,
            profile: .universal
        )
        try addContact(identity.publicKeyData)

        let signed = try await stack.signingService.signCleartext(
            "Detailed expired cleartext",
            signerFingerprint: identity.fingerprint
        )

        try await Task.sleep(for: .seconds(2))

        let detailed = try await stack.signingService.verifyCleartextDetailed(signed)
        let legacy = try await stack.signingService.verifyCleartext(signed)

        XCTAssertEqual(detailed.verification.legacyStatus, .expired)
        XCTAssertEqual(detailed.verification.signatures.count, 1)
        XCTAssertEqual(detailed.verification.signatures[0].status, .expired)
        XCTAssertEqual(
            detailed.verification.signatures[0].signerPrimaryFingerprint,
            identity.fingerprint
        )
        assertLegacyVerificationEquivalent(
            detailed.verification.legacyVerification,
            legacy.verification
        )
    }

    func test_verifyDetachedDetailed_fixtureExpiredUnknown_preservesVerifyFoldAndLegacyBridge()
        async throws
    {
        let expiredSigner = try loadFixture("ffi_detailed_mixedfold_expired_signer")
        let expiredInfo = try stack.engine.parseKeyInfo(keyData: expiredSigner)
        let data = try loadFixture("ffi_detailed_mixedfold_data", ext: "txt")
        let signature = try loadFixture("ffi_detailed_mixedfold_expired_unknown", ext: "sig")

        try addContact(expiredSigner)

        let detailed = try await stack.signingService.verifyDetachedDetailed(
            data: data,
            signature: signature
        )
        let legacy = try await stack.signingService.verifyDetached(
            data: data,
            signature: signature
        )

        XCTAssertEqual(detailed.legacyStatus, .expired)
        XCTAssertEqual(detailed.signatures.count, 2)
        XCTAssertEqual(detailed.signatures[0].status, .unknownSigner)
        XCTAssertEqual(detailed.signatures[0].verificationState, .signerCertificateUnavailable)
        XCTAssertNil(detailed.signatures[0].signerPrimaryFingerprint)
        XCTAssertNil(detailed.signatures[0].signerIdentity)
        XCTAssertEqual(detailed.signatures[1].status, .expired)
        XCTAssertEqual(detailed.signatures[1].verificationState, .expired)
        XCTAssertEqual(
            detailed.signatures[1].signerPrimaryFingerprint,
            expiredInfo.fingerprint
        )
        XCTAssertEqual(detailed.signatures[1].signerIdentity?.source, .contact)
        assertLegacyVerificationEquivalent(detailed.legacyVerification, legacy)
    }

    func test_verifyDetachedDetailed_fixtureExpiredBad_preservesVerifyFoldAndLegacyBridge()
        async throws
    {
        let expiredSigner = try loadFixture("ffi_detailed_mixedfold_expired_signer")
        let badSigner = try loadFixture("ffi_detailed_mixedfold_bad_signer")
        let expiredInfo = try stack.engine.parseKeyInfo(keyData: expiredSigner)
        let data = try loadFixture("ffi_detailed_mixedfold_data", ext: "txt")
        let signature = try loadFixture("ffi_detailed_mixedfold_expired_bad", ext: "sig")

        try addContact(expiredSigner)
        try addContact(badSigner)

        let detailed = try await stack.signingService.verifyDetachedDetailed(
            data: data,
            signature: signature
        )
        let legacy = try await stack.signingService.verifyDetached(
            data: data,
            signature: signature
        )

        XCTAssertEqual(detailed.legacyStatus, .expired)
        XCTAssertEqual(detailed.signatures.count, 2)
        XCTAssertEqual(detailed.signatures[0].status, .expired)
        XCTAssertEqual(detailed.signatures[0].signerPrimaryFingerprint, expiredInfo.fingerprint)
        XCTAssertEqual(detailed.signatures[0].signerIdentity?.source, .contact)
        XCTAssertEqual(detailed.signatures[1].status, .bad)
        XCTAssertNil(detailed.signatures[1].signerPrimaryFingerprint)
        XCTAssertNil(detailed.signatures[1].signerIdentity)
        assertLegacyVerificationEquivalent(detailed.legacyVerification, legacy)
    }

    func test_verifyDetachedStreamingDetailed_fixtureKnownPlusUnknown_matchesInMemoryAndLegacyBridge()
        async throws
    {
        let signerA = try loadFixture("ffi_detailed_signer_a")
        let data = try loadFixture("ffi_detailed_detached_data", ext: "txt")
        let signature = try loadFixture("ffi_detailed_multisig_detached", ext: "sig")
        let fileURL = try makeTemporaryFile(
            named: "ffi-detailed-known-unknown.txt",
            contents: data
        )
        defer { try? FileManager.default.removeItem(at: fileURL) }

        try addContact(signerA)

        let detailed = try await stack.signingService.verifyDetachedStreamingDetailed(
            fileURL: fileURL,
            signature: signature,
            progress: nil
        )
        let inMemoryDetailed = try await stack.signingService.verifyDetachedDetailed(
            data: data,
            signature: signature
        )
        let legacy = try await stack.signingService.verifyDetachedStreaming(
            fileURL: fileURL,
            signature: signature,
            progress: nil
        )

        XCTAssertEqual(detailed.signatures, inMemoryDetailed.signatures)
        XCTAssertEqual(detailed.legacyStatus, inMemoryDetailed.legacyStatus)
        XCTAssertEqual(detailed.legacySignerFingerprint, inMemoryDetailed.legacySignerFingerprint)
        assertLegacyVerificationEquivalent(detailed.legacyVerification, legacy)
    }

    func test_verifyDetachedStreamingDetailed_cancellation_throwsOperationCancelled() async throws {
        let signer = try await TestHelpers.generateAndStoreKey(
            service: stack.keyManagement,
            profile: .universal,
            name: "Detailed Cancel Signer"
        )

        let fileData = Data(repeating: 0x42, count: 256 * 1024)
        let inputURL = try makeTemporaryFile(
            named: "ffi-detailed-cancel.txt",
            contents: fileData
        )
        defer { try? FileManager.default.removeItem(at: inputURL) }

        let signature = try await stack.signingService.signDetachedStreaming(
            fileURL: inputURL,
            signerFingerprint: signer.fingerprint,
            progress: nil
        )

        let progress = FileProgressReporter()
        progress.cancel()

        do {
            _ = try await stack.signingService.verifyDetachedStreamingDetailed(
                fileURL: inputURL,
                signature: signature,
                progress: progress
            )
            XCTFail("Expected operationCancelled")
        } catch let error as CypherAirError {
            guard case .operationCancelled = error else {
                return XCTFail("Expected operationCancelled, got \(error)")
            }
        } catch let error as PgpError {
            guard case .OperationCancelled = error else {
                return XCTFail("Expected OperationCancelled, got \(error)")
            }
        }
    }

    func test_verifyCleartextDetailed_profileBGenerated_matchesLegacyBridge() async throws {
        let identity = try await stack.keyManagement.generateKey(
            name: "Detailed Profile B Signer",
            email: "detailed-b@example.com",
            expirySeconds: nil,
            profile: .advanced
        )

        let signed = try await stack.signingService.signCleartext(
            "Profile B detailed cleartext",
            signerFingerprint: identity.fingerprint
        )

        let detailed = try await stack.signingService.verifyCleartextDetailed(signed)
        let legacy = try await stack.signingService.verifyCleartext(signed)

        XCTAssertEqual(detailed.verification.signatures.count, 1)
        XCTAssertEqual(detailed.verification.signatures[0].status, .valid)
        XCTAssertEqual(detailed.verification.signatures[0].verificationState, .verified)
        XCTAssertEqual(
            detailed.verification.signatures[0].signerPrimaryFingerprint,
            identity.fingerprint
        )
        XCTAssertEqual(detailed.verification.signatures[0].signerIdentity?.source, .ownKey)
        assertLegacyVerificationEquivalent(
            detailed.verification.legacyVerification,
            legacy.verification
        )
    }

    func test_verifyDetachedDetailed_profileBGenerated_matchesLegacyBridge() async throws {
        let identity = try await stack.keyManagement.generateKey(
            name: "Detailed Profile B Detached Signer",
            email: "detailed-b-detached@example.com",
            expirySeconds: nil,
            profile: .advanced
        )
        let data = Data("Profile B detailed detached".utf8)

        let signature = try await stack.signingService.signDetached(
            data,
            signerFingerprint: identity.fingerprint
        )

        let detailed = try await stack.signingService.verifyDetachedDetailed(
            data: data,
            signature: signature
        )
        let legacy = try await stack.signingService.verifyDetached(
            data: data,
            signature: signature
        )

        XCTAssertEqual(detailed.signatures.count, 1)
        XCTAssertEqual(detailed.signatures[0].status, .valid)
        XCTAssertEqual(detailed.signatures[0].signerPrimaryFingerprint, identity.fingerprint)
        assertLegacyVerificationEquivalent(detailed.legacyVerification, legacy)
    }

    private func loadFixture(_ name: String, ext: String = "gpg") throws -> Data {
        try FixtureLoader.loadData(name, ext: ext)
    }

    private func addContact(_ publicKeyData: Data) throws {
        _ = try stack.contactService.addContact(publicKeyData: publicKeyData)
    }

    private func makeTemporaryFile(named name: String, contents: Data) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAirDetailedSigningTests-\(UUID().uuidString)-\(name)")
        try contents.write(to: url, options: .atomic)
        return url
    }

    private func assertLegacyVerificationEquivalent(
        _ actual: SignatureVerification,
        _ expected: SignatureVerification,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertEqual(actual.status, expected.status, file: file, line: line)
        XCTAssertEqual(actual.signerFingerprint, expected.signerFingerprint, file: file, line: line)
        XCTAssertEqual(actual.signerContact, expected.signerContact, file: file, line: line)
        XCTAssertEqual(actual.signerIdentity, expected.signerIdentity, file: file, line: line)
    }
}
