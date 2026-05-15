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

    func test_verifyCleartextDetailed_fixtureMultiSigner_preservesDetailedEntries()
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

        XCTAssertEqual(detailed.text, Data("FFI detailed multi-signer cleartext".utf8))
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
    }

    func test_verifyDetachedDetailed_fixtureKnownPlusUnknown_preservesUnknownAndKnownEntries()
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
    }

    func test_verifyDetachedDetailed_fixtureRepeatedSigner_preservesRepeatedEntries()
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
    }

    func test_verifyDetachedDetailed_fixtureExpiredUnknown_preservesDetailedFold()
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
    }

    func test_verifyDetachedDetailed_fixtureExpiredBad_preservesDetailedFold()
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

        XCTAssertEqual(detailed.legacyStatus, .expired)
        XCTAssertEqual(detailed.signatures.count, 2)
        XCTAssertEqual(detailed.signatures[0].status, .expired)
        XCTAssertEqual(detailed.signatures[0].signerPrimaryFingerprint, expiredInfo.fingerprint)
        XCTAssertEqual(detailed.signatures[0].signerIdentity?.source, .contact)
        XCTAssertEqual(detailed.signatures[1].status, .bad)
        XCTAssertNil(detailed.signatures[1].signerPrimaryFingerprint)
        XCTAssertNil(detailed.signatures[1].signerIdentity)
    }

    func test_verifyDetachedStreamingDetailed_fixtureKnownPlusUnknown_matchesInMemoryDetailed()
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

        XCTAssertEqual(detailed.signatures, inMemoryDetailed.signatures)
        XCTAssertEqual(detailed.legacyStatus, inMemoryDetailed.legacyStatus)
        XCTAssertEqual(detailed.legacySignerFingerprint, inMemoryDetailed.legacySignerFingerprint)
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
        } catch {
            XCTFail("Expected operationCancelled, got \(error)")
        }
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

}
