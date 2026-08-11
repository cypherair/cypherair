import XCTest
@testable import CypherAir

/// What the engine actually writes into the certificate when the app states a
/// validity — the layer below `KeyGenerationScreenModelTests`, which can only see
/// the choice leave the screen model.
extension FFIIntegrationTests {
    func test_generateKey_neverProducesACertificateWithNoExpiry() async throws {
        let metadata = try await generatedKeyMetadata(validity: KeyExpiryPolicy.validity(for: .never))

        XCTAssertNil(
            metadata.expiryDate,
            "the picker's Never must reach Sequoia as no expiry, not as a date the engine chose"
        )
    }

    /// The other direction: a stated term must survive the crossing intact, so
    /// "no expiry works" can never be bought by dropping every expiry.
    func test_generateKey_aStatedTermProducesThatExpiry() async throws {
        let oneYear: TimeInterval = 365 * 24 * 60 * 60
        let metadata = try await generatedKeyMetadata(
            validity: .expiresIn(seconds: UInt64(oneYear))
        )

        let expiryDate = try XCTUnwrap(metadata.expiryDate, "a stated term must produce an expiry")
        XCTAssertEqual(
            expiryDate.timeIntervalSinceNow,
            oneYear,
            accuracy: 60 * 60,
            "the stated term must reach the certificate unaltered"
        )
    }

    /// Generate through the app's own adapter — the path a key generation takes —
    /// and hand back the metadata parsed from the certificate the engine produced.
    private func generatedKeyMetadata(validity: PGPKeyValidity) async throws -> PGPKeyMetadata {
        var material = try await PGPKeyOperationAdapter(engine: engine).generateKey(
            name: "Expiry Probe",
            email: nil,
            validity: validity,
            suite: .ed25519X25519
        )
        defer { material.certData.zeroize() }
        return material.metadata
    }
}
