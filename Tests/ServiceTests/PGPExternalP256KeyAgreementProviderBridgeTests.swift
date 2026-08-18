import CryptoKit
import XCTest
@testable import CypherAir

final class PGPExternalP256KeyAgreementProviderBridgeTests: XCTestCase {
    func test_keyAgreementDerivesP256SharedSecretAndChecksRecipientBinding() throws {
        let material = SoftwareP256CustodyProvider.shared.makeMaterial()
        let localPublicKey = material.keyAgreementPublicKeyX963
        let peerPrivateKey = P256.KeyAgreement.PrivateKey()
        let handle = try Self.handle(role: .keyAgreement, publicKeyX963: localPublicKey)
        let request = ExternalP256KeyAgreementRequest(
            recipientPublicKey: localPublicKey,
            ephemeralPublicKey: peerPrivateKey.publicKey.x963Representation
        )

        let sharedSecret = try SoftwareP256CustodyProvider.shared.keyAgreement
            .deriveSharedSecret(request: request, using: handle)
        let expected = try peerPrivateKey.sharedSecretFromKeyAgreement(
            with: P256.KeyAgreement.PublicKey(x963Representation: localPublicKey)
        ).withUnsafeBytes { Data($0) }

        XCTAssertEqual(sharedSecret.raw.copiedBytes(), expected)
        XCTAssertEqual(sharedSecret.raw.count, SecureEnclaveP256RawSharedSecret.rawLength)

        let mismatchedRequest = ExternalP256KeyAgreementRequest(
            recipientPublicKey: SoftwareP256CustodyProvider.shared.makeMaterial().keyAgreementPublicKeyX963,
            ephemeralPublicKey: peerPrivateKey.publicKey.x963Representation
        )
        assertThrowsError(
            try SoftwareP256CustodyProvider.shared.keyAgreement
                .deriveSharedSecret(request: mismatchedRequest, using: handle)
        ) { error in
            XCTAssertEqual(
                error as? SecureEnclaveCustodyHandleError,
                .handlePublicKeyBindingMismatch(.keyAgreement)
            )
        }
    }

    /// The carrier's two fail-closed checks, which nothing downstream repeats:
    /// a key agreement that yields an all-zero point or the wrong number of
    /// bytes must never reach the engine as a shared secret.
    func test_rawSharedSecret_rejectsAnAllZeroPointAndAWrongLength() {
        assertThrowsError(
            try SecureEnclaveP256RawSharedSecret(
                raw: SensitiveBuffer(count: SecureEnclaveP256RawSharedSecret.rawLength) { _ in }
            )
        ) { error in
            XCTAssertEqual(
                error as? SecureEnclaveCustodyHandleError,
                .privateHandleInaccessible(.keyAgreement)
            )
        }

        assertThrowsError(
            try SecureEnclaveP256RawSharedSecret(
                raw: SensitiveBuffer(copying: Data(repeating: 0x7F, count: 31))
            )
        ) { error in
            XCTAssertEqual(
                error as? SecureEnclaveCustodyHandleError,
                .privateHandleInaccessible(.keyAgreement)
            )
        }
    }

    func test_providerBridgeMapsCancellationAndStableFailureCategories() throws {
        let handle = try Self.handle(
            role: .keyAgreement,
            publicKeyX963: Self.publicKey(byte: 0x21)
        )
        let request = ExternalP256KeyAgreementRequest(
            recipientPublicKey: handle.binding.publicKeyRaw,
            ephemeralPublicKey: Self.publicKey(byte: 0x22)
        )

        let cancelBridge = PGPExternalP256KeyAgreementProviderBridge(
            handle: handle,
            keyAgreement: ThrowingKeyAgreement(error: CancellationError())
        )
        assertThrowsError(try cancelBridge.deriveSharedSecret(request: request)) { error in
            XCTAssertEqual(error as? ExternalP256KeyAgreementError, .OperationCancelled)
        }

        let authBridge = PGPExternalP256KeyAgreementProviderBridge(
            handle: handle,
            keyAgreement: ThrowingKeyAgreement(
                error: SecureEnclaveCustodyHandleError.localAuthenticationFailed(.keyAgreement)
            )
        )
        assertThrowsError(try authBridge.deriveSharedSecret(request: request)) { error in
            XCTAssertEqual(
                error as? ExternalP256KeyAgreementError,
                .Failed(category: .localAuthenticationFailed)
            )
        }

        let unknownBridge = PGPExternalP256KeyAgreementProviderBridge(
            handle: handle,
            keyAgreement: ThrowingKeyAgreement(error: RawKeyAgreementFailure())
        )
        assertThrowsError(try unknownBridge.deriveSharedSecret(request: request)) { error in
            XCTAssertEqual(
                error as? ExternalP256KeyAgreementError,
                .Failed(category: .externalOperationFailed)
            )
        }
    }

    func test_providerBridgeRejectsShapeValidOffCurveEphemeralPublicKey() throws {
        let material = SoftwareP256CustodyProvider.shared.makeMaterial()
        let localPublicKey = material.keyAgreementPublicKeyX963
        let handle = try Self.handle(role: .keyAgreement, publicKeyX963: localPublicKey)
        let request = ExternalP256KeyAgreementRequest(
            recipientPublicKey: localPublicKey,
            ephemeralPublicKey: Self.shapeValidOffCurvePublicKey()
        )
        let bridge = PGPExternalP256KeyAgreementProviderBridge(
            handle: handle,
            keyAgreement: SoftwareP256CustodyProvider.shared.keyAgreement
        )

        assertThrowsError(try bridge.deriveSharedSecret(request: request)) { error in
            XCTAssertEqual(
                error as? ExternalP256KeyAgreementError,
                .Failed(category: .externalOperationInvalidRequest)
            )
        }
    }

    private static func handle(
        role: PGPPrivateOperationRole,
        publicKeyX963: Data
    ) throws -> SecureEnclaveCustodyLoadedHandle {
        let reference = try SecureEnclaveCustodyHandleReference(
            handleSetIdentifier: "a9bcd0e1",
            role: role,
            tier: .classicalP256
        )
        return SecureEnclaveCustodyLoadedHandle(
            binding: try SecureEnclaveCustodyHandlePublicBinding(
                reference: reference,
                publicKeyRaw: publicKeyX963
            ),
            privateKey: nil
        )
    }

    private static func publicKey(byte: UInt8) -> Data {
        var data = Data([0x04])
        data.append(Data(repeating: byte, count: 64))
        return data
    }

    private static func shapeValidOffCurvePublicKey() -> Data {
        var data = Data([0x04])
        data.append(Data(repeating: 0x00, count: 63))
        data.append(0x01)
        return data
    }
}

private struct ThrowingKeyAgreement: SecureEnclaveCustodyKeyAgreement {
    let error: Error

    func deriveSharedSecret(
        request: ExternalP256KeyAgreementRequest,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> SecureEnclaveP256RawSharedSecret {
        throw error
    }
}

private struct RawKeyAgreementFailure: Error {}
