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

        XCTAssertEqual(sharedSecret.raw, expected)
        XCTAssertEqual(sharedSecret.raw.count, 32)
        XCTAssertTrue(sharedSecret.raw.contains(where: { $0 != 0 }))

        let mismatchedRequest = ExternalP256KeyAgreementRequest(
            recipientPublicKey: SoftwareP256CustodyProvider.shared.makeMaterial().keyAgreementPublicKeyX963,
            ephemeralPublicKey: peerPrivateKey.publicKey.x963Representation
        )
        XCTAssertThrowsError(
            try SoftwareP256CustodyProvider.shared.keyAgreement
                .deriveSharedSecret(request: mismatchedRequest, using: handle)
        ) { error in
            XCTAssertEqual(
                error as? SecureEnclaveCustodyHandleError,
                .handlePublicKeyBindingMismatch(.keyAgreement)
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
        XCTAssertThrowsError(try cancelBridge.deriveSharedSecret(request: request)) { error in
            XCTAssertEqual(error as? ExternalP256KeyAgreementError, .OperationCancelled)
        }

        let authBridge = PGPExternalP256KeyAgreementProviderBridge(
            handle: handle,
            keyAgreement: ThrowingKeyAgreement(
                error: SecureEnclaveCustodyHandleError.localAuthenticationFailed(.keyAgreement)
            )
        )
        XCTAssertThrowsError(try authBridge.deriveSharedSecret(request: request)) { error in
            XCTAssertEqual(
                error as? ExternalP256KeyAgreementError,
                .Failed(category: .localAuthenticationFailed)
            )
        }

        let unknownBridge = PGPExternalP256KeyAgreementProviderBridge(
            handle: handle,
            keyAgreement: ThrowingKeyAgreement(error: RawKeyAgreementFailure())
        )
        XCTAssertThrowsError(try unknownBridge.deriveSharedSecret(request: request)) { error in
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

        XCTAssertThrowsError(try bridge.deriveSharedSecret(request: request)) { error in
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
