import Security
import XCTest
@testable import CypherAir

final class PGPExternalP256KeyAgreementProviderBridgeTests: XCTestCase {
    func test_systemKeyAgreementDerivesP256SharedSecretAndChecksRecipientBinding() throws {
        let localPrivateKey = try Self.makeEphemeralP256PrivateKey()
        let localPublicKey = try Self.publicKeyX963(from: localPrivateKey)
        let peerPrivateKey = try Self.makeEphemeralP256PrivateKey()
        let peerPublicKey = try Self.publicKeyX963(from: peerPrivateKey)
        let handle = try Self.handle(
            role: .keyAgreement,
            publicKeyX963: localPublicKey,
            privateKey: localPrivateKey
        )
        let request = ExternalP256KeyAgreementRequest(
            recipientPublicKey: localPublicKey,
            ephemeralPublicKey: peerPublicKey
        )

        let sharedSecret = try SystemSecureEnclaveCustodyKeyAgreement()
            .deriveSharedSecret(request: request, using: handle)
        let expected = try Self.deriveSharedSecret(
            privateKey: peerPrivateKey,
            peerPublicKeyX963: localPublicKey
        )

        XCTAssertEqual(sharedSecret.raw, expected)
        XCTAssertEqual(sharedSecret.raw.count, 32)
        XCTAssertTrue(sharedSecret.raw.contains(where: { $0 != 0 }))

        let mismatchedRequest = ExternalP256KeyAgreementRequest(
            recipientPublicKey: try Self.publicKeyX963(from: try Self.makeEphemeralP256PrivateKey()),
            ephemeralPublicKey: peerPublicKey
        )
        XCTAssertThrowsError(
            try SystemSecureEnclaveCustodyKeyAgreement()
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
            publicKeyX963: Self.publicKey(byte: 0x21),
            privateKey: nil
        )
        let request = ExternalP256KeyAgreementRequest(
            recipientPublicKey: handle.binding.publicKeyX963,
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

    private static func makeEphemeralP256PrivateKey() throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error?.takeRetainedValue() as Error?
                ?? SecureEnclaveCustodyHandleError.privateHandleInaccessible(.keyAgreement)
        }
        return privateKey
    }

    private static func publicKeyX963(from privateKey: SecKey) throws -> Data {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.keyAgreement)
        }
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw error?.takeRetainedValue() as Error?
                ?? SecureEnclaveCustodyHandleError.privateHandleInaccessible(.keyAgreement)
        }
        return data
    }

    private static func deriveSharedSecret(
        privateKey: SecKey,
        peerPublicKeyX963: Data
    ) throws -> Data {
        let peerPublicKey = try importP256PublicKey(peerPublicKeyX963)
        var error: Unmanaged<CFError>?
        guard let sharedSecret = SecKeyCopyKeyExchangeResult(
            privateKey,
            .ecdhKeyExchangeStandard,
            peerPublicKey,
            [:] as CFDictionary,
            &error
        ) as Data? else {
            throw error?.takeRetainedValue() as Error?
                ?? SecureEnclaveCustodyHandleError.privateHandleInaccessible(.keyAgreement)
        }
        return sharedSecret
    }

    private static func importP256PublicKey(_ publicKeyX963: Data) throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        guard let publicKey = SecKeyCreateWithData(
            publicKeyX963 as CFData,
            attributes as CFDictionary,
            &error
        ) else {
            throw error?.takeRetainedValue() as Error?
                ?? SecureEnclaveCustodyHandleError.invalidPublicKey(.keyAgreement)
        }
        return publicKey
    }

    private static func handle(
        role: PGPPrivateOperationRole,
        publicKeyX963: Data,
        privateKey: SecKey?
    ) throws -> SecureEnclaveCustodyLoadedHandle {
        let reference = try SecureEnclaveCustodyHandleReference(
            handleSetIdentifier: "key-agreement-bridge",
            role: role
        )
        return SecureEnclaveCustodyLoadedHandle(
            binding: try SecureEnclaveCustodyHandlePublicBinding(
                reference: reference,
                publicKeyX963: publicKeyX963
            ),
            privateKey: privateKey
        )
    }

    private static func publicKey(byte: UInt8) -> Data {
        var data = Data([0x04])
        data.append(Data(repeating: byte, count: 64))
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
