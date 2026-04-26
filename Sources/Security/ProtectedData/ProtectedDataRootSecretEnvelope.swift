import CryptoKit
import Foundation
import Security

struct ProtectedDataRootSecretEnvelope: Codable, Equatable, Sendable {
    static let magic = "CAPDSEV2"
    static let currentFormatVersion = 2
    static let currentAADVersion = 1
    static let algorithmID = "p256-ecdh-hkdf-sha256-aes-gcm-v1"
    static let expectedRootSecretLength = 32
    static let expectedSaltLength = 32
    static let expectedNonceLength = 12
    static let expectedAuthenticationTagLength = 16
    static let expectedP256X963Length = 65

    let magic: String
    let formatVersion: Int
    let algorithmID: String
    let aadVersion: Int
    let sharedRightIdentifier: String
    let deviceBindingKeyIdentifier: String
    let deviceBindingPublicKeyX963: Data
    let ephemeralPublicKeyX963: Data
    let hkdfSalt: Data
    let nonce: Data
    let ciphertext: Data
    let tag: Data

    func validateContract(expectedSharedRightIdentifier: String? = nil) throws {
        guard magic == Self.magic else {
            throw ProtectedDataError.invalidEnvelope("Unsupported root-secret envelope magic.")
        }
        guard formatVersion == Self.currentFormatVersion else {
            throw ProtectedDataError.invalidEnvelope("Unsupported root-secret envelope format version \(formatVersion).")
        }
        guard algorithmID == Self.algorithmID else {
            throw ProtectedDataError.invalidEnvelope("Unsupported root-secret envelope algorithm.")
        }
        guard aadVersion == Self.currentAADVersion else {
            throw ProtectedDataError.invalidEnvelope("Unsupported root-secret envelope AAD version \(aadVersion).")
        }
        if let expectedSharedRightIdentifier {
            guard sharedRightIdentifier == expectedSharedRightIdentifier else {
                throw ProtectedDataError.invalidEnvelope("Root-secret envelope shared-right identifier mismatch.")
            }
        }
        guard !deviceBindingKeyIdentifier.isEmpty else {
            throw ProtectedDataError.invalidEnvelope("Root-secret envelope device-binding key identifier is missing.")
        }
        guard deviceBindingPublicKeyX963.count == Self.expectedP256X963Length else {
            throw ProtectedDataError.invalidEnvelope("Root-secret envelope device-binding public key has invalid length.")
        }
        guard ephemeralPublicKeyX963.count == Self.expectedP256X963Length else {
            throw ProtectedDataError.invalidEnvelope("Root-secret envelope ephemeral public key has invalid length.")
        }
        guard hkdfSalt.count == Self.expectedSaltLength else {
            throw ProtectedDataError.invalidEnvelope("Root-secret envelope HKDF salt has invalid length.")
        }
        guard nonce.count == Self.expectedNonceLength else {
            throw ProtectedDataError.invalidNonceLength(nonce.count)
        }
        guard ciphertext.count == Self.expectedRootSecretLength else {
            throw ProtectedDataError.invalidCiphertextLength(ciphertext.count)
        }
        guard tag.count == Self.expectedAuthenticationTagLength else {
            throw ProtectedDataError.invalidAuthenticationTagLength(tag.count)
        }

        _ = try P256.KeyAgreement.PublicKey(x963Representation: deviceBindingPublicKeyX963)
        _ = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKeyX963)
    }
}

enum ProtectedDataRootSecretEnvelopeCodec {
    private static let allowedKeys: Set<String> = [
        "magic",
        "formatVersion",
        "algorithmID",
        "aadVersion",
        "sharedRightIdentifier",
        "deviceBindingKeyIdentifier",
        "deviceBindingPublicKeyX963",
        "ephemeralPublicKeyX963",
        "hkdfSalt",
        "nonce",
        "ciphertext",
        "tag"
    ]

    static func encode(_ envelope: ProtectedDataRootSecretEnvelope) throws -> Data {
        try envelope.validateContract(expectedSharedRightIdentifier: envelope.sharedRightIdentifier)
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        return try encoder.encode(envelope)
    }

    static func decode(_ data: Data, expectedSharedRightIdentifier: String? = nil) throws -> ProtectedDataRootSecretEnvelope {
        try validateNoUnsupportedKeys(in: data)
        let envelope = try PropertyListDecoder().decode(ProtectedDataRootSecretEnvelope.self, from: data)
        try envelope.validateContract(expectedSharedRightIdentifier: expectedSharedRightIdentifier)
        return envelope
    }

    static func seal(
        rootSecret: Data,
        sharedRightIdentifier: String,
        deviceBindingKeyIdentifier: String,
        deviceBindingPublicKeyX963: Data,
        ephemeralPrivateKey: P256.KeyAgreement.PrivateKey? = nil
    ) throws -> ProtectedDataRootSecretEnvelope {
        guard rootSecret.count == ProtectedDataRootSecretEnvelope.expectedRootSecretLength else {
            throw ProtectedDataError.invalidDomainMasterKeyLength(rootSecret.count)
        }

        let deviceBindingPublicKey = try P256.KeyAgreement.PublicKey(
            x963Representation: deviceBindingPublicKeyX963
        )
        let ephemeralPrivateKey = ephemeralPrivateKey ?? P256.KeyAgreement.PrivateKey()
        let ephemeralPublicKeyX963 = ephemeralPrivateKey.publicKey.x963Representation
        let sharedSecret = try ephemeralPrivateKey.sharedSecretFromKeyAgreement(with: deviceBindingPublicKey)
        let salt = try randomData(count: ProtectedDataRootSecretEnvelope.expectedSaltLength)
        let nonce = try randomData(count: ProtectedDataRootSecretEnvelope.expectedNonceLength)
        let symmetricKey = try rootSecretWrappingKey(
            sharedSecret: sharedSecret,
            salt: salt,
            sharedRightIdentifier: sharedRightIdentifier,
            deviceBindingKeyIdentifier: deviceBindingKeyIdentifier,
            deviceBindingPublicKeyX963: deviceBindingPublicKeyX963,
            ephemeralPublicKeyX963: ephemeralPublicKeyX963,
            rootSecretLength: rootSecret.count
        )
        let aad = try rootSecretEnvelopeAAD(
            sharedRightIdentifier: sharedRightIdentifier,
            deviceBindingKeyIdentifier: deviceBindingKeyIdentifier,
            deviceBindingPublicKeyX963: deviceBindingPublicKeyX963,
            ephemeralPublicKeyX963: ephemeralPublicKeyX963,
            rootSecretLength: rootSecret.count
        )
        let sealedBox = try AES.GCM.seal(
            rootSecret,
            using: symmetricKey,
            nonce: AES.GCM.Nonce(data: nonce),
            authenticating: aad
        )

        let envelope = ProtectedDataRootSecretEnvelope(
            magic: ProtectedDataRootSecretEnvelope.magic,
            formatVersion: ProtectedDataRootSecretEnvelope.currentFormatVersion,
            algorithmID: ProtectedDataRootSecretEnvelope.algorithmID,
            aadVersion: ProtectedDataRootSecretEnvelope.currentAADVersion,
            sharedRightIdentifier: sharedRightIdentifier,
            deviceBindingKeyIdentifier: deviceBindingKeyIdentifier,
            deviceBindingPublicKeyX963: deviceBindingPublicKeyX963,
            ephemeralPublicKeyX963: ephemeralPublicKeyX963,
            hkdfSalt: salt,
            nonce: nonce,
            ciphertext: sealedBox.ciphertext,
            tag: sealedBox.tag
        )
        try envelope.validateContract(expectedSharedRightIdentifier: sharedRightIdentifier)
        return envelope
    }

    static func open(
        envelope: ProtectedDataRootSecretEnvelope,
        sharedSecret: SharedSecret,
        expectedSharedRightIdentifier: String
    ) throws -> Data {
        try envelope.validateContract(expectedSharedRightIdentifier: expectedSharedRightIdentifier)
        let symmetricKey = try rootSecretWrappingKey(
            sharedSecret: sharedSecret,
            salt: envelope.hkdfSalt,
            sharedRightIdentifier: envelope.sharedRightIdentifier,
            deviceBindingKeyIdentifier: envelope.deviceBindingKeyIdentifier,
            deviceBindingPublicKeyX963: envelope.deviceBindingPublicKeyX963,
            ephemeralPublicKeyX963: envelope.ephemeralPublicKeyX963,
            rootSecretLength: envelope.ciphertext.count
        )
        let aad = try rootSecretEnvelopeAAD(
            sharedRightIdentifier: envelope.sharedRightIdentifier,
            deviceBindingKeyIdentifier: envelope.deviceBindingKeyIdentifier,
            deviceBindingPublicKeyX963: envelope.deviceBindingPublicKeyX963,
            ephemeralPublicKeyX963: envelope.ephemeralPublicKeyX963,
            rootSecretLength: envelope.ciphertext.count
        )
        let sealedBox = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: envelope.nonce),
            ciphertext: envelope.ciphertext,
            tag: envelope.tag
        )
        let rootSecret = try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: aad)
        guard rootSecret.count == ProtectedDataRootSecretEnvelope.expectedRootSecretLength else {
            throw ProtectedDataError.invalidDomainMasterKeyLength(rootSecret.count)
        }
        return rootSecret
    }

    static func rootSecretEnvelopeAAD(
        sharedRightIdentifier: String,
        deviceBindingKeyIdentifier: String,
        deviceBindingPublicKeyX963: Data,
        ephemeralPublicKeyX963: Data,
        rootSecretLength: Int
    ) throws -> Data {
        try rootSecretEnvelopeBindingData(
            prefix: "CAPDSEAD",
            sharedRightIdentifier: sharedRightIdentifier,
            deviceBindingKeyIdentifier: deviceBindingKeyIdentifier,
            deviceBindingPublicKeyX963: deviceBindingPublicKeyX963,
            ephemeralPublicKeyX963: ephemeralPublicKeyX963,
            rootSecretLength: rootSecretLength
        )
    }

    private static func rootSecretWrappingKey(
        sharedSecret: SharedSecret,
        salt: Data,
        sharedRightIdentifier: String,
        deviceBindingKeyIdentifier: String,
        deviceBindingPublicKeyX963: Data,
        ephemeralPublicKeyX963: Data,
        rootSecretLength: Int
    ) throws -> SymmetricKey {
        let sharedInfo = try rootSecretEnvelopeBindingData(
            prefix: "CAPDSEKI",
            sharedRightIdentifier: sharedRightIdentifier,
            deviceBindingKeyIdentifier: deviceBindingKeyIdentifier,
            deviceBindingPublicKeyX963: deviceBindingPublicKeyX963,
            ephemeralPublicKeyX963: ephemeralPublicKeyX963,
            rootSecretLength: rootSecretLength
        )
        return sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: sharedInfo,
            outputByteCount: 32
        )
    }

    private static func rootSecretEnvelopeBindingData(
        prefix: String,
        sharedRightIdentifier: String,
        deviceBindingKeyIdentifier: String,
        deviceBindingPublicKeyX963: Data,
        ephemeralPublicKeyX963: Data,
        rootSecretLength: Int
    ) throws -> Data {
        guard let prefixData = prefix.data(using: .utf8),
              let magicData = ProtectedDataRootSecretEnvelope.magic.data(using: .utf8),
              let algorithmData = ProtectedDataRootSecretEnvelope.algorithmID.data(using: .utf8),
              let sharedRightData = sharedRightIdentifier.data(using: .utf8),
              let deviceBindingKeyData = deviceBindingKeyIdentifier.data(using: .utf8) else {
            throw ProtectedDataError.internalFailure("Root-secret envelope binding data could not be encoded.")
        }

        var data = Data()
        data.append(prefixData)
        data.append(UInt8(ProtectedDataRootSecretEnvelope.currentFormatVersion))
        data.append(UInt8(ProtectedDataRootSecretEnvelope.currentAADVersion))
        data.append(UInt16(magicData.count).bigEndianData)
        data.append(magicData)
        data.append(UInt16(algorithmData.count).bigEndianData)
        data.append(algorithmData)
        data.append(UInt16(sharedRightData.count).bigEndianData)
        data.append(sharedRightData)
        data.append(UInt16(deviceBindingKeyData.count).bigEndianData)
        data.append(deviceBindingKeyData)
        let deviceBindingPublicKeyHash = SHA256.hash(data: deviceBindingPublicKeyX963)
        data.append(Data(deviceBindingPublicKeyHash))
        data.append(UInt16(ephemeralPublicKeyX963.count).bigEndianData)
        data.append(UInt16(rootSecretLength).bigEndianData)
        return data
    }

    private static func validateNoUnsupportedKeys(in data: Data) throws {
        var format = PropertyListSerialization.PropertyListFormat.binary
        let propertyList = try PropertyListSerialization.propertyList(
            from: data,
            options: [],
            format: &format
        )
        guard let dictionary = propertyList as? [String: Any] else {
            throw ProtectedDataError.invalidEnvelope("Root-secret envelope is not a dictionary.")
        }
        let keys = Set(dictionary.keys)
        guard keys == allowedKeys else {
            throw ProtectedDataError.invalidEnvelope("Root-secret envelope contains unsupported or missing fields.")
        }
    }

    private static func randomData(count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw ProtectedDataError.internalFailure(
                String(
                    localized: "error.protectedData.randomFailure",
                    defaultValue: "A secure random-number operation failed while preparing protected app data."
                )
            )
        }
        return data
    }
}

private extension UInt16 {
    var bigEndianData: Data {
        withUnsafeBytes(of: bigEndian) { Data($0) }
    }
}
