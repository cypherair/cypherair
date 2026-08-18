import CryptoKit
import Foundation
import Security

/// Authenticated envelope that seals the 32-byte ProtectedData root secret under a
/// ProtectedData-only Secure Enclave P-256 device-binding key (ephemeral-static ECDH).
///
/// Self-contained single row: like `PrivateKeyEnvelope` folds `seKeyData`, this folds
/// the device-binding Secure Enclave key `dataRepresentation` (`deviceBindingKeyData`)
/// into the envelope so one Keychain row reconstructs the handle and reopens the root
/// secret — there is no separate persisted key item. The folded blob is an
/// SE-encrypted key that is useless off-device, and its hash is bound into both the
/// HKDF `sharedInfo` and the AES-GCM AAD.
///
/// Domain-separated from the per-key private-key envelope (`CAPKEV1`) by distinct
/// `magic` (`CAPDSEV1`) and HKDF/AAD prefixes so neither blob can be misread. The
/// magic is the format's whole identity — there is exactly one construction per
/// magic — and it is bound into both the HKDF `sharedInfo` and the AES-GCM AAD.
///
/// See SECURITY.md Section 3.
struct ProtectedDataRootSecretEnvelope: Codable, Equatable, Sendable {
    static let magic = "CAPDSEV1"
    /// HKDF `sharedInfo` domain-separation prefix for this magic.
    static let hkdfInfoPrefix = "CAPDSEKI1"
    /// AES-GCM AAD domain-separation prefix for this magic.
    static let aadPrefix = "CAPDSEAD1"
    /// Derived AES-256 wrapping-key length. Its own fact: the root secret and
    /// the HKDF salt agree on the number, but each is a different quantity.
    static let wrappingKeyLength = 32
    static let expectedRootSecretLength = 32
    static let expectedSaltLength = 32
    static let expectedNonceLength = 12
    static let expectedAuthenticationTagLength = 16
    static let expectedP256X963Length = 65

    let magic: String
    let sharedRightIdentifier: String
    let deviceBindingKeyIdentifier: String
    /// ProtectedData device-binding Secure Enclave key `dataRepresentation` — folded in
    /// so one row reconstructs the handle. SE-encrypted; useless off-device.
    let deviceBindingKeyData: Data
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
        if let expectedSharedRightIdentifier {
            guard sharedRightIdentifier == expectedSharedRightIdentifier else {
                throw ProtectedDataError.invalidEnvelope("Root-secret envelope shared-right identifier mismatch.")
            }
        }
        guard !deviceBindingKeyIdentifier.isEmpty else {
            throw ProtectedDataError.invalidEnvelope("Root-secret envelope device-binding key identifier is missing.")
        }
        guard !deviceBindingKeyData.isEmpty else {
            throw ProtectedDataError.invalidEnvelope("Root-secret envelope device-binding key data is missing.")
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
            throw ProtectedDataError.invalidNonceLength(expected: Self.expectedNonceLength, got: nonce.count)
        }
        guard ciphertext.count == Self.expectedRootSecretLength else {
            throw ProtectedDataError.invalidCiphertextLength(expected: Self.expectedRootSecretLength, got: ciphertext.count)
        }
        guard tag.count == Self.expectedAuthenticationTagLength else {
            throw ProtectedDataError.invalidAuthenticationTagLength(
                expected: Self.expectedAuthenticationTagLength,
                got: tag.count
            )
        }

        _ = try P256.KeyAgreement.PublicKey(x963Representation: deviceBindingPublicKeyX963)
        _ = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKeyX963)
    }
}

enum ProtectedDataRootSecretEnvelopeCodec {
    private static let allowedKeys: Set<String> = [
        "magic",
        "sharedRightIdentifier",
        "deviceBindingKeyIdentifier",
        "deviceBindingKeyData",
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
        try EnvelopePlistInspector.validateTopLevelKeys(
            in: data,
            allowed: allowedKeys,
            noun: "Root-secret envelope"
        )
        let envelope = try PropertyListDecoder().decode(ProtectedDataRootSecretEnvelope.self, from: data)
        try envelope.validateContract(expectedSharedRightIdentifier: expectedSharedRightIdentifier)
        return envelope
    }

    static func seal(
        rootSecret: Data,
        sharedRightIdentifier: String,
        deviceBindingKeyIdentifier: String,
        deviceBindingKeyData: Data,
        deviceBindingPublicKeyX963: Data,
        ephemeralPrivateKey: P256.KeyAgreement.PrivateKey? = nil
    ) throws -> ProtectedDataRootSecretEnvelope {
        guard rootSecret.count == ProtectedDataRootSecretEnvelope.expectedRootSecretLength else {
            throw ProtectedDataError.invalidKeyMaterialLength(
                expected: ProtectedDataRootSecretEnvelope.expectedRootSecretLength,
                got: rootSecret.count
            )
        }
        guard !deviceBindingKeyData.isEmpty else {
            throw ProtectedDataError.invalidEnvelope("Root-secret envelope device-binding key data is missing.")
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
            deviceBindingKeyData: deviceBindingKeyData,
            deviceBindingPublicKeyX963: deviceBindingPublicKeyX963,
            ephemeralPublicKeyX963: ephemeralPublicKeyX963,
            rootSecretLength: rootSecret.count
        )
        let aad = try rootSecretEnvelopeAAD(
            sharedRightIdentifier: sharedRightIdentifier,
            deviceBindingKeyIdentifier: deviceBindingKeyIdentifier,
            deviceBindingKeyData: deviceBindingKeyData,
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
            sharedRightIdentifier: sharedRightIdentifier,
            deviceBindingKeyIdentifier: deviceBindingKeyIdentifier,
            deviceBindingKeyData: deviceBindingKeyData,
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
            deviceBindingKeyData: envelope.deviceBindingKeyData,
            deviceBindingPublicKeyX963: envelope.deviceBindingPublicKeyX963,
            ephemeralPublicKeyX963: envelope.ephemeralPublicKeyX963,
            rootSecretLength: envelope.ciphertext.count
        )
        let aad = try rootSecretEnvelopeAAD(
            sharedRightIdentifier: envelope.sharedRightIdentifier,
            deviceBindingKeyIdentifier: envelope.deviceBindingKeyIdentifier,
            deviceBindingKeyData: envelope.deviceBindingKeyData,
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
            throw ProtectedDataError.invalidKeyMaterialLength(
                expected: ProtectedDataRootSecretEnvelope.expectedRootSecretLength,
                got: rootSecret.count
            )
        }
        return rootSecret
    }

    static func rootSecretEnvelopeAAD(
        sharedRightIdentifier: String,
        deviceBindingKeyIdentifier: String,
        deviceBindingKeyData: Data,
        deviceBindingPublicKeyX963: Data,
        ephemeralPublicKeyX963: Data,
        rootSecretLength: Int
    ) throws -> Data {
        try rootSecretEnvelopeBindingData(
            prefix: ProtectedDataRootSecretEnvelope.aadPrefix,
            sharedRightIdentifier: sharedRightIdentifier,
            deviceBindingKeyIdentifier: deviceBindingKeyIdentifier,
            deviceBindingKeyData: deviceBindingKeyData,
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
        deviceBindingKeyData: Data,
        deviceBindingPublicKeyX963: Data,
        ephemeralPublicKeyX963: Data,
        rootSecretLength: Int
    ) throws -> SymmetricKey {
        let sharedInfo = try rootSecretEnvelopeBindingData(
            prefix: ProtectedDataRootSecretEnvelope.hkdfInfoPrefix,
            sharedRightIdentifier: sharedRightIdentifier,
            deviceBindingKeyIdentifier: deviceBindingKeyIdentifier,
            deviceBindingKeyData: deviceBindingKeyData,
            deviceBindingPublicKeyX963: deviceBindingPublicKeyX963,
            ephemeralPublicKeyX963: ephemeralPublicKeyX963,
            rootSecretLength: rootSecretLength
        )
        return sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: sharedInfo,
            outputByteCount: ProtectedDataRootSecretEnvelope.wrappingKeyLength
        )
    }

    private static func rootSecretEnvelopeBindingData(
        prefix: String,
        sharedRightIdentifier: String,
        deviceBindingKeyIdentifier: String,
        deviceBindingKeyData: Data,
        deviceBindingPublicKeyX963: Data,
        ephemeralPublicKeyX963: Data,
        rootSecretLength: Int
    ) throws -> Data {
        guard let prefixData = prefix.data(using: .utf8),
              let magicData = ProtectedDataRootSecretEnvelope.magic.data(using: .utf8),
              let sharedRightData = sharedRightIdentifier.data(using: .utf8),
              let deviceBindingKeyIdentifierData = deviceBindingKeyIdentifier.data(using: .utf8) else {
            throw ProtectedDataError.internalFailure("Root-secret envelope binding data could not be encoded.")
        }

        var data = Data()
        data.append(prefixData)
        data.append(UInt16(magicData.count).bigEndianData)
        data.append(magicData)
        data.append(UInt16(sharedRightData.count).bigEndianData)
        data.append(sharedRightData)
        data.append(UInt16(deviceBindingKeyIdentifierData.count).bigEndianData)
        data.append(deviceBindingKeyIdentifierData)
        let deviceBindingKeyDataHash = SHA256.hash(data: deviceBindingKeyData)
        data.append(Data(deviceBindingKeyDataHash))
        let deviceBindingPublicKeyHash = SHA256.hash(data: deviceBindingPublicKeyX963)
        data.append(Data(deviceBindingPublicKeyHash))
        let ephemeralPublicKeyHash = SHA256.hash(data: ephemeralPublicKeyX963)
        data.append(Data(ephemeralPublicKeyHash))
        data.append(UInt16(ephemeralPublicKeyX963.count).bigEndianData)
        data.append(UInt16(rootSecretLength).bigEndianData)
        return data
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
