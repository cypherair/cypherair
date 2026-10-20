import CryptoKit
import Foundation

/// What an envelope seals. Bound into the key derivation and the authenticated
/// data, so a blob opens only as the kind it was sealed as.
public enum SealedPayloadKind: String, Codable, Equatable, Sendable, CaseIterable {
    case rootSecret = "root-secret"
    case secretCertificate = "secret-certificate"
    case splitCustodyComponent = "split-custody-component"
}

/// Authenticated envelope that seals one secret under an enclave P-256
/// key-agreement key.
///
/// Sealing is pure software: a fresh ephemeral P-256 key agrees with the enclave
/// key's public key. Opening needs the enclave: the caller performs the key
/// agreement between the enclave key and the ephemeral public key stored here
/// and hands the shared secret to `open`. The enclave key's blob and public key
/// are folded in, so one row reconstructs the key and reopens the secret, and
/// every public field is bound into HKDF and into the AES-GCM authenticated data.
public struct EnclaveSealedEnvelope: Codable, Equatable, Sendable {
    public static let magic = "CAVENV1"
    public static let ephemeralPublicKeyLength = 65
    public static let saltLength = 32
    public static let nonceLength = 12
    public static let tagLength = 16

    public let magic: String
    public let payloadKind: SealedPayloadKind
    /// Caller-owned public metadata, authenticated but not encrypted.
    public let associatedData: Data
    /// The enclave key's `dataRepresentation`; useless off this device.
    public let sealingKeyBlob: Data
    public let sealingPublicKeyX963: Data
    public let ephemeralPublicKeyX963: Data
    public let hkdfSalt: Data
    public let nonce: Data
    public let ciphertext: Data
    public let tag: Data

    static let allowedKeys: Set<String> = [
        "magic", "payloadKind", "associatedData", "sealingKeyBlob", "sealingPublicKeyX963",
        "ephemeralPublicKeyX963", "hkdfSalt", "nonce", "ciphertext", "tag",
    ]

    func validate(expectedKind: SealedPayloadKind) throws(SealingError) {
        guard magic == Self.magic else { throw .malformed("envelope magic") }
        guard payloadKind == expectedKind else { throw .payloadKindMismatch }
        guard !sealingKeyBlob.isEmpty else { throw .malformed("sealing key blob") }
        guard sealingPublicKeyX963.count == Self.ephemeralPublicKeyLength else { throw .malformed("sealing public key length") }
        guard ephemeralPublicKeyX963.count == Self.ephemeralPublicKeyLength else { throw .malformed("ephemeral public key length") }
        guard hkdfSalt.count == Self.saltLength else { throw .malformed("salt length") }
        guard nonce.count == Self.nonceLength else { throw .malformed("nonce length") }
        guard tag.count == Self.tagLength else { throw .malformed("tag length") }
        guard !ciphertext.isEmpty else { throw .malformed("empty ciphertext") }
        guard (try? P256.KeyAgreement.PublicKey(x963Representation: sealingPublicKeyX963)) != nil else {
            throw .malformed("sealing public key")
        }
        guard (try? P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKeyX963)) != nil else {
            throw .malformed("ephemeral public key")
        }
    }
}

public enum EnclaveSealedEnvelopeCodec {
    /// Seals `plaintext` for the enclave key described by `sealingKeyBlob` and
    /// `sealingPublicKeyX963`. Pure software; no enclave operation.
    public static func seal(
        plaintext: borrowing SensitiveBuffer,
        kind: SealedPayloadKind,
        associatedData: Data,
        sealingKeyBlob: Data,
        sealingPublicKeyX963: Data
    ) throws(SealingError) -> EnclaveSealedEnvelope {
        let ephemeral = P256.KeyAgreement.PrivateKey()
        return try seal(
            plaintext: plaintext,
            kind: kind,
            associatedData: associatedData,
            sealingKeyBlob: sealingKeyBlob,
            sealingPublicKeyX963: sealingPublicKeyX963,
            ephemeralPrivateKey: ephemeral,
            salt: try Randomness.bytes(count: EnclaveSealedEnvelope.saltLength),
            nonce: try Randomness.bytes(count: EnclaveSealedEnvelope.nonceLength)
        )
    }

    /// Deterministic core of `seal`, for known-answer tests.
    static func seal(
        plaintext: borrowing SensitiveBuffer,
        kind: SealedPayloadKind,
        associatedData: Data,
        sealingKeyBlob: Data,
        sealingPublicKeyX963: Data,
        ephemeralPrivateKey: P256.KeyAgreement.PrivateKey,
        salt: Data,
        nonce: Data
    ) throws(SealingError) -> EnclaveSealedEnvelope {
        guard !plaintext.isEmpty else { throw .malformed("empty plaintext") }
        guard !sealingKeyBlob.isEmpty else { throw .malformed("sealing key blob") }
        guard let sealingPublicKey = try? P256.KeyAgreement.PublicKey(x963Representation: sealingPublicKeyX963) else {
            throw .malformed("sealing public key")
        }
        guard let sharedSecret = try? ephemeralPrivateKey.sharedSecretFromKeyAgreement(with: sealingPublicKey) else {
            throw .internalFailure("key agreement failed")
        }
        let ephemeralPublicKeyX963 = ephemeralPrivateKey.publicKey.x963Representation
        let binding = Binding(
            kind: kind,
            associatedData: associatedData,
            sealingKeyBlob: sealingKeyBlob,
            sealingPublicKeyX963: sealingPublicKeyX963,
            ephemeralPublicKeyX963: ephemeralPublicKeyX963,
            plaintextLength: plaintext.count
        )
        let key = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: binding.info,
            outputByteCount: 32
        )
        let sealed: AES.GCM.SealedBox
        do {
            sealed = try plaintext.withUnsafeBytes { bytes in
                try AES.GCM.seal(bytes, using: key, nonce: AES.GCM.Nonce(data: nonce), authenticating: binding.aad)
            }
        } catch {
            throw SealingError.internalFailure("AES-GCM seal failed")
        }
        return EnclaveSealedEnvelope(
            magic: EnclaveSealedEnvelope.magic,
            payloadKind: kind,
            associatedData: associatedData,
            sealingKeyBlob: sealingKeyBlob,
            sealingPublicKeyX963: sealingPublicKeyX963,
            ephemeralPublicKeyX963: ephemeralPublicKeyX963,
            hkdfSalt: salt,
            nonce: nonce,
            ciphertext: sealed.ciphertext,
            tag: sealed.tag
        )
    }

    /// Opens an envelope with the shared secret the enclave produced from its
    /// key and the envelope's ephemeral public key.
    public static func open(
        _ envelope: EnclaveSealedEnvelope,
        sharedSecret: SharedSecret,
        expectedKind: SealedPayloadKind
    ) throws(SealingError) -> SensitiveBuffer {
        try envelope.validate(expectedKind: expectedKind)
        let binding = Binding(
            kind: envelope.payloadKind,
            associatedData: envelope.associatedData,
            sealingKeyBlob: envelope.sealingKeyBlob,
            sealingPublicKeyX963: envelope.sealingPublicKeyX963,
            ephemeralPublicKeyX963: envelope.ephemeralPublicKeyX963,
            plaintextLength: envelope.ciphertext.count
        )
        let key = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: envelope.hkdfSalt,
            sharedInfo: binding.info,
            outputByteCount: 32
        )
        var plaintext: Data
        do {
            let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: envelope.nonce), ciphertext: envelope.ciphertext, tag: envelope.tag)
            plaintext = try AES.GCM.open(box, using: key, authenticating: binding.aad)
        } catch {
            throw SealingError.authenticationFailed
        }
        return SensitiveBuffer(consuming: &plaintext)
    }

    public static func encode(_ envelope: EnclaveSealedEnvelope) throws(SealingError) -> Data {
        try envelope.validate(expectedKind: envelope.payloadKind)
        return try StrictPropertyList.encode(envelope)
    }

    /// Decodes and validates the public structure. No cryptography: the caller
    /// may read `associatedData` and the sealing key blob before any prompt.
    public static func decode(_ data: Data, expectedKind: SealedPayloadKind) throws(SealingError) -> EnclaveSealedEnvelope {
        let envelope = try StrictPropertyList.decode(
            EnclaveSealedEnvelope.self,
            from: data,
            allowedKeys: EnclaveSealedEnvelope.allowedKeys
        )
        try envelope.validate(expectedKind: expectedKind)
        return envelope
    }

    /// The bytes bound into the key derivation (`info`) and the authenticated
    /// data (`aad`). Both cover every public field of the envelope.
    struct Binding {
        let info: Data
        let aad: Data

        init(
            kind: SealedPayloadKind,
            associatedData: Data,
            sealingKeyBlob: Data,
            sealingPublicKeyX963: Data,
            ephemeralPublicKeyX963: Data,
            plaintextLength: Int
        ) {
            func bytes(label: String) -> Data {
                var data = Data(label.utf8)
                data.appendLengthPrefixed(Data(EnclaveSealedEnvelope.magic.utf8))
                data.appendLengthPrefixed(Data(kind.rawValue.utf8))
                data.append(Data(SHA256.hash(data: associatedData)))
                data.append(Data(SHA256.hash(data: sealingKeyBlob)))
                data.append(Data(SHA256.hash(data: sealingPublicKeyX963)))
                data.append(Data(SHA256.hash(data: ephemeralPublicKeyX963)))
                data.append(UInt64(plaintextLength).bigEndianData)
                return data
            }
            info = bytes(label: "CypherAir enclave envelope v1 key")
            aad = bytes(label: "CypherAir enclave envelope v1 aad")
        }
    }
}
