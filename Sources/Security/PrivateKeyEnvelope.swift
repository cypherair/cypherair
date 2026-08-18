import CryptoKit
import Foundation
import Security

/// Errors from the private-key Secure Enclave envelope.
///
/// Kept distinct from `ProtectedDataError`: the private-key envelope protects
/// OpenPGP secret key bytes and must not be conflated with the ProtectedData
/// app-data wrapping path (see SECURITY.md Section 3).
enum PrivateKeyEnvelopeError: Error, Equatable {
    /// Magic / version / algorithm / binding contract was not satisfied.
    case invalidEnvelope(String)
    /// HKDF salt length was not the expected size.
    case invalidSaltLength(Int)
    /// AES-GCM nonce length was not the expected size.
    case invalidNonceLength(Int)
    /// AES-GCM authentication tag length was not the expected size.
    case invalidAuthenticationTagLength(Int)
    /// Sealed private-key ciphertext length was empty or out of bounds.
    case invalidCiphertextLength(Int)
    /// The envelope's bound Secure Enclave public key did not match the handle.
    case deviceBindingMismatch
    /// The sealed payload is of a different kind than the caller asked to open.
    case payloadKindMismatch
    /// Internal encoding/random failure.
    case internalFailure(String)
}

/// What a `PrivateKeyEnvelope` seals. The kind is part of the authenticated
/// binding, so an envelope can only ever be opened as the kind it was sealed
/// as — the two payloads are not interchangeable, and neither the row's
/// location nor a caller's assumption decides which one a blob is.
enum PrivateKeyEnvelopePayloadKind: String, Codable, Equatable, Sendable, CaseIterable {
    /// A whole exportable OpenPGP secret certificate under software custody.
    case softwareSecretCertificate = "software-secret-certificate"
    /// The concatenated classical component scalars of a Device-Bound
    /// Post-Quantum split-custody identity (CUSTODY.md §6).
    case splitCustodyClassicalComponent = "split-custody-classical-component"
}

/// Authenticated envelope that seals one private payload — a software secret
/// certificate or a split-custody classical component — under a per-payload
/// Secure Enclave P-256 key.
///
/// Construction mirrors `ProtectedDataRootSecretEnvelope` (ephemeral-static ECDH):
/// a fresh software ephemeral P-256 key agrees with the **persistent** Secure
/// Enclave public key; the shared secret is HKDF-expanded with a per-seal salt and
/// a domain-separated `sharedInfo`, and the private key is sealed with AES-GCM whose
/// AAD binds every public parameter. The Secure Enclave key `dataRepresentation`
/// (`seKeyData`) is folded into the envelope so a single Keychain row reconstructs
/// the handle and reopens the material.
///
/// `payloadKind` rides in both the HKDF `sharedInfo` and the AES-GCM AAD, so the
/// two payload kinds are cryptographically separated: a classical-component
/// envelope handed to a software-certificate consumer fails contract validation
/// before any Secure Enclave operation, and would fail the AEAD even if that
/// check were bypassed.
///
/// This deliberately does **not** reuse the ProtectedData root-secret envelope:
/// the two are domain-separated by `magic` (`CAPKEV6` vs `CAPDSEV5`) and by their
/// HKDF/AAD prefixes so neither blob can be misread as the other.
///
/// See SECURITY.md Section 3.
struct PrivateKeyEnvelope: Codable, Equatable, Sendable {
    static let magic = "CAPKEV6"
    static let currentFormatVersion = 6
    static let currentAADVersion = 6
    static let algorithmID = "p256-ecdh-hkdf-sha256-aes-gcm-v6"
    static let expectedSaltLength = 32
    static let expectedNonceLength = 12
    static let expectedAuthenticationTagLength = 16
    static let expectedP256X963Length = 65

    let magic: String
    let formatVersion: Int
    let algorithmID: String
    let aadVersion: Int
    /// What the ciphertext holds. Authenticated, never inferred.
    let payloadKind: PrivateKeyEnvelopePayloadKind
    /// Lowercase hex fingerprint of the wrapped key (bound identity).
    let fingerprint: String
    /// Secure Enclave key `dataRepresentation` — folded in so one row reconstructs the handle.
    let seKeyData: Data
    /// Persistent Secure Enclave wrapping-key public key (X9.63, 65 bytes).
    let seKeyPublicKeyX963: Data
    /// Per-seal software ephemeral public key (X9.63, 65 bytes).
    let ephemeralPublicKeyX963: Data
    let hkdfSalt: Data
    let nonce: Data
    let ciphertext: Data
    let tag: Data

    func validateContract(
        expectedFingerprint: String? = nil,
        expectedPayloadKind: PrivateKeyEnvelopePayloadKind
    ) throws {
        guard magic == Self.magic else {
            throw PrivateKeyEnvelopeError.invalidEnvelope("Unsupported private-key envelope magic.")
        }
        guard formatVersion == Self.currentFormatVersion else {
            throw PrivateKeyEnvelopeError.invalidEnvelope("Unsupported private-key envelope format version \(formatVersion).")
        }
        guard algorithmID == Self.algorithmID else {
            throw PrivateKeyEnvelopeError.invalidEnvelope("Unsupported private-key envelope algorithm.")
        }
        guard aadVersion == Self.currentAADVersion else {
            throw PrivateKeyEnvelopeError.invalidEnvelope("Unsupported private-key envelope AAD version \(aadVersion).")
        }
        guard payloadKind == expectedPayloadKind else {
            throw PrivateKeyEnvelopeError.payloadKindMismatch
        }
        try SEConstants.validateFingerprint(fingerprint)
        guard fingerprint == fingerprint.lowercased() else {
            throw PrivateKeyEnvelopeError.invalidEnvelope("Private-key envelope fingerprint must be lowercase hex.")
        }
        if let expectedFingerprint {
            guard fingerprint == expectedFingerprint.lowercased() else {
                throw PrivateKeyEnvelopeError.invalidEnvelope("Private-key envelope fingerprint mismatch.")
            }
        }
        guard !seKeyData.isEmpty else {
            throw PrivateKeyEnvelopeError.invalidEnvelope("Private-key envelope Secure Enclave key data is missing.")
        }
        guard seKeyPublicKeyX963.count == Self.expectedP256X963Length else {
            throw PrivateKeyEnvelopeError.invalidEnvelope("Private-key envelope Secure Enclave public key has invalid length.")
        }
        guard ephemeralPublicKeyX963.count == Self.expectedP256X963Length else {
            throw PrivateKeyEnvelopeError.invalidEnvelope("Private-key envelope ephemeral public key has invalid length.")
        }
        guard hkdfSalt.count == Self.expectedSaltLength else {
            throw PrivateKeyEnvelopeError.invalidSaltLength(hkdfSalt.count)
        }
        guard nonce.count == Self.expectedNonceLength else {
            throw PrivateKeyEnvelopeError.invalidNonceLength(nonce.count)
        }
        // No upper bound: the sealed payload is a full transferable secret key whose
        // size is dominated by user IDs, photo-UID attributes, subkeys, and third-party
        // certifications. The exact length is authenticated in the HKDF sharedInfo and
        // the AES-GCM AAD, so integrity does not depend on a policy limit here.
        guard ciphertext.count >= 1 else {
            throw PrivateKeyEnvelopeError.invalidCiphertextLength(ciphertext.count)
        }
        guard tag.count == Self.expectedAuthenticationTagLength else {
            throw PrivateKeyEnvelopeError.invalidAuthenticationTagLength(tag.count)
        }

        _ = try P256.KeyAgreement.PublicKey(x963Representation: seKeyPublicKeyX963)
        _ = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKeyX963)
    }
}

enum PrivateKeyEnvelopeCodec {
    private static let allowedKeys: Set<String> = [
        "magic",
        "formatVersion",
        "algorithmID",
        "aadVersion",
        "payloadKind",
        "fingerprint",
        "seKeyData",
        "seKeyPublicKeyX963",
        "ephemeralPublicKeyX963",
        "hkdfSalt",
        "nonce",
        "ciphertext",
        "tag"
    ]

    static func encode(_ envelope: PrivateKeyEnvelope) throws -> Data {
        try envelope.validateContract(
            expectedFingerprint: envelope.fingerprint,
            expectedPayloadKind: envelope.payloadKind
        )
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        return try encoder.encode(envelope)
    }

    static func decode(
        _ data: Data,
        expectedFingerprint: String? = nil,
        expectedPayloadKind: PrivateKeyEnvelopePayloadKind
    ) throws -> PrivateKeyEnvelope {
        try validateNoUnsupportedKeys(in: data)
        let envelope = try PropertyListDecoder().decode(PrivateKeyEnvelope.self, from: data)
        try envelope.validateContract(
            expectedFingerprint: expectedFingerprint,
            expectedPayloadKind: expectedPayloadKind
        )
        return envelope
    }

    /// Decode + validate an envelope and return only the Secure Enclave key
    /// `dataRepresentation`, used by the reconstruct seam before biometric unwrap.
    /// A payload-kind mismatch is rejected here — before any Secure Enclave call,
    /// so a wrong-kind row never reaches a biometric prompt.
    static func seKeyData(
        from data: Data,
        expectedFingerprint: String,
        expectedPayloadKind: PrivateKeyEnvelopePayloadKind
    ) throws -> Data {
        try decode(
            data,
            expectedFingerprint: expectedFingerprint,
            expectedPayloadKind: expectedPayloadKind
        ).seKeyData
    }

    static func seal(
        privateKey: borrowing SensitiveBuffer,
        fingerprint: String,
        payloadKind: PrivateKeyEnvelopePayloadKind,
        seKeyData: Data,
        seKeyPublicKeyX963: Data,
        ephemeralPrivateKey: P256.KeyAgreement.PrivateKey? = nil
    ) throws -> PrivateKeyEnvelope {
        try SEConstants.validateFingerprint(fingerprint)
        let normalizedFingerprint = fingerprint.lowercased()
        guard !privateKey.isEmpty else {
            throw PrivateKeyEnvelopeError.invalidCiphertextLength(privateKey.count)
        }
        guard !seKeyData.isEmpty else {
            throw PrivateKeyEnvelopeError.invalidEnvelope("Private-key envelope Secure Enclave key data is missing.")
        }

        let seKeyPublicKey = try P256.KeyAgreement.PublicKey(x963Representation: seKeyPublicKeyX963)
        let ephemeralPrivateKey = ephemeralPrivateKey ?? P256.KeyAgreement.PrivateKey()
        let ephemeralPublicKeyX963 = ephemeralPrivateKey.publicKey.x963Representation
        let sharedSecret = try ephemeralPrivateKey.sharedSecretFromKeyAgreement(with: seKeyPublicKey)
        let salt = try randomData(count: PrivateKeyEnvelope.expectedSaltLength)
        let nonce = try randomData(count: PrivateKeyEnvelope.expectedNonceLength)
        let symmetricKey = try wrappingKey(
            sharedSecret: sharedSecret,
            salt: salt,
            payloadKind: payloadKind,
            fingerprint: normalizedFingerprint,
            seKeyData: seKeyData,
            seKeyPublicKeyX963: seKeyPublicKeyX963,
            ephemeralPublicKeyX963: ephemeralPublicKeyX963,
            plaintextLength: privateKey.count
        )
        let aad = try envelopeAAD(
            payloadKind: payloadKind,
            fingerprint: normalizedFingerprint,
            seKeyData: seKeyData,
            seKeyPublicKeyX963: seKeyPublicKeyX963,
            ephemeralPublicKeyX963: ephemeralPublicKeyX963,
            plaintextLength: privateKey.count
        )
        let sealedBox = try privateKey.withUnsafeBytes { plaintext in
            try AES.GCM.seal(
                plaintext,
                using: symmetricKey,
                nonce: AES.GCM.Nonce(data: nonce),
                authenticating: aad
            )
        }

        let envelope = PrivateKeyEnvelope(
            magic: PrivateKeyEnvelope.magic,
            formatVersion: PrivateKeyEnvelope.currentFormatVersion,
            algorithmID: PrivateKeyEnvelope.algorithmID,
            aadVersion: PrivateKeyEnvelope.currentAADVersion,
            payloadKind: payloadKind,
            fingerprint: normalizedFingerprint,
            seKeyData: seKeyData,
            seKeyPublicKeyX963: seKeyPublicKeyX963,
            ephemeralPublicKeyX963: ephemeralPublicKeyX963,
            hkdfSalt: salt,
            nonce: nonce,
            ciphertext: sealedBox.ciphertext,
            tag: sealedBox.tag
        )
        try envelope.validateContract(
            expectedFingerprint: normalizedFingerprint,
            expectedPayloadKind: payloadKind
        )
        return envelope
    }

    static func open(
        envelope: PrivateKeyEnvelope,
        sharedSecret: SharedSecret,
        expectedFingerprint: String,
        expectedPayloadKind: PrivateKeyEnvelopePayloadKind
    ) throws -> SensitiveBuffer {
        try envelope.validateContract(
            expectedFingerprint: expectedFingerprint,
            expectedPayloadKind: expectedPayloadKind
        )
        let symmetricKey = try wrappingKey(
            sharedSecret: sharedSecret,
            salt: envelope.hkdfSalt,
            payloadKind: envelope.payloadKind,
            fingerprint: envelope.fingerprint,
            seKeyData: envelope.seKeyData,
            seKeyPublicKeyX963: envelope.seKeyPublicKeyX963,
            ephemeralPublicKeyX963: envelope.ephemeralPublicKeyX963,
            plaintextLength: envelope.ciphertext.count
        )
        let aad = try envelopeAAD(
            payloadKind: envelope.payloadKind,
            fingerprint: envelope.fingerprint,
            seKeyData: envelope.seKeyData,
            seKeyPublicKeyX963: envelope.seKeyPublicKeyX963,
            ephemeralPublicKeyX963: envelope.ephemeralPublicKeyX963,
            plaintextLength: envelope.ciphertext.count
        )
        let sealedBox = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: envelope.nonce),
            ciphertext: envelope.ciphertext,
            tag: envelope.tag
        )
        // `AES.GCM.open` hands back a freshly allocated `Data` that nothing else
        // references, which is exactly the ownership `init(consuming:)` needs to
        // move the plaintext into the buffer and erase what it came from.
        var plaintext = try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: aad)
        return SensitiveBuffer(consuming: &plaintext)
    }

    private static func wrappingKey(
        sharedSecret: SharedSecret,
        salt: Data,
        payloadKind: PrivateKeyEnvelopePayloadKind,
        fingerprint: String,
        seKeyData: Data,
        seKeyPublicKeyX963: Data,
        ephemeralPublicKeyX963: Data,
        plaintextLength: Int
    ) throws -> SymmetricKey {
        let sharedInfo = try bindingData(
            prefix: "CAPKKI6",
            payloadKind: payloadKind,
            fingerprint: fingerprint,
            seKeyData: seKeyData,
            seKeyPublicKeyX963: seKeyPublicKeyX963,
            ephemeralPublicKeyX963: ephemeralPublicKeyX963,
            plaintextLength: plaintextLength
        )
        return sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: sharedInfo,
            outputByteCount: 32
        )
    }

    private static func envelopeAAD(
        payloadKind: PrivateKeyEnvelopePayloadKind,
        fingerprint: String,
        seKeyData: Data,
        seKeyPublicKeyX963: Data,
        ephemeralPublicKeyX963: Data,
        plaintextLength: Int
    ) throws -> Data {
        try bindingData(
            prefix: "CAPKAD6",
            payloadKind: payloadKind,
            fingerprint: fingerprint,
            seKeyData: seKeyData,
            seKeyPublicKeyX963: seKeyPublicKeyX963,
            ephemeralPublicKeyX963: ephemeralPublicKeyX963,
            plaintextLength: plaintextLength
        )
    }

    private static func bindingData(
        prefix: String,
        payloadKind: PrivateKeyEnvelopePayloadKind,
        fingerprint: String,
        seKeyData: Data,
        seKeyPublicKeyX963: Data,
        ephemeralPublicKeyX963: Data,
        plaintextLength: Int
    ) throws -> Data {
        guard let prefixData = prefix.data(using: .utf8),
              let magicData = PrivateKeyEnvelope.magic.data(using: .utf8),
              let algorithmData = PrivateKeyEnvelope.algorithmID.data(using: .utf8),
              let payloadKindData = payloadKind.rawValue.data(using: .utf8),
              let fingerprintData = fingerprint.data(using: .utf8) else {
            throw PrivateKeyEnvelopeError.internalFailure("Private-key envelope binding data could not be encoded.")
        }

        var data = Data()
        data.append(prefixData)
        data.append(UInt8(PrivateKeyEnvelope.currentFormatVersion))
        data.append(UInt8(PrivateKeyEnvelope.currentAADVersion))
        data.append(UInt16(magicData.count).bigEndianData)
        data.append(magicData)
        data.append(UInt16(algorithmData.count).bigEndianData)
        data.append(algorithmData)
        data.append(UInt16(payloadKindData.count).bigEndianData)
        data.append(payloadKindData)
        data.append(UInt16(fingerprintData.count).bigEndianData)
        data.append(fingerprintData)
        data.append(Data(SHA256.hash(data: seKeyData)))
        data.append(Data(SHA256.hash(data: seKeyPublicKeyX963)))
        data.append(Data(SHA256.hash(data: ephemeralPublicKeyX963)))
        data.append(UInt16(ephemeralPublicKeyX963.count).bigEndianData)
        data.append(UInt64(plaintextLength).bigEndianData)
        return data
    }

    private static func validateNoUnsupportedKeys(in data: Data) throws {
        guard let keys = try EnvelopePlistInspector.topLevelKeys(in: data) else {
            throw PrivateKeyEnvelopeError.invalidEnvelope("Private-key envelope is not a dictionary.")
        }
        guard keys == allowedKeys else {
            throw PrivateKeyEnvelopeError.invalidEnvelope("Private-key envelope contains unsupported or missing fields.")
        }
    }

    private static func randomData(count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw PrivateKeyEnvelopeError.internalFailure("A secure random-number operation failed while sealing a private key.")
        }
        return data
    }
}
