import CryptoKit
import Foundation
import Testing
@testable import Sealing

/// The envelope's contract: it opens only with the right shared secret, only as
/// the kind it was sealed as, and only while every public field is intact.
struct EnclaveSealedEnvelopeTests {
    /// A software P-256 key standing in for the enclave key: the seal side only
    /// ever sees its public key and blob, and the open side supplies the shared
    /// secret exactly as the vault does with a real enclave key.
    private let sealingKey = P256.KeyAgreement.PrivateKey()
    private var blob: Data { Data("stand-in enclave key blob".utf8) }

    private func seal(_ plaintext: [UInt8], kind: SealedPayloadKind = .rootSecret, associatedData: Data = Data("meta".utf8)) throws -> EnclaveSealedEnvelope {
        let secret = SensitiveBuffer(count: plaintext.count) { $0.copyBytes(from: plaintext) }
        return try EnclaveSealedEnvelopeCodec.seal(
            plaintext: secret, kind: kind, associatedData: associatedData,
            sealingKeyBlob: blob, sealingPublicKeyX963: sealingKey.publicKey.x963Representation
        )
    }

    private func open(_ envelope: EnclaveSealedEnvelope, kind: SealedPayloadKind = .rootSecret) throws -> [UInt8] {
        let ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: envelope.ephemeralPublicKeyX963)
        let shared = try sealingKey.sharedSecretFromKeyAgreement(with: ephemeral)
        let opened = try EnclaveSealedEnvelopeCodec.open(envelope, sharedSecret: shared, expectedKind: kind)
        return opened.withUnsafeBytes { Array($0) }
    }

    @Test func `Wrong kind is refused before any cryptography`() throws {
        let envelope = try seal([1, 2, 3], kind: .secretKeys)
        let encoded = try EnclaveSealedEnvelopeCodec.encode(envelope)
        #expect(throws: SealingError.payloadKindMismatch) {
            try EnclaveSealedEnvelopeCodec.decode(encoded, expectedKind: .rootSecret)
        }
        #expect(throws: SealingError.payloadKindMismatch) {
            try open(envelope, kind: .splitCustodyComponent)
        }
    }

    @Test func `Every public field is authenticated`() throws {
        let envelope = try seal(Array("payload".utf8))
        func flipped(_ data: Data) -> Data { var copy = data; copy[copy.startIndex] ^= 0x01; return copy }
        let variants: [(String, EnclaveSealedEnvelope)] = [
            ("associatedData", envelope.with(associatedData: flipped(envelope.associatedData))),
            ("sealingKeyBlob", envelope.with(sealingKeyBlob: flipped(envelope.sealingKeyBlob))),
            ("hkdfSalt", envelope.with(hkdfSalt: flipped(envelope.hkdfSalt))),
            ("nonce", envelope.with(nonce: flipped(envelope.nonce))),
            ("ciphertext", envelope.with(ciphertext: flipped(envelope.ciphertext))),
            ("tag", envelope.with(tag: flipped(envelope.tag))),
        ]
        for (field, variant) in variants {
            #expect(throws: SealingError.authenticationFailed, "\(field)") {
                try open(variant)
            }
        }
        // A different sealing public key changes the derived key and the binding alike.
        let otherKey = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        #expect(throws: SealingError.authenticationFailed) {
            try open(envelope.with(sealingPublicKeyX963: otherKey))
        }
    }

    @Test func `Another enclave key cannot open`() throws {
        let envelope = try seal([9, 9, 9])
        let other = P256.KeyAgreement.PrivateKey()
        let ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: envelope.ephemeralPublicKeyX963)
        let shared = try other.sharedSecretFromKeyAgreement(with: ephemeral)
        #expect(throws: SealingError.authenticationFailed) {
            _ = try EnclaveSealedEnvelopeCodec.open(envelope, sharedSecret: shared, expectedKind: .rootSecret)
        }
    }

    @Test func `Unknown or missing field is refused`() throws {
        let envelope = try seal([1])
        let encoded = try EnclaveSealedEnvelopeCodec.encode(envelope)
        var object = try #require(try PropertyListSerialization.propertyList(from: encoded, format: nil) as? [String: Any])
        object["extra"] = "x"
        let withExtra = try PropertyListSerialization.data(fromPropertyList: object, format: .binary, options: 0)
        #expect(throws: SealingError.malformed("unsupported or missing fields")) {
            try EnclaveSealedEnvelopeCodec.decode(withExtra, expectedKind: .rootSecret)
        }
        object.removeValue(forKey: "extra"); object.removeValue(forKey: "tag")
        let missing = try PropertyListSerialization.data(fromPropertyList: object, format: .binary, options: 0)
        #expect(throws: SealingError.malformed("unsupported or missing fields")) {
            try EnclaveSealedEnvelopeCodec.decode(missing, expectedKind: .rootSecret)
        }
        #expect(throws: SealingError.malformed("not a property list")) {
            try EnclaveSealedEnvelopeCodec.decode(Data("not a plist".utf8), expectedKind: .rootSecret)
        }
    }

    /// Pins the derivation labels and the authenticated-data layout. Any change
    /// to either alters the ciphertext of these fixed inputs.
    @Test func `Known answer pins binding and derivation`() throws {
        let staticKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 0x11, count: 32))
        let ephemeral = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 0x22, count: 32))
        let plaintext = SensitiveBuffer(count: 8) { $0.copyBytes(from: Array("vector01".utf8)) }
        let envelope = try EnclaveSealedEnvelopeCodec.seal(
            plaintext: plaintext, kind: .secretKeys, associatedData: Data("fp".utf8),
            sealingKeyBlob: Data("blob".utf8), sealingPublicKeyX963: staticKey.publicKey.x963Representation,
            ephemeralPrivateKey: ephemeral, salt: Data(repeating: 0x33, count: 32), nonce: Data(repeating: 0x44, count: 12)
        )
        #expect(envelope.ciphertext.map { String(format: "%02x", $0) }.joined() == KnownAnswers.envelopeCiphertext)
        #expect(envelope.tag.map { String(format: "%02x", $0) }.joined() == KnownAnswers.envelopeTag)
    }
}

extension EnclaveSealedEnvelope {
    func with(
        associatedData: Data? = nil, sealingKeyBlob: Data? = nil, sealingPublicKeyX963: Data? = nil,
        hkdfSalt: Data? = nil, nonce: Data? = nil, ciphertext: Data? = nil, tag: Data? = nil
    ) -> EnclaveSealedEnvelope {
        EnclaveSealedEnvelope(
            magic: magic, payloadKind: payloadKind,
            associatedData: associatedData ?? self.associatedData,
            sealingKeyBlob: sealingKeyBlob ?? self.sealingKeyBlob,
            sealingPublicKeyX963: sealingPublicKeyX963 ?? self.sealingPublicKeyX963,
            ephemeralPublicKeyX963: ephemeralPublicKeyX963,
            hkdfSalt: hkdfSalt ?? self.hkdfSalt, nonce: nonce ?? self.nonce,
            ciphertext: ciphertext ?? self.ciphertext, tag: tag ?? self.tag
        )
    }
}
