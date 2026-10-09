import CryptoKit
import Foundation
import LocalAuthentication
import Sealing

/// The six enclave key types device-bound custody uses. ML-KEM keys are the one
/// exception to the application-password rule, because the enclave cannot
/// decapsulate under the option.
public enum CustodyKeyType: String, Sendable, CaseIterable, Codable {
    case p256Signing
    case p256KeyAgreement
    case mldsa65
    case mldsa87
    case mlkem768
    case mlkem1024

    public var policy: EnclaveAccessPolicy {
        switch self {
        case .mlkem768, .mlkem1024: .biometricOnly
        default: .biometricAndPassword
        }
    }
}

/// A device-bound custody key inside the enclave. Only the operation its type
/// supports succeeds; the others throw.
public protocol EnclaveCustodyKey {
    var type: CustodyKeyType { get }
    var dataRepresentation: Data { get }
    /// P-256: the X9.63 public key. ML-DSA and ML-KEM: the raw public key.
    var publicKeyRaw: Data { get }
    /// P-256 signing: `input` is a 32-byte SHA-256 digest and the result is r‖s.
    /// ML-DSA: `input` is the message and the result is the signature.
    func signature(for input: Data) throws -> Data
    /// P-256 key agreement: the raw 32-byte shared secret.
    func sharedSecret(withEphemeralPublicKeyX963 x963: Data) throws -> SensitiveBuffer
    /// ML-KEM: the shared secret for `ciphertext`.
    func decapsulate(_ ciphertext: Data) throws -> SensitiveBuffer
}

/// A 32-byte SHA-256 digest computed elsewhere, presented to CryptoKit's
/// digest-signing API.
public struct RawSHA256Digest: Digest {
    public static var byteCount: Int { 32 }
    private let bytes: [UInt8]

    public init?(_ data: Data) {
        guard data.count == Self.byteCount else { return nil }
        bytes = Array(data)
    }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }

    public func makeIterator() -> Array<UInt8>.Iterator { bytes.makeIterator() }
    public var description: String { "SHA256 digest" }
    public func hash(into hasher: inout Hasher) { hasher.combine(bytes) }
    public static func == (lhs: RawSHA256Digest, rhs: RawSHA256Digest) -> Bool { lhs.bytes == rhs.bytes }
}

extension SymmetricKey {
    /// Moves the key's bytes into a sensitive buffer.
    func sensitiveBytes() -> SensitiveBuffer {
        SensitiveBuffer(count: bitCount / 8) { destination in
            withUnsafeBytes { destination.copyMemory(from: $0) }
        }
    }
}

extension SharedSecret {
    func sensitiveBytes() -> SensitiveBuffer {
        let count = withUnsafeBytes { $0.count }
        return SensitiveBuffer(count: count) { destination in
            withUnsafeBytes { destination.copyMemory(from: $0) }
        }
    }
}
