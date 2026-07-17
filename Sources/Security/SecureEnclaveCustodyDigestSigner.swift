import CryptoKit
import Foundation

struct SecureEnclaveP256RawSignature: Equatable, Sendable {
    let r: Data
    let s: Data

    init(r: Data, s: Data) throws {
        guard r.count == 32, s.count == 32,
              r.contains(where: { $0 != 0 }),
              s.contains(where: { $0 != 0 }) else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
        }
        self.r = r
        self.s = s
    }
}

protocol SecureEnclaveCustodyDigestSigning: Sendable {
    func signSHA256Digest(
        _ digest: Data,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> SecureEnclaveP256RawSignature
}

struct SystemSecureEnclaveCustodyDigestSigner: SecureEnclaveCustodyDigestSigning {
    func signSHA256Digest(
        _ digest: Data,
        using handle: SecureEnclaveCustodyLoadedHandle
    ) throws -> SecureEnclaveP256RawSignature {
        guard handle.role == .signing else {
            throw SecureEnclaveCustodyHandleError.privateOperationRoleMismatch(
                expected: .signing,
                actual: handle.role
            )
        }
        guard let rawDigest = SecureEnclaveP256SHA256Digest(digest) else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
        }
        guard case .p256Signing(let privateKey)? = handle.privateKey else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
        }

        let signature: P256.Signing.ECDSASignature
        do {
            signature = try privateKey.signature(for: rawDigest)
        } catch {
            throw Self.mapEnclaveOperationError(error)
        }
        guard privateKey.publicKey.isValidSignature(signature, for: rawDigest) else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
        }

        let raw = signature.rawRepresentation
        guard raw.count == 64 else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
        }
        return try SecureEnclaveP256RawSignature(
            r: raw.prefix(32),
            s: raw.suffix(32)
        )
    }

    private static func mapEnclaveOperationError(_ error: Error) -> SecureEnclaveCustodyHandleError {
        switch SecureEnclaveCustodyAuthenticationErrorNormalizer.normalize(error) {
        case .operationCancelled:
            return .localAuthenticationCancelled(.signing)
        case .authenticationFailed:
            return .localAuthenticationFailed(.signing)
        default:
            return .privateHandleUnauthorized(.signing)
        }
    }
}

/// Carries the Rust-computed 32-byte OpenPGP SHA-256 signature digest into
/// CryptoKit's digest-signing entry point verbatim: `signature(for:)` over a
/// `Digest` signs exactly these bytes as the ECDSA message representative and
/// never re-hashes them.
struct SecureEnclaveP256SHA256Digest: Digest {
    static var byteCount: Int { 32 }

    private let bytes: [UInt8]

    init?(_ digest: Data) {
        guard digest.count == Self.byteCount else {
            return nil
        }
        self.bytes = [UInt8](digest)
    }

    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }

    func makeIterator() -> Array<UInt8>.Iterator {
        bytes.makeIterator()
    }

    var description: String {
        "SecureEnclaveP256SHA256Digest"
    }
}
