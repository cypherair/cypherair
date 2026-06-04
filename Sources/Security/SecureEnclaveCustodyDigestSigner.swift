import Foundation
import Security

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
        guard digest.count == 32 else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
        }
        guard let privateKey = handle.privateKey,
              let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SecureEnclaveCustodyHandleError.privateHandleMissing(.signing)
        }

        if SecKeyIsAlgorithmSupported(privateKey, .sign, .ecdsaSignatureDigestRFC4754),
           SecKeyIsAlgorithmSupported(publicKey, .verify, .ecdsaSignatureDigestRFC4754) {
            let signature = try makeSignature(
                digest: digest,
                privateKey: privateKey,
                publicKey: publicKey,
                algorithm: .ecdsaSignatureDigestRFC4754
            )
            guard signature.count == 64 else {
                throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
            }
            return try SecureEnclaveP256RawSignature(
                r: signature.prefix(32),
                s: signature.suffix(32)
            )
        }

        let derSignature = try makeSignature(
            digest: digest,
            privateKey: privateKey,
            publicKey: publicKey,
            algorithm: .ecdsaSignatureDigestX962SHA256
        )
        return try Self.rawSignatureFromDER(derSignature)
    }

    private func makeSignature(
        digest: Data,
        privateKey: SecKey,
        publicKey: SecKey,
        algorithm: SecKeyAlgorithm
    ) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            algorithm,
            digest as CFData,
            &error
        ) as Data? else {
            throw Self.mapCFError(error)
        }
        guard SecKeyVerifySignature(
            publicKey,
            algorithm,
            digest as CFData,
            signature as CFData,
            &error
        ) else {
            throw Self.mapCFError(error)
        }
        return signature
    }

    static func rawSignatureFromDER(_ der: Data) throws -> SecureEnclaveP256RawSignature {
        let bytes = [UInt8](der)
        var index = 0

        func readByte() throws -> UInt8 {
            guard index < bytes.count else {
                throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
            }
            defer { index += 1 }
            return bytes[index]
        }

        func readLength() throws -> Int {
            let first = try readByte()
            if first < 0x80 {
                return Int(first)
            }
            let lengthByteCount = Int(first & 0x7f)
            guard lengthByteCount > 0, lengthByteCount <= 2 else {
                throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
            }
            var length = 0
            for _ in 0..<lengthByteCount {
                length = (length << 8) | Int(try readByte())
            }
            return length
        }

        func readInteger() throws -> Data {
            guard try readByte() == 0x02 else {
                throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
            }
            let length = try readLength()
            guard length > 0, index + length <= bytes.count else {
                throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
            }
            let value = Array(bytes[index..<(index + length)])
            index += length
            let stripped = value.drop(while: { $0 == 0 })
            guard stripped.count <= 32 else {
                throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
            }
            var padded = Data(repeating: 0, count: 32 - stripped.count)
            padded.append(contentsOf: stripped)
            return padded
        }

        guard try readByte() == 0x30 else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
        }
        let sequenceLength = try readLength()
        guard index + sequenceLength == bytes.count else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
        }
        let r = try readInteger()
        let s = try readInteger()
        guard index == bytes.count else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
        }
        return try SecureEnclaveP256RawSignature(r: r, s: s)
    }

    private static func mapCFError(
        _ error: Unmanaged<CFError>?
    ) -> SecureEnclaveCustodyHandleError {
        SecureEnclaveCustodyOSStatusMapper.handleError(for: error, role: .signing)
    }
}
