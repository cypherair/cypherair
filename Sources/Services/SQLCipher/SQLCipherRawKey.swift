import Foundation

enum SQLCipherRawKeyError: Error, Equatable {
    case invalidRawKeyLength(Int)
}

enum SQLCipherRawKey {
    static let rawKeyLength = 32
    static let keySpecLength = 67

    static func keySpecBytes(for rawKey: Data) throws -> [UInt8] {
        var keyBytes = [UInt8](rawKey)
        defer {
            zeroize(&keyBytes)
        }
        return try keySpecBytes(for: keyBytes)
    }

    static func keySpecBytes(for rawKey: [UInt8]) throws -> [UInt8] {
        guard rawKey.count == rawKeyLength else {
            throw SQLCipherRawKeyError.invalidRawKeyLength(rawKey.count)
        }

        let hexDigits = Array("0123456789abcdef".utf8)
        var keySpec = [UInt8]()
        keySpec.reserveCapacity(keySpecLength)
        keySpec.append(UInt8(ascii: "x"))
        keySpec.append(UInt8(ascii: "'"))
        for byte in rawKey {
            keySpec.append(hexDigits[Int(byte >> 4)])
            keySpec.append(hexDigits[Int(byte & 0x0f)])
        }
        keySpec.append(UInt8(ascii: "'"))
        return keySpec
    }

    static func zeroize(_ bytes: inout [UInt8]) {
        guard !bytes.isEmpty else { return }
        bytes.withUnsafeMutableBufferPointer { buffer in
            guard let base = buffer.baseAddress else { return }
            opaqueZero(base, buffer.count)
        }
    }
}

@_optimize(none)
private func opaqueZero(_ ptr: UnsafeMutablePointer<UInt8>, _ count: Int) {
    ptr.initialize(repeating: 0, count: count)
}
