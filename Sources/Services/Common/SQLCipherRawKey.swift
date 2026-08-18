import Foundation

enum SQLCipherRawKeyError: Error, Equatable {
    case invalidRawKeyLength(Int)
}

/// The raw-key literal SQLCipher takes in place of a passphrase: `x'<64 hex
/// digits>'`, which keys the database directly with no KDF in between.
enum SQLCipherRawKey {
    static let rawKeyLength = 32
    static let keySpecLength = 67

    /// Render `rawKey` as the key-spec literal, in storage that erases itself
    /// when the caller releases it.
    ///
    /// The literal is as secret as the key it spells out — it is the key, hex
    /// encoded — so it is built straight into a `SensitiveBuffer` rather than
    /// through an intermediate array the caller would have to remember to
    /// scrub.
    static func keySpec(for rawKey: Data) throws -> SensitiveBuffer {
        guard rawKey.count == rawKeyLength else {
            throw SQLCipherRawKeyError.invalidRawKeyLength(rawKey.count)
        }

        let hexDigits = Array("0123456789abcdef".utf8)
        return SensitiveBuffer(count: keySpecLength) { destination in
            destination[0] = UInt8(ascii: "x")
            destination[1] = UInt8(ascii: "'")
            // `enumerated` counts from zero whatever `rawKey`'s own indices are.
            for (offset, byte) in rawKey.enumerated() {
                destination[2 + offset * 2] = hexDigits[Int(byte >> 4)]
                destination[3 + offset * 2] = hexDigits[Int(byte & 0x0f)]
            }
            destination[keySpecLength - 1] = UInt8(ascii: "'")
        }
    }
}
