import Foundation
import Security

extension UInt16 {
    var bigEndianData: Data { withUnsafeBytes(of: bigEndian) { Data($0) } }
}

extension UInt32 {
    var bigEndianData: Data { withUnsafeBytes(of: bigEndian) { Data($0) } }
}

extension UInt64 {
    var bigEndianData: Data { withUnsafeBytes(of: bigEndian) { Data($0) } }
}

extension Data {
    /// Appends `value` as a big-endian 16-bit length followed by its bytes.
    mutating func appendLengthPrefixed(_ value: Data) {
        append(UInt16(value.count).bigEndianData)
        append(value)
    }
}

enum Randomness {
    static func bytes(count: Int) throws(SealingError) -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw SealingError.randomnessUnavailable
        }
        return data
    }
}

/// Binary property-list encoding whose decoder accepts exactly one set of keys.
/// Every envelope goes through this, so an unknown or missing field is rejected
/// before any payload is trusted.
enum StrictPropertyList {
    static func encode<T: Encodable>(_ value: T) throws(SealingError) -> Data {
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        do {
            return try encoder.encode(value)
        } catch {
            throw SealingError.internalFailure("property-list encoding failed")
        }
    }

    static func decode<T: Decodable>(
        _ type: T.Type,
        from data: Data,
        allowedKeys: Set<String>
    ) throws(SealingError) -> T {
        let keys: Set<String>
        do {
            var format = PropertyListSerialization.PropertyListFormat.binary
            let object = try PropertyListSerialization.propertyList(from: data, options: [], format: &format)
            guard let dictionary = object as? [String: Any] else {
                throw SealingError.malformed("not a dictionary")
            }
            keys = Set(dictionary.keys)
        } catch let error as SealingError {
            throw error
        } catch {
            throw SealingError.malformed("not a property list")
        }
        guard keys == allowedKeys else {
            throw SealingError.malformed("unsupported or missing fields")
        }
        do {
            return try PropertyListDecoder().decode(type, from: data)
        } catch {
            throw SealingError.malformed("fields of the wrong type")
        }
    }
}
