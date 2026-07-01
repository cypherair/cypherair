import Foundation

// Big-endian byte encodings of fixed-width integers.
//
// Used to build the length-prefixed binding data (HKDF `sharedInfo` and AES-GCM
// AAD) shared by the self-describing envelope codecs. Centralized so every
// envelope format encodes integer fields identically; the individual codecs stay
// domain-separated through their own magic / prefixes, not their integer encoding.

extension UInt16 {
    var bigEndianData: Data {
        withUnsafeBytes(of: bigEndian) { Data($0) }
    }
}

extension UInt32 {
    var bigEndianData: Data {
        withUnsafeBytes(of: bigEndian) { Data($0) }
    }
}

extension UInt64 {
    var bigEndianData: Data {
        withUnsafeBytes(of: bigEndian) { Data($0) }
    }
}
