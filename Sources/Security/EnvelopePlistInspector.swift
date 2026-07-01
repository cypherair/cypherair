import Foundation

/// Shared mechanism for the strict "exactly these keys" check used by the
/// self-describing envelope codecs (`PrivateKeyEnvelope`, and the ProtectedData
/// root-secret / domain-master-key / domain-payload envelopes).
///
/// Only the binary property-list parse is shared: each codec keeps its own
/// `allowedKeys` set and throws its own domain error, so the envelope formats
/// stay domain-separated and individually auditable. Folding the parse into one
/// place keeps every codec's unsupported-field rejection byte-for-byte identical.
///
/// SECURITY-CRITICAL: participates in strict envelope decoding (rejecting
/// unknown/missing fields before a payload is trusted). See SECURITY.md Section 10.
enum EnvelopePlistInspector {
    /// Returns the top-level dictionary keys of a binary property-list payload, or
    /// `nil` when the payload is not a `[String: Any]` dictionary. Throws only when
    /// the bytes are not a decodable property list.
    static func topLevelKeys(in data: Data) throws -> Set<String>? {
        var format = PropertyListSerialization.PropertyListFormat.binary
        let propertyList = try PropertyListSerialization.propertyList(
            from: data,
            options: [],
            format: &format
        )
        guard let dictionary = propertyList as? [String: Any] else {
            return nil
        }
        return Set(dictionary.keys)
    }
}
