import Foundation

/// The strict "exactly these keys" check every self-describing envelope codec
/// runs before trusting a payload (`PrivateKeyEnvelope`, and the ProtectedData
/// root-secret / domain-master-key / domain-payload envelopes).
///
/// One shared function: each codec keeps its own permitted key set — the sets
/// are genuinely different per format — and passes its format's noun for the
/// message. Sharing the check keeps every codec's unsupported-field rejection
/// byte-for-byte identical.
///
/// SECURITY-CRITICAL: participates in strict envelope decoding (rejecting
/// unknown/missing fields before a payload is trusted).
enum EnvelopePlistInspector {
    /// Throws unless `data` is a binary property-list dictionary whose top-level
    /// keys are exactly `allowed`.
    static func validateTopLevelKeys(in data: Data, allowed: Set<String>, noun: String) throws {
        guard let keys = try topLevelKeys(in: data) else {
            throw ProtectedDataError.invalidEnvelope("\(noun) is not a dictionary.")
        }
        guard keys == allowed else {
            throw ProtectedDataError.invalidEnvelope("\(noun) contains unsupported or missing fields.")
        }
    }

    /// Returns the top-level dictionary keys of a binary property-list payload, or
    /// `nil` when the payload is not a `[String: Any]` dictionary. Throws only when
    /// the bytes are not a decodable property list.
    private static func topLevelKeys(in data: Data) throws -> Set<String>? {
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
