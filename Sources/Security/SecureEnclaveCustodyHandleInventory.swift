import Foundation

/// One non-prompting sweep of every stored custody handle row: the decodable
/// public bindings, plus the count of app-owned rows that no longer decode
/// (foreign or corrupted rows under the custody service namespaces).
struct SecureEnclaveCustodyHandleInventory: Sendable {
    let bindings: [SecureEnclaveCustodyHandlePublicBinding]
    let malformedRowCount: Int

    static let empty = SecureEnclaveCustodyHandleInventory(bindings: [], malformedRowCount: 0)

    var totalRowCount: Int {
        bindings.count + malformedRowCount
    }
}
