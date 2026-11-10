import Foundation
import os

/// Where the sealed domain files live: whole files by name, each replaced
/// atomically. Production is `ProtectedDataDirectory`; the software composition
/// keeps the files in memory.
public protocol DomainFiles: Sendable {
    func read(_ name: String) throws(StoreError) -> Data?
    /// Replaces the file's bytes. A crash leaves the old bytes or the new ones,
    /// never a mix.
    func replace(_ name: String, with data: Data) throws(StoreError)
    /// Removes every file. Part of Reset All Local Data.
    func eraseAll() throws(StoreError)
}

/// Domain files held in memory. Nothing reaches the disk.
public final class InMemoryDomainFiles: DomainFiles, @unchecked Sendable {
    private let files = OSAllocatedUnfairLock<[String: Data]>(initialState: [:])

    public init() {}

    public func read(_ name: String) throws(StoreError) -> Data? { files.withLock { $0[name] } }

    public func replace(_ name: String, with data: Data) throws(StoreError) { files.withLock { $0[name] = data } }

    public func delete(_ name: String) { files.withLock { $0[name] = nil } }

    public func eraseAll() throws(StoreError) { files.withLock { $0.removeAll() } }
}
