import Foundation

/// Overwrites `region` with zeros before the caller releases the memory behind it.
///
/// `@_optimize(none)` is the barrier: a zeroing store into memory that is never
/// read again is dead by the optimizer's rules, and `-O -wmo` is entitled to
/// delete it. `memset_s` carries the same guarantee inside the C library.
@_optimize(none)
public func sensitiveErase(_ region: UnsafeMutableRawBufferPointer) {
    guard let base = region.baseAddress else { return }
    memset_s(base, rsize_t(region.count), 0, rsize_t(region.count))
}

/// The sole owner of a run of secret bytes.
///
/// Being `~Copyable` is the point: a secret held here cannot be copied, so it
/// cannot outlive its owner, and `deinit` erases the one copy that exists.
/// There is deliberately no way to get the bytes out as a value; reads go
/// through the scoped accessors.
public struct SensitiveBuffer: ~Copyable {
    private let storage: UnsafeMutableRawBufferPointer

    public var count: Int { storage.count }
    public var isEmpty: Bool { storage.isEmpty }

    /// Allocates `count` zeroed bytes and hands them to `body` to fill. A failed
    /// fill erases and releases the allocation before rethrowing.
    public init<E: Error>(
        count: Int,
        filling body: (UnsafeMutableRawBufferPointer) throws(E) -> Void
    ) throws(E) {
        let storage = UnsafeMutableRawBufferPointer.allocate(byteCount: count, alignment: 16)
        storage.initializeMemory(as: UInt8.self, repeating: 0)
        do {
            try body(storage)
        } catch {
            sensitiveErase(storage)
            storage.deallocate()
            throw error
        }
        self.storage = storage
    }

    /// Takes the bytes of `data` and leaves the source erased. Only as good as
    /// the caller's ownership: erasing a `Data` whose buffer is shared clears a
    /// copy and leaves the original elsewhere. Hand over a `Data` you uniquely own.
    public init(consuming data: inout Data) {
        self.init(count: data.count) { destination in
            destination.copyBytes(from: data)
        }
        data.withUnsafeMutableBytes { sensitiveErase($0) }
    }

    public borrowing func withUnsafeBytes<R: ~Copyable, E: Error>(
        _ body: (UnsafeRawBufferPointer) throws(E) -> R
    ) throws(E) -> R {
        try body(UnsafeRawBufferPointer(storage))
    }

    public borrowing func withUnsafeMutableBytes<R: ~Copyable, E: Error>(
        _ body: (UnsafeMutableRawBufferPointer) throws(E) -> R
    ) throws(E) -> R {
        try body(storage)
    }

    /// Constant-time equality, for tests and for verifying a derived value.
    public borrowing func contentEquals(_ other: borrowing SensitiveBuffer) -> Bool {
        guard count == other.count else { return false }
        return withUnsafeBytes { mine in
            other.withUnsafeBytes { theirs in
                var difference: UInt8 = 0
                for index in 0..<mine.count {
                    difference |= mine[index] ^ theirs[index]
                }
                return difference == 0
            }
        }
    }

    deinit {
        sensitiveErase(storage)
        storage.deallocate()
    }
}

/// A `SensitiveBuffer` behind a reference, for places that need one: a dictionary
/// value, lock state, an escaping closure. Deallocating the box erases the buffer.
///
/// `@unchecked Sendable` buys reachability across isolation domains and nothing
/// else; whatever holds the box serializes access to it.
public final class SensitiveKeyBox: @unchecked Sendable {
    public let buffer: SensitiveBuffer

    public init(_ buffer: consuming SensitiveBuffer) {
        self.buffer = buffer
    }
}
