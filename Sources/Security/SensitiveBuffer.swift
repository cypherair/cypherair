import Foundation

/// The app's one erase primitive: overwrite `region` with zeros before the
/// caller releases the memory behind it.
///
/// `@_optimize(none)` is the barrier. A zeroing store into memory that is never
/// read again is dead by the optimizer's rules, and `-O -wmo` is entitled to
/// delete it; the attribute puts this body out of the optimizer's reach and keeps
/// it from being inlined into optimized callers. `memset_s` carries the same
/// guarantee inside the C library, so the write survives on its own merits even
/// if the attribute ever stops meaning what it means today.
@_optimize(none)
func sensitiveErase(_ region: UnsafeMutableRawBufferPointer) {
    // A null base is the one input `memset_s` will not take; a zero length it
    // handles on its own, so an empty region needs no separate guard.
    guard let base = region.baseAddress else { return }
    memset_s(base, rsize_t(region.count), 0, rsize_t(region.count))
}

/// The sole owner of a run of secret bytes.
///
/// Being `~Copyable` is the entire point. A secret held here cannot be copied,
/// so it cannot outlive its owner behind the owner's back, and `deinit` erases
/// the one copy that exists. `Data` cannot do this: it is copy-on-write, so
/// zeroizing one of two sharing values clears a copy Foundation makes for the
/// occasion while the secret stays intact in the other — which is not a
/// hypothetical, but the mechanism behind the leaks this type exists to end.
/// `SensitiveBufferTests.test_copyOnWriteData_cannotBeZeroized` holds that
/// physics down in executable form.
///
/// The omissions are load-bearing. There is no `dataCopy()`, no `var data`, and
/// no `Equatable`/`Codable`/`CustomStringConvertible`/`Sendable` conformance,
/// because every one of them would hand the bytes out as a value that this
/// buffer no longer controls. Reads go through the scoped accessors, whose
/// lifetime the buffer does control. Code that tries to copy a secret does not
/// compile, and that — not a convention, not a review checklist — is the
/// enforcement.
struct SensitiveBuffer: ~Copyable {
    /// Storage is allocated eagerly and owned outright: no sharing, no
    /// reference counting, nothing else that could keep the bytes alive past
    /// `deinit`. Raw bytes need no particular alignment; 16 is what `malloc` — and
    /// so `Data` — hands back, so nothing downstream inherits a weaker guarantee
    /// than it has today.
    private let storage: UnsafeMutableRawBufferPointer

    var count: Int { storage.count }
    var isEmpty: Bool { storage.isEmpty }

    /// Allocates `count` zeroed bytes and hands them to `body` to fill.
    ///
    /// The zero fill is not redundant with the fill closure: it makes a partial
    /// fill deterministic instead of leaving whatever the allocator handed back
    /// readable through the accessors.
    init<E: Error>(
        count: Int,
        filling body: (UnsafeMutableRawBufferPointer) throws(E) -> Void
    ) throws(E) {
        let storage = UnsafeMutableRawBufferPointer.allocate(byteCount: count, alignment: 16)
        storage.initializeMemory(as: UInt8.self, repeating: 0)
        do {
            try body(storage)
        } catch {
            // `self` was never fully initialized, so `deinit` will not run for
            // this allocation; erase and release it here or the failed fill
            // leaks whatever it managed to write.
            sensitiveErase(storage)
            storage.deallocate()
            throw error
        }
        self.storage = storage
    }

    /// Takes the bytes of `data` and leaves the source erased. This is the one
    /// bridge from `Data` into the type.
    ///
    /// It is only ever as good as the caller's ownership. Erasing a `Data` whose
    /// buffer is shared with another value clears a copy Foundation makes on the
    /// spot and leaves the original bytes untouched elsewhere; `inout` does not
    /// establish uniqueness and never did. Hand over a `Data` you uniquely own.
    /// Each stage that converts a producer to vend a `SensitiveBuffer` directly
    /// removes callers of this initializer, and with them the exposure.
    init(consuming data: inout Data) {
        self.init(count: data.count) { destination in
            destination.copyBytes(from: data)
        }
        data.withUnsafeMutableBytes { sensitiveErase($0) }
    }

    borrowing func withUnsafeBytes<R: ~Copyable, E: Error>(
        _ body: (UnsafeRawBufferPointer) throws(E) -> R
    ) throws(E) -> R {
        try body(UnsafeRawBufferPointer(storage))
    }

    borrowing func withUnsafeMutableBytes<R: ~Copyable, E: Error>(
        _ body: (UnsafeMutableRawBufferPointer) throws(E) -> R
    ) throws(E) -> R {
        try body(storage)
    }

    deinit {
        sensitiveErase(storage)
        storage.deallocate()
    }
}

/// A `SensitiveBuffer` in a place that requires a reference: a dictionary value,
/// the state of an `OSAllocatedUnfairLock`, the result of an escaping closure.
/// Deallocating the box runs the buffer's `deinit`, so erasure still happens by
/// ownership rather than by a hand-written `defer`.
///
/// The `@unchecked Sendable` buys reachability across isolation domains and
/// nothing else. The buffer's bytes are unsynchronized memory, so a box reachable
/// from two writers has to be serialized by whatever holds it — which is what the
/// lock and the isolated caches this box exists for already do.
final class SensitiveKeyBox: @unchecked Sendable {
    let buffer: SensitiveBuffer

    init(_ buffer: consuming SensitiveBuffer) {
        self.buffer = buffer
    }
}
