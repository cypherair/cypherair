import Foundation

/// The one answer to "can this process afford an Argon2id derivation right
/// now", for every path where one is about to run.
///
/// Three of them exist: passphrase-protected key export, passphrase-protected
/// key import, and opening a password-encrypted message. The first two derive
/// under parameters we chose and are checked here, by `validate`. The third
/// derives under the *sender's* parameters, so the budget travels into the
/// engine instead (`affordableMemoryKib`) and is applied per password slot,
/// where the alternative candidates are.
///
/// Routine message decryption and signing run no S2K at all, and Portable
/// Legacy keys use Iterated+Salted S2K (memoryKib=0) in both directions, so
/// neither reaches this type.
///
/// See docs/SECURITY.md Section 7.
struct Argon2idMemoryGuard {

    private let memoryInfo: any MemoryInfoProvidable

    init(memoryInfo: any MemoryInfoProvidable = SystemMemoryInfo()) {
        self.memoryInfo = memoryInfo
    }

    /// The largest Argon2id memory cost this process can afford to dirty right
    /// now: 75% of the headroom under the memory limit it has actually been
    /// granted, leaving the remaining quarter for everything else the app is
    /// holding while the derivation runs.
    ///
    /// Momentary by nature — `MemoryInfoProvidable` documents the figure as
    /// advisory and invalidated by allocating work — so it is read per
    /// operation and never cached.
    func affordableMemoryKib() -> UInt64 {
        // Integer arithmetic throughout, avoiding floating-point rounding:
        // affordableKib = availableBytes * 3 / 4096, where 4096 = 1024 × 4.
        // Overflow-checked rather than wrapping (&*): a wrap could produce a
        // small value and turn abundant headroom into a refusal.
        let (availableTimesThree, overflowed) =
            memoryInfo.availableMemoryBytes().multipliedReportingOverflow(by: 3)
        // More than 6 EB of headroom is not a real device; treat it as unbounded.
        return overflowed ? .max : availableTimesThree / 4096
    }

    /// Refuse a key-protection derivation this device cannot afford.
    ///
    /// This guard answers only the platform question. What the format itself
    /// permits is the engine's bound (`MAX_IMPORT_ARGON2_MEMORY_KIB` in
    /// `pgp-mobile/src/keys/s2k.rs`), applied before these parameters ever
    /// reach Swift.
    ///
    /// Failing is the only outcome when the memory is not there: the export
    /// parameters are fixed by the engine and are never weakened to fit a
    /// device, so a backup this device cannot afford to produce is one it must
    /// refuse to produce.
    ///
    /// - Parameter protectionInfo: App-owned S2K protection info, either parsed
    ///   from an incoming key at the FFI boundary or declared by the engine for
    ///   an outgoing export.
    /// - Throws: `CypherAirError.argon2idMemoryExceeded` if the memory
    ///   requirement exceeds what `affordableMemoryKib()` allows.
    func validate(protectionInfo: PGPKeyS2KInfo) throws {
        // Non-Argon2id (Portable Legacy: iterated-and-salted) — no memory check needed.
        guard protectionInfo.s2kType == .argon2id else { return }

        // memoryKib=0 means no memory requirement (shouldn't happen for argon2id,
        // but be defensive).
        guard protectionInfo.memoryKib > 0 else { return }

        guard protectionInfo.memoryKib <= affordableMemoryKib() else {
            throw CypherAirError.argon2idMemoryExceeded(requiredMb: protectionInfo.memoryKib / 1024)
        }
    }
}

/// Production implementation of MemoryInfoProvidable.
struct SystemMemoryInfo: MemoryInfoProvidable {
    func availableMemoryBytes() -> UInt64 {
        #if os(macOS)
        // macOS applies no per-process dirty-memory limit and has no Jetsam, so
        // there is no granted limit to read — physical memory is the ceiling
        // that matters, and the guard still refuses requirements beyond it.
        return ProcessInfo.processInfo.physicalMemory
        #else
        return UInt64(_os_proc_available_memory())
        #endif
    }
}

// os_proc_available_memory() is a C function from <os/proc.h>, available on
// iOS/iPadOS/visionOS and declared API_UNAVAILABLE(macos).
//
// It reports the bytes remaining before the process hits its *current* dirty
// memory limit — the limit the system has actually granted this process, which
// is what makes it the right probe here: `increased-memory-limit` raises that
// limit only on device models that support it, so reading the granted figure is
// the only honest way to learn whether the 2 GiB derivation fits. Apple
// documents the value as advisory and invalidated by any allocating work, so it
// is read per operation and never cached. It returns 0 for a process that is
// not an app or has already exceeded its limit, which fails the check closed.
//
// We use @_silgen_name because the function is not exposed in the
// Darwin Swift module map, and adding a bridging header for a single
// function would add unnecessary build complexity.
#if !os(macOS)
@_silgen_name("os_proc_available_memory")
private func _os_proc_available_memory() -> UInt
#endif
