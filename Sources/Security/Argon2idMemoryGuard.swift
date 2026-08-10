import Foundation

/// Guards against Jetsam termination when a passphrase-protected key runs its
/// Argon2id S2K derivation — on export as well as on import. Both directions
/// derive under the same high-memory parameters and carry the same risk of the
/// process being killed part-way through.
///
/// It does NOT apply to routine message decryption or signing, which use the
/// SE-unwrapped private key directly and run no S2K at all. Portable Legacy
/// keys use Iterated+Salted S2K (memoryKib=0) in both directions, so the guard
/// is a no-op for them.
///
/// See docs/SECURITY.md Section 7.
struct Argon2idMemoryGuard {

    private let memoryInfo: any MemoryInfoProvidable

    init(memoryInfo: any MemoryInfoProvidable = SystemMemoryInfo()) {
        self.memoryInfo = memoryInfo
    }

    /// Validate that the device has sufficient memory to perform Argon2id
    /// key derivation for the given S2K parameters.
    ///
    /// This guard answers only the platform question — whether *this device* can
    /// afford the derivation, under the memory limit it has actually been
    /// granted. What the format itself permits is the engine's bound
    /// (`MAX_IMPORT_ARGON2_MEMORY_KIB` in `pgp-mobile/src/keys/s2k.rs`), applied
    /// before these parameters ever reach Swift.
    ///
    /// Failing is the only outcome when the memory is not there: the export
    /// parameters are fixed by the engine and are never weakened to fit a
    /// device, so a backup this device cannot afford to produce is one it must
    /// refuse to produce.
    ///
    /// - Parameter protectionInfo: App-owned S2K protection info, either parsed
    ///   from an incoming key at the FFI boundary or declared by the engine for
    ///   an outgoing export.
    /// - Throws: `CypherAirError.argon2idMemoryExceeded` if the memory requirement
    ///   exceeds 75% of available memory.
    func validate(protectionInfo: PGPKeyS2KInfo) throws {
        // Non-Argon2id (Portable Legacy: iterated-and-salted) — no memory check needed.
        guard protectionInfo.s2kType == .argon2id else { return }

        // memoryKib=0 means no memory requirement (shouldn't happen for argon2id,
        // but be defensive).
        guard protectionInfo.memoryKib > 0 else { return }

        // 75% threshold in integer arithmetic, avoiding floating-point rounding:
        // requiredBytes <= availableBytes * 3/4  ⟺  memoryKib * 4096 <= availableBytes * 3.
        //
        // Both products are overflow-checked rather than wrapping (&*): a wrap
        // could produce a small value and let an implausible requirement past.
        let (requiredTimesFour, requiredOverflowed) =
            protectionInfo.memoryKib.multipliedReportingOverflow(by: 4096)
        let (availableTimesThree, availableOverflowed) =
            memoryInfo.availableMemoryBytes().multipliedReportingOverflow(by: 3)

        // An overflowing requirement is beyond any conceivable device — refuse.
        // Overflowing headroom would mean more than 6 EB free — always pass.
        let exceeds: Bool
        if requiredOverflowed {
            exceeds = true
        } else if availableOverflowed {
            exceeds = false
        } else {
            exceeds = requiredTimesFour > availableTimesThree
        }

        guard !exceeds else {
            let requiredMb = protectionInfo.memoryKib / 1024
            throw CypherAirError.argon2idMemoryExceeded(requiredMb: requiredMb)
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
