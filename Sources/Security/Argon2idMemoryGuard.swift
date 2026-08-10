import Foundation

/// Guards against Jetsam termination when importing passphrase-protected keys
/// that use Argon2id S2K with high memory parameters.
///
/// This guard applies ONLY to key import (passphrase-protected key files).
/// It does NOT apply to routine message decryption or signing (those use
/// the SE-unwrapped private key directly).
///
/// Portable Legacy keys use Iterated+Salted S2K (memoryKib=0) — the guard is a no-op.
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
    /// afford the derivation. What the format itself permits is the engine's
    /// bound (`MAX_IMPORT_ARGON2_MEMORY_KIB` in `pgp-mobile/src/keys/s2k.rs`),
    /// applied before these parameters ever reach Swift.
    ///
    /// - Parameter protectionInfo: App-owned S2K protection info parsed at the FFI boundary.
    /// - Throws: `CypherAirError.argon2idMemoryExceeded` if the memory requirement
    ///   exceeds 75% of available memory.
    func validate(protectionInfo: PGPKeyImportS2KInfo) throws {
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
/// iOS: calls os_proc_available_memory() to check Jetsam headroom.
/// macOS: returns total physical memory (no Jetsam on macOS).
struct SystemMemoryInfo: MemoryInfoProvidable {
    func availableMemoryBytes() -> UInt64 {
        #if os(macOS)
        // macOS has no Jetsam — use total physical memory.
        // The guard still rejects malformed S2K parameters that exceed physical RAM.
        return ProcessInfo.processInfo.physicalMemory
        #else
        return UInt64(_os_proc_available_memory())
        #endif
    }
}

// os_proc_available_memory() is a C function from <os/proc.h>.
// It returns the number of bytes available to the process before Jetsam
// would terminate it. Available since iOS 13.0.
// API_UNAVAILABLE(macos) — not applicable on macOS (no Jetsam).
//
// We use @_silgen_name because the function is not exposed in the
// Darwin Swift module map, and adding a bridging header for a single
// function would add unnecessary build complexity.
#if !os(macOS)
@_silgen_name("os_proc_available_memory")
private func _os_proc_available_memory() -> UInt
#endif
