import Foundation

/// Guards against Jetsam termination when importing passphrase-protected keys
/// that use Argon2id S2K with high memory parameters.
///
/// This guard applies ONLY to key import (passphrase-protected key files).
/// It does NOT apply to routine message decryption or signing (those use
/// the SE-unwrapped private key directly).
///
/// Profile A keys use Iterated+Salted S2K (memoryKib=0) — the guard is a no-op.
///
/// See SECURITY.md Section 5, TDD Section 4.
struct Argon2idMemoryGuard {

    private let memoryInfo: any MemoryInfoProvidable

    init(memoryInfo: any MemoryInfoProvidable = SystemMemoryInfo()) {
        self.memoryInfo = memoryInfo
    }

    /// Validate that the device has sufficient memory to perform Argon2id
    /// key derivation for the given S2K parameters.
    ///
    /// - Parameter s2kInfo: The parsed S2K parameters from the key file.
    /// - Throws: `PgpError.Argon2idMemoryExceeded` if memory requirement
    ///   exceeds 75% of available memory.
    func validate(s2kInfo: S2kInfo) throws {
        // Non-Argon2id (Profile A: "iterated-salted") — no memory check needed.
        guard s2kInfo.s2kType == "argon2id" else { return }

        // memoryKib=0 means no memory requirement (shouldn't happen for argon2id,
        // but be defensive).
        guard s2kInfo.memoryKib > 0 else { return }

        let requiredBytes = s2kInfo.memoryKib * 1024
        let availableBytes = memoryInfo.availableMemoryBytes()

        // 75% threshold using integer arithmetic to avoid floating-point rounding.
        // required <= available * 3/4  ⟺  required * 4 <= available * 3
        guard requiredBytes &* 4 <= availableBytes &* 3 else {
            let requiredMb = s2kInfo.memoryKib / 1024
            throw PgpError.Argon2idMemoryExceeded(requiredMb: requiredMb)
        }
    }
}

/// Production implementation of MemoryInfoProvidable.
/// Calls os_proc_available_memory() via @_silgen_name.
struct SystemMemoryInfo: MemoryInfoProvidable {
    func availableMemoryBytes() -> UInt64 {
        UInt64(_os_proc_available_memory())
    }
}

// os_proc_available_memory() is a C function from <os/proc.h>.
// It returns the number of bytes available to the process before Jetsam
// would terminate it. Available since iOS 13.0.
//
// We use @_silgen_name because the function is not exposed in the
// Darwin Swift module map, and adding a bridging header for a single
// function would add unnecessary build complexity.
@_silgen_name("os_proc_available_memory")
private func _os_proc_available_memory() -> UInt
