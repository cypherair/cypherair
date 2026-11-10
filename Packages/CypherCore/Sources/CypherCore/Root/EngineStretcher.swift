internal import CypherEngine
import Foundation
internal import Sealing

/// The unlock stretch, in the engine. The vault hands in the passphrase and
/// erases the result once the wrapping key has used it.
struct EngineStretcher: PassphraseStretcher {
    func stretch(passphrase: borrowing SensitiveBuffer, salt: Data, parameters: UnlockStretchParameters) throws -> SensitiveBuffer {
        // The engine borrows this copy without copying it again; it is erased
        // here once the call returns.
        var input = passphrase.withUnsafeBytes { Data($0) }
        defer { input.withUnsafeMutableBytes { sensitiveErase($0) } }
        var output = try stretchUnlockPassphrase(
            passphrase: input,
            salt: salt,
            memoryKib: parameters.memoryKiB,
            iterations: parameters.iterations,
            parallelism: parameters.parallelism
        )
        // Moves the bytes into a buffer that erases itself, and erases this
        // copy. UniFFI's own transit copy is out of reach (SECURITY.md §9).
        return SensitiveBuffer(consuming: &output)
    }
}
