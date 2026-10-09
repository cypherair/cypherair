import Foundation
import Sealing

/// The unlock passphrase stretch, performed by the engine's Argon2id.
struct EngineStretcher: PassphraseStretcher {
    let engine: PgpEngine

    func stretch(
        passphrase: borrowing SensitiveBuffer,
        salt: Data,
        parameters: UnlockStretchParameters
    ) throws -> SensitiveBuffer {
        var input = passphrase.withUnsafeBytes { Data($0) }
        defer { input.withUnsafeMutableBytes { sensitiveErase($0) } }
        var output = try engine.deriveUnlockSecret(
            passphrase: input,
            salt: salt,
            memoryKib: parameters.memoryKiB,
            iterations: parameters.iterations,
            parallelism: parameters.parallelism
        )
        return SensitiveBuffer(consuming: &output)
    }
}
