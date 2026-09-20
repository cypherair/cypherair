import Foundation

/// Fixed Argon2id parameters for the unlock passphrase. Stored, authenticated,
/// in the sealed root's metadata; the implementation lives in the engine.
public struct UnlockStretchParameters: Codable, Equatable, Sendable {
    public static let saltLength = 16
    public static let outputLength = 32
    /// 64 MiB, three passes, one lane: far below the backup profile, and well
    /// under a second on the slowest supported device.
    public static let current = UnlockStretchParameters(memoryKiB: 65_536, iterations: 3, parallelism: 1)

    public let memoryKiB: UInt32
    public let iterations: UInt32
    public let parallelism: UInt32

    public init(memoryKiB: UInt32, iterations: UInt32, parallelism: UInt32) {
        self.memoryKiB = memoryKiB
        self.iterations = iterations
        self.parallelism = parallelism
    }
}

/// Turns the unlock passphrase into the wrapping key's application password.
/// The vault never sees Argon2id itself; the app supplies the engine-backed
/// implementation.
public protocol PassphraseStretcher: Sendable {
    func stretch(
        passphrase: borrowing SensitiveBuffer,
        salt: Data,
        parameters: UnlockStretchParameters
    ) throws -> SensitiveBuffer
}
