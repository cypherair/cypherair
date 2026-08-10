import Foundation

/// How a passphrase-protected key derives its unlock key. Mapped exhaustively
/// from the engine's `S2kType` at the FFI adapter boundary, so a new or renamed
/// engine case stops the build instead of silently disabling the memory guard.
enum PGPKeyS2KType: Equatable, Sendable {
    case argon2id
    case iteratedSalted
    case unknown
}

/// The S2K parameters of a passphrase-protected key — either the ones an
/// incoming key file declares, or the ones an outgoing export will derive under.
struct PGPKeyS2KInfo: Equatable, Sendable {
    let s2kType: PGPKeyS2KType
    let memoryKib: UInt64
}
