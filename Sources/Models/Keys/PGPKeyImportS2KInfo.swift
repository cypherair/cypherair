import Foundation

/// How a passphrase-protected key derives its unlock key. Mapped exhaustively
/// from the engine's `S2kType` at the FFI adapter boundary, so a new or renamed
/// engine case stops the build instead of silently disabling the memory guard.
enum PGPKeyImportS2KType: Equatable, Sendable {
    case argon2id
    case iteratedSalted
    case unknown
}

struct PGPKeyImportS2KInfo: Equatable, Sendable {
    let s2kType: PGPKeyImportS2KType
    let memoryKib: UInt64
}
