import Foundation

struct PGPKeyImportS2KInfo: Equatable, Sendable {
    let s2kType: String
    let memoryKib: UInt64
}
