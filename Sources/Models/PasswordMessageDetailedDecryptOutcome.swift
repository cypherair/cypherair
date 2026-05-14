import Foundation

enum PasswordMessageDetailedDecryptOutcome: Equatable {
    case decrypted(plaintext: Data, verification: DetailedSignatureVerification)
    case noSkesk
    case passwordRejected
}
