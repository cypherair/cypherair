import Foundation

enum CertificateSignatureVerificationStatus: Equatable, Hashable, Sendable {
    case valid
    case invalid
    case signerMissing
}
