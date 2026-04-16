import Foundation

struct CertificateSignatureVerification: Equatable {
    let status: CertificateSignatureStatus
    let certificationKind: CertificationKind?
    let signerPrimaryFingerprint: String?
    let signingKeyFingerprint: String?
    let signerIdentity: CertificateSignatureSignerIdentity?
}
