import Foundation

struct CertificateSignatureVerification: Equatable {
    let status: CertificateSignatureVerificationStatus
    let certificationKind: OpenPGPCertificationKind?
    let signerPrimaryFingerprint: String?
    let signingKeyFingerprint: String?
    let signerIdentity: CertificateSignatureSignerIdentity?
}
