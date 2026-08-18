import Foundation

/// The engine's verdict on one certificate signature. Every member describes the
/// signature itself; who the signer is to the user, and whether their word
/// carries any weight, is resolved separately and live —
/// `ContactCertificationSignerResolver` and `ContactCertificationTrustWeb`.
struct CertificateSignatureVerification: Equatable {
    let status: CertificateSignatureVerificationStatus
    let certificationKind: OpenPGPCertificationKind?
    let signerPrimaryFingerprint: String?
    let signingKeyFingerprint: String?
}
