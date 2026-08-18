use super::*;

/// Get the key version from binary certificate data.
///
/// Not FFI-exported: crate tests use it as the parse-side oracle for the
/// version a generated certificate actually carries.
pub fn get_key_version(cert_data: &[u8]) -> Result<u8, PgpError> {
    let cert = openpgp::Cert::from_bytes(cert_data).map_err(|e| PgpError::InvalidKeyData {
        reason: e.to_string(),
    })?;
    Ok(cert.primary_key().key().version())
}

/// Classify a parsed certificate into its key suite, or refuse.
///
/// The certificate is the only authority on what it is: the primary-key
/// algorithm, its curve, and the certificate version must all agree with
/// exactly one suite, and a certificate that matches none — an algorithm
/// outside the vocabulary, a curve the named algorithm does not pin, or an
/// algorithm on a certificate version it does not belong to — is `None`,
/// never approximated to a nearby suite. NIST P-256 is why the version is
/// consulted for recognised algorithms too: ECDSA/ECDH keep their algorithm
/// ids across certificate versions, so only the version separates the v4 and
/// v6 P-256 suites.
pub(crate) fn classify_suite(cert: &openpgp::Cert) -> Option<KeySuite> {
    use openpgp::crypto::mpi::PublicKey;
    use openpgp::types::{Curve, PublicKeyAlgorithm};

    let key = cert.primary_key().key();
    match (key.pk_algo(), key.version()) {
        (PublicKeyAlgorithm::MLDSA65_Ed25519, 6) => Some(KeySuite::MlDsa65Ed25519MlKem768X25519),
        (PublicKeyAlgorithm::MLDSA87_Ed448, 6) => Some(KeySuite::MlDsa87Ed448MlKem1024X448),
        (PublicKeyAlgorithm::Ed25519, 6) => Some(KeySuite::Ed25519X25519),
        (PublicKeyAlgorithm::Ed448, 6) => Some(KeySuite::Ed448X448),
        (PublicKeyAlgorithm::EdDSA, 4) => match key.mpis() {
            PublicKey::EdDSA {
                curve: Curve::Ed25519,
                ..
            } => Some(KeySuite::Ed25519LegacyCurve25519Legacy),
            _ => None,
        },
        (PublicKeyAlgorithm::ECDSA, 4) => match key.mpis() {
            PublicKey::ECDSA {
                curve: Curve::NistP256,
                ..
            } => Some(KeySuite::EcdsaNistP256EcdhNistP256V4),
            _ => None,
        },
        (PublicKeyAlgorithm::ECDSA, 6) => match key.mpis() {
            PublicKey::ECDSA {
                curve: Curve::NistP256,
                ..
            } => Some(KeySuite::EcdsaNistP256EcdhNistP256),
            _ => None,
        },
        _ => None,
    }
}

/// Classify binary certificate data into its suite, or `None` when the
/// certificate cannot be placed.
///
/// Not FFI-exported: production callers read `KeyInfo::suite`; crate tests
/// use this as the classification oracle beside `get_key_version`.
pub fn detect_suite(cert_data: &[u8]) -> Result<Option<KeySuite>, PgpError> {
    let cert = openpgp::Cert::from_bytes(cert_data).map_err(|e| PgpError::InvalidKeyData {
        reason: e.to_string(),
    })?;
    Ok(classify_suite(&cert))
}
