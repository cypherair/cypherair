use super::*;

/// Get the key version from binary certificate data.
pub fn get_key_version(cert_data: &[u8]) -> Result<u8, PgpError> {
    let cert = openpgp::Cert::from_bytes(cert_data).map_err(|e| PgpError::InvalidKeyData {
        reason: e.to_string(),
    })?;
    Ok(cert.primary_key().key().version())
}

/// Classify a parsed certificate into its key profile.
///
/// RFC 9980 composite primaries are Post-Quantum regardless of version
/// (they only exist on v6); any other v6 primary is Profile B; v4 is
/// Profile A. A bare key version is not enough: a v6 PQ certificate
/// must not be classified as Profile B.
pub(crate) fn classify_profile(cert: &openpgp::Cert) -> KeyProfile {
    use openpgp::types::PublicKeyAlgorithm;
    match cert.primary_key().key().pk_algo() {
        PublicKeyAlgorithm::MLDSA65_Ed25519 | PublicKeyAlgorithm::MLDSA87_Ed448 => {
            KeyProfile::PostQuantum
        }
        _ if cert.primary_key().key().version() >= 6 => KeyProfile::Advanced,
        _ => KeyProfile::Universal,
    }
}

/// Detect the profile of a key based on its version and algorithms.
pub fn detect_profile(cert_data: &[u8]) -> Result<KeyProfile, PgpError> {
    let cert = openpgp::Cert::from_bytes(cert_data).map_err(|e| PgpError::InvalidKeyData {
        reason: e.to_string(),
    })?;
    Ok(classify_profile(&cert))
}
