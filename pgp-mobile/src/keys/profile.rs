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
/// Classification is by primary-key algorithm, because a bare key version is
/// ambiguous: v6 carries the baseline classical (Ed25519 → Modern), the high
/// classical (Ed448 → Advanced), and both RFC 9980 composite tiers. The
/// composite primaries (ML-DSA-65+Ed25519, ML-DSA-87+Ed448) only exist on v6
/// and each map to their own post-quantum tier. v4 Curve25519 signs with
/// EdDSALegacy and falls through to Universal.
pub(crate) fn classify_profile(cert: &openpgp::Cert) -> KeyProfile {
    use openpgp::types::PublicKeyAlgorithm;
    match cert.primary_key().key().pk_algo() {
        PublicKeyAlgorithm::MLDSA65_Ed25519 => KeyProfile::PostQuantum,
        PublicKeyAlgorithm::MLDSA87_Ed448 => KeyProfile::PostQuantumHigh,
        PublicKeyAlgorithm::Ed25519 => KeyProfile::Modern,
        PublicKeyAlgorithm::Ed448 => KeyProfile::Advanced,
        // Defensive: any other v6 primary is treated as the high classical
        // tier; anything else (v4 EdDSALegacy, etc.) is Universal.
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
