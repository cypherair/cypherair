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

/// Classify a parsed certificate into its key suite.
///
/// Classification is by primary-key algorithm, because a bare key version is
/// ambiguous: v6 carries the baseline classical (Ed25519), the high classical
/// (Ed448), and both RFC 9980 composite tiers. The composite primaries
/// (ML-DSA-65+Ed25519, ML-DSA-87+Ed448) only exist on v6 and each map to
/// their own post-quantum tier. v4 Curve25519 signs with EdDSALegacy and
/// falls through to the legacy suite.
pub(crate) fn classify_suite(cert: &openpgp::Cert) -> KeySuite {
    use openpgp::types::PublicKeyAlgorithm;
    match cert.primary_key().key().pk_algo() {
        PublicKeyAlgorithm::MLDSA65_Ed25519 => KeySuite::MlDsa65Ed25519MlKem768X25519,
        PublicKeyAlgorithm::MLDSA87_Ed448 => KeySuite::MlDsa87Ed448MlKem1024X448,
        PublicKeyAlgorithm::Ed25519 => KeySuite::Ed25519X25519,
        PublicKeyAlgorithm::Ed448 => KeySuite::Ed448X448,
        // Defensive: any other v6 primary is treated as the high classical
        // tier; anything else (v4 EdDSALegacy, etc.) is the legacy suite.
        _ if cert.primary_key().key().version() >= 6 => KeySuite::Ed448X448,
        _ => KeySuite::Ed25519LegacyCurve25519Legacy,
    }
}

/// Detect the suite of a key based on its version and algorithms.
pub fn detect_suite(cert_data: &[u8]) -> Result<KeySuite, PgpError> {
    let cert = openpgp::Cert::from_bytes(cert_data).map_err(|e| PgpError::InvalidKeyData {
        reason: e.to_string(),
    })?;
    Ok(classify_suite(&cert))
}
