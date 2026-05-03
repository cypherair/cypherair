use super::*;

/// Get the key version from binary certificate data.
pub fn get_key_version(cert_data: &[u8]) -> Result<u8, PgpError> {
    let cert = openpgp::Cert::from_bytes(cert_data).map_err(|e| PgpError::InvalidKeyData {
        reason: e.to_string(),
    })?;
    Ok(cert.primary_key().key().version())
}

/// Detect the profile of a key based on its version and algorithms.
pub fn detect_profile(cert_data: &[u8]) -> Result<KeyProfile, PgpError> {
    let version = get_key_version(cert_data)?;
    Ok(if version >= 6 {
        KeyProfile::Advanced
    } else {
        KeyProfile::Universal
    })
}
