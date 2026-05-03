use super::*;

/// Result of modifying a certificate's expiration time.
///
/// SECURITY: `cert_data` contains unencrypted secret key material. The Swift caller must:
/// 1. SE-wrap `cert_data` immediately.
/// 2. Zeroize `cert_data` (via `resetBytes(in:)`) after wrapping is confirmed.
#[derive(Debug, uniffi::Record)]
pub struct ModifyExpiryResult {
    /// Updated full certificate (public + secret) in binary OpenPGP format.
    /// MUST be zeroized by the caller after SE wrapping.
    pub cert_data: Vec<u8>,
    /// Updated public key only in binary OpenPGP format.
    pub public_key_data: Vec<u8>,
    /// Updated key info with new expiry status.
    pub key_info: KeyInfo,
}

/// Modify the expiration time of an existing certificate.
///
/// Requires the full certificate with secret key material, because updating the expiry
/// requires re-signing the primary key's binding signatures (direct key sig + all User ID
/// binding sigs). Works identically for v4 (Profile A) and v6 (Profile B) keys — Sequoia's
/// `Cert::set_expiration_time()` handles both transparently.
///
/// - `cert_data`: Full certificate with secret key material (binary OpenPGP format).
/// - `new_expiry_seconds`: Duration from now in seconds. `None` removes expiry (never expire).
///
/// Returns the updated certificate (with secret keys) and updated public key + key info.
pub fn modify_expiry(
    cert_data: &[u8],
    new_expiry_seconds: Option<u64>,
) -> Result<ModifyExpiryResult, PgpError> {
    let cert = openpgp::Cert::from_bytes(cert_data).map_err(|e| PgpError::InvalidKeyData {
        reason: e.to_string(),
    })?;

    let policy = StandardPolicy::new();

    // Extract the primary key as a KeyPair for signing the new binding signatures.
    // SECURITY: `keypair` holds secret key material. Sequoia's KeyPair uses Protected<>
    // internally, which zeroizes on Drop.
    let mut keypair = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .map_err(|e| PgpError::InvalidKeyData {
            reason: format!("No secret key material for re-signing: {e}"),
        })?
        .into_keypair()
        .map_err(|e| PgpError::InvalidKeyData {
            reason: format!("Cannot create keypair from secret key: {e}"),
        })?;

    // Compute the target expiration time.
    let expiration =
        new_expiry_seconds.map(|secs| SystemTime::now() + std::time::Duration::from_secs(secs));

    // Generate new binding signatures with the updated expiry.
    // This updates: direct key signature + all valid, non-revoked User ID binding signatures.
    let sigs = cert
        .set_expiration_time(&policy, None, &mut keypair, expiration)
        .map_err(|e| PgpError::KeyGenerationFailed {
            reason: format!("Failed to set expiration time: {e}"),
        })?;

    // Insert the new signatures into the certificate.
    let (updated_cert, _) =
        cert.insert_packets(sigs)
            .map_err(|e| PgpError::KeyGenerationFailed {
                reason: format!("Failed to update certificate with new signatures: {e}"),
            })?;

    // Serialize the updated full cert (public + secret).
    // SECURITY: Wrapped in Zeroizing<> for automatic cleanup on error paths.
    let mut cert_output = Zeroizing::new(Vec::new());
    updated_cert
        .as_tsk()
        .serialize(&mut *cert_output)
        .map_err(|e| PgpError::KeyGenerationFailed {
            reason: format!("Failed to serialize updated certificate: {e}"),
        })?;

    // Serialize the public key only.
    let mut public_key_data = Vec::new();
    updated_cert
        .serialize(&mut public_key_data)
        .map_err(|e| PgpError::KeyGenerationFailed {
            reason: format!("Failed to serialize updated public key: {e}"),
        })?;

    // Re-parse key info to get updated expiry status.
    let key_info = parse_key_info(&public_key_data)?;

    Ok(ModifyExpiryResult {
        cert_data: std::mem::take(&mut *cert_output),
        public_key_data,
        key_info,
    })
}
