use super::*;

/// Generate a new key pair with the specified profile.
///
/// - Profile A (Universal): CipherSuite::Cv25519, Profile::RFC4880 → v4 key
/// - Profile B (Advanced): CipherSuite::Cv448, Profile::RFC9580 → v6 key
pub fn generate_key(
    name: String,
    email: Option<String>,
    expiry_seconds: Option<u64>,
) -> Result<GeneratedKey, PgpError> {
    generate_key_with_profile(name, email, expiry_seconds, KeyProfile::Universal)
}

/// Generate a new key pair with explicit profile selection.
pub fn generate_key_with_profile(
    name: String,
    email: Option<String>,
    expiry_seconds: Option<u64>,
    profile: KeyProfile,
) -> Result<GeneratedKey, PgpError> {
    let user_id = match &email {
        Some(e) => format!("{name} <{e}>"),
        None => name.clone(),
    };

    let mut builder = CertBuilder::general_purpose(Some(user_id.clone()));

    // Set cipher suite and profile based on KeyProfile
    match profile {
        KeyProfile::Universal => {
            // Explicitly set RFC4880 profile and strip SEIPDv2 feature.
            // Sequoia 2.2.0 defaults to advertising SEIPDv2 support in the
            // Features subpacket (because the library itself supports it).
            // For Profile A (GnuPG-compatible), we must advertise only SEIPDv1
            // so that other implementations send SEIPDv1 messages to this key.
            // Without this, GnuPG users cannot decrypt messages sent to Profile A keys.
            builder = builder
                .set_cipher_suite(CipherSuite::Cv25519)
                .set_profile(openpgp::Profile::RFC4880)
                .map_err(|e| PgpError::KeyGenerationFailed {
                    reason: format!("Failed to set profile: {e}"),
                })?
                .set_features(openpgp::types::Features::empty().set_seipdv1())
                .map_err(|e| PgpError::KeyGenerationFailed {
                    reason: format!("Failed to set features: {e}"),
                })?;
        }
        KeyProfile::Advanced => {
            builder = builder
                .set_cipher_suite(CipherSuite::Cv448)
                .set_profile(openpgp::Profile::RFC9580)
                .map_err(|e| PgpError::KeyGenerationFailed {
                    reason: format!("Failed to set profile: {e}"),
                })?;
        }
    }

    // Set expiry
    if let Some(secs) = expiry_seconds {
        builder = builder.set_validity_period(Some(std::time::Duration::from_secs(secs)));
    } else {
        // Default: 2 years
        builder = builder
            .set_validity_period(Some(std::time::Duration::from_secs(2 * 365 * 24 * 60 * 60)));
    }

    let (cert, rev) = builder
        .generate()
        .map_err(|e| PgpError::KeyGenerationFailed {
            reason: e.to_string(),
        })?;

    // Serialize full cert (public + secret).
    // SECURITY: cert_data contains unencrypted secret key material. Wrapped in Zeroizing<>
    // so it is automatically zeroized on error paths (dropped without reaching the caller).
    let mut cert_data = Zeroizing::new(Vec::new());
    cert.as_tsk()
        .serialize(&mut *cert_data)
        .map_err(|e| PgpError::KeyGenerationFailed {
            reason: format!("Failed to serialize cert: {e}"),
        })?;

    // Serialize public key only
    let mut public_key_data = Vec::new();
    cert.serialize(&mut public_key_data)
        .map_err(|e| PgpError::KeyGenerationFailed {
            reason: format!("Failed to serialize public key: {e}"),
        })?;

    // Serialize revocation certificate
    let mut revocation_cert = Vec::new();
    openpgp::Packet::from(rev)
        .serialize(&mut revocation_cert)
        .map_err(|e| PgpError::RevocationError {
            reason: format!("Failed to serialize revocation cert: {e}"),
        })?;

    let fingerprint = cert.fingerprint().to_hex();
    let key_version = cert.primary_key().key().version();

    Ok(GeneratedKey {
        cert_data: std::mem::take(&mut *cert_data),
        public_key_data,
        revocation_cert,
        fingerprint: fingerprint.to_lowercase(),
        key_version,
        profile,
    })
}
