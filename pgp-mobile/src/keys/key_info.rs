use super::*;

/// Parse a certificate (public key or full key) and extract key information.
pub fn parse_key_info(key_data: &[u8]) -> Result<KeyInfo, PgpError> {
    let cert = openpgp::Cert::from_bytes(key_data).map_err(|e| PgpError::InvalidKeyData {
        reason: e.to_string(),
    })?;

    let policy = StandardPolicy::new();
    let now = SystemTime::now();

    let fingerprint = cert.fingerprint().to_hex().to_lowercase();
    let key_version = cert.primary_key().key().version();

    // Extract the primary User ID using Sequoia's policy-selected value when the
    // certificate is fully valid. If the certificate is expired or revoked, fall back
    // to a best-effort ranking that keeps display identity aligned with Sequoia's
    // primary-selection rules as closely as possible.
    let user_id = select_display_user_id(&cert, &policy, now);

    // Check for valid encryption subkey
    let has_encryption_subkey = cert
        .keys()
        .with_policy(&policy, Some(now))
        .supported()
        .for_transport_encryption()
        .next()
        .is_some();

    // Check revocation status
    let is_revoked = matches!(
        cert.revocation_status(&policy, Some(now)),
        RevocationStatus::Revoked(_)
    );

    // Check expiry: a key is expired if the primary key's alive() check fails at the
    // current time but succeeds at its creation time (meaning the issue is temporal, not
    // structural). Revoked keys are not considered expired (they have a separate status).
    let is_expired = if is_revoked {
        false
    } else if let Ok(valid_cert) = cert.with_policy(&policy, Some(now)) {
        // If the cert is valid at the current time, check if the primary key is alive
        valid_cert.primary_key().alive().is_err()
    } else {
        // If the cert is not valid at now, check if it was valid at creation time
        // (meaning it expired rather than being structurally invalid)
        let creation_time = cert.primary_key().key().creation_time();
        cert.with_policy(&policy, Some(creation_time)).is_ok()
    };

    // Detect profile from key version
    let profile = if key_version >= 6 {
        KeyProfile::Advanced
    } else {
        KeyProfile::Universal
    };

    // Extract primary key algorithm name (Display gives human-readable names like "EdDSA", "Ed448")
    let primary_algo = cert.primary_key().key().pk_algo().to_string();

    // Extract encryption subkey algorithm name (first encryption-capable subkey)
    let subkey_algo = cert
        .keys()
        .subkeys()
        .with_policy(&policy, Some(now))
        .for_transport_encryption()
        .next()
        .map(|ka| ka.key().pk_algo().to_string())
        .or_else(|| {
            // Fallback for display only: if no policy-valid encryption subkey found
            // (e.g., expired key), report the first subkey's algorithm name.
            // This does NOT affect encryption operations — encrypt() independently
            // uses with_policy() to find valid encryption subkeys and will correctly
            // reject keys with no valid encryption-capable subkey.
            cert.keys()
                .subkeys()
                .next()
                .map(|ka| ka.key().pk_algo().to_string())
        });

    // Extract expiry timestamp from the primary key's self-signature.
    // key_expiration_time() returns the absolute time at which the key expires.
    let expiry_timestamp = cert
        .with_policy(&policy, Some(now))
        .ok()
        .and_then(|valid_cert| valid_cert.primary_key().key_expiration_time())
        .or_else(|| {
            // Fallback for expired certs: validate without temporal check
            // to retrieve the expiry timestamp for display purposes.
            cert.with_policy(&policy, None)
                .ok()
                .and_then(|valid_cert| valid_cert.primary_key().key_expiration_time())
        })
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs());

    Ok(KeyInfo {
        fingerprint,
        key_version,
        user_id,
        has_encryption_subkey,
        is_revoked,
        is_expired,
        profile,
        primary_algo,
        subkey_algo,
        expiry_timestamp,
    })
}
