use super::*;

/// Discover selector-bearing subkey and User ID metadata from binary certificate bytes.
///
/// This API is binary-only by contract. ASCII-armored certificate input is rejected.
pub fn discover_certificate_selectors(
    cert_data: &[u8],
) -> Result<DiscoveredCertificateSelectors, PgpError> {
    reject_armored_certificate_input(cert_data)?;

    let cert = openpgp::Cert::from_bytes(cert_data).map_err(|e| PgpError::InvalidKeyData {
        reason: e.to_string(),
    })?;
    let policy = StandardPolicy::new();
    let now = SystemTime::now();

    let currently_valid_subkeys = current_valid_subkey_fingerprints(&cert, &policy, now);
    let transport_encryption_capable_subkeys =
        current_transport_encryption_capable_subkey_fingerprints(&cert, &policy, now);
    let raw_user_ids = raw_user_id_occurrences(cert_data)?;

    let subkeys = cert
        .keys()
        .subkeys()
        .map(|subkey| {
            discover_subkey(
                &cert,
                &subkey,
                &policy,
                now,
                &currently_valid_subkeys,
                &transport_encryption_capable_subkeys,
            )
        })
        .collect();

    let user_ids = raw_user_ids
        .iter()
        .enumerate()
        .map(|(occurrence_index, user_id)| {
            discover_user_id(&cert, user_id, occurrence_index as u64, &policy, now)
        })
        .collect();

    Ok(DiscoveredCertificateSelectors {
        certificate_fingerprint: cert.fingerprint().to_hex().to_lowercase(),
        subkeys,
        user_ids,
    })
}
