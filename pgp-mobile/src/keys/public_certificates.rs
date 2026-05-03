use super::*;

/// Validate that contact-import data is a public certificate and return normalized metadata.
pub fn validate_public_certificate(
    cert_data: &[u8],
) -> Result<PublicCertificateValidationResult, PgpError> {
    let cert = openpgp::Cert::from_bytes(cert_data).map_err(|e| PgpError::InvalidKeyData {
        reason: e.to_string(),
    })?;

    if cert.is_tsk() {
        return Err(PgpError::InvalidKeyData {
            reason: CONTACT_IMPORT_PUBLIC_ONLY_REASON.to_string(),
        });
    }

    let public_cert_data = serialize_public_cert(&cert)?;
    let key_info = parse_key_info(&public_cert_data)?;
    let profile = key_info.profile;

    Ok(PublicCertificateValidationResult {
        public_cert_data,
        key_info,
        profile,
    })
}

/// Merge same-fingerprint public certificate update material into an existing public certificate.
///
/// Both inputs must parse as public certificates with the same primary fingerprint.
/// Secret-bearing input is rejected as an API precondition failure.
pub fn merge_public_certificate_update(
    existing_cert: &[u8],
    incoming_cert_or_update: &[u8],
) -> Result<CertificateMergeResult, PgpError> {
    let existing_cert =
        openpgp::Cert::from_bytes(existing_cert).map_err(|e| PgpError::InvalidKeyData {
            reason: format!("Invalid existing public certificate: {e}"),
        })?;
    if existing_cert.is_tsk() {
        return Err(PgpError::InvalidKeyData {
            reason: "Existing certificate contains secret key material; merge/update accepts public certificates only.".to_string(),
        });
    }

    let incoming_cert = openpgp::Cert::from_bytes(incoming_cert_or_update).map_err(|e| {
        PgpError::InvalidKeyData {
            reason: format!("Invalid incoming public certificate update: {e}"),
        }
    })?;
    if incoming_cert.is_tsk() {
        return Err(PgpError::InvalidKeyData {
            reason: "Incoming certificate update contains secret key material; merge/update accepts public certificates only.".to_string(),
        });
    }

    if existing_cert.fingerprint() != incoming_cert.fingerprint() {
        return Err(PgpError::InvalidKeyData {
            reason:
                "Public certificate merge/update requires both inputs to have the same fingerprint."
                    .to_string(),
        });
    }

    let existing_public = serialize_public_cert(&existing_cert)?;
    let merged_cert =
        existing_cert
            .merge_public(incoming_cert)
            .map_err(|e| PgpError::InvalidKeyData {
                reason: format!("Failed to merge public certificates: {e}"),
            })?;
    let merged_cert_data = serialize_public_cert(&merged_cert)?;

    let outcome = if merged_cert_data == existing_public {
        CertificateMergeOutcome::NoOp
    } else {
        CertificateMergeOutcome::Updated
    };

    Ok(CertificateMergeResult {
        merged_cert_data,
        outcome,
    })
}
