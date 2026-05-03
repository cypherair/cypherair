use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sequoia_openpgp as openpgp;
use sequoia_openpgp::parse::Parse;

use crate::error::PgpError;

const QR_URL_PREFIX: &str = "cypherair://import/v1/";
const QR_MAX_BYTES: usize = 2953;

pub(crate) fn encode_qr_url(public_key_data: Vec<u8>) -> Result<String, PgpError> {
    // Validate input is a valid OpenPGP certificate.
    let cert = openpgp::Cert::from_bytes(&public_key_data).map_err(|e| {
        PgpError::InvalidKeyData {
            reason: format!("Invalid key data for QR encoding: {e}"),
        }
    })?;

    // Reject secret key material: only public keys should be shared via QR.
    if cert.is_tsk() {
        return Err(PgpError::InvalidKeyData {
            reason: "Cannot encode secret key material in QR code. Only public keys should be shared via QR.".to_string(),
        });
    }

    let encoded = URL_SAFE_NO_PAD.encode(&public_key_data);
    let url = format!("{QR_URL_PREFIX}{encoded}");

    // QR code capacity at Level L (lowest error correction) is about 2953 binary bytes.
    if url.len() > QR_MAX_BYTES {
        return Err(PgpError::KeyTooLargeForQr {
            size_bytes: public_key_data.len() as u64,
            max_bytes: QR_MAX_BYTES as u64,
        });
    }

    Ok(url)
}

pub(crate) fn decode_qr_url(url: &str) -> Result<Vec<u8>, PgpError> {
    if !url.starts_with(QR_URL_PREFIX) {
        return Err(PgpError::CorruptData {
            reason: "Not a valid CypherAir URL. Expected cypherair://import/v1/...".to_string(),
        });
    }

    let b64_data = &url[QR_URL_PREFIX.len()..];
    let key_bytes = URL_SAFE_NO_PAD
        .decode(b64_data)
        .map_err(|e| PgpError::CorruptData {
            reason: format!("Invalid base64url data: {e}"),
        })?;

    // Single parse: validate that the payload is an OpenPGP key and check for secret material.
    let cert = openpgp::Cert::from_bytes(&key_bytes).map_err(|e| PgpError::InvalidKeyData {
        reason: format!("Invalid key data: {e}"),
    })?;

    // Reject secret key material: QR exchange should only contain public keys.
    if cert.is_tsk() {
        return Err(PgpError::InvalidKeyData {
            reason: "QR code contains secret key material. Only public keys should be shared via QR.".to_string(),
        });
    }

    Ok(key_bytes)
}
