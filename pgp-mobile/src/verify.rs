use openpgp::parse::stream::*;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use sequoia_openpgp as openpgp;

use crate::decrypt::{SignatureStatus, is_expired_error};
use crate::error::PgpError;

/// Result of signature verification.
#[derive(uniffi::Record)]
pub struct VerifyResult {
    /// Signature verification status.
    pub status: SignatureStatus,
    /// Fingerprint of the signer key, if known.
    pub signer_fingerprint: Option<String>,
    /// The signed content (for cleartext-signed messages).
    pub content: Option<Vec<u8>>,
}

/// Verify a cleartext-signed message.
/// Returns the message content and verification result.
pub fn verify_cleartext(
    signed_message: &[u8],
    verification_keys: &[Vec<u8>],
) -> Result<VerifyResult, PgpError> {
    let policy = StandardPolicy::new();

    let mut certs = Vec::new();
    for key_data in verification_keys {
        let cert = openpgp::Cert::from_bytes(key_data).map_err(|e| {
            PgpError::InvalidKeyData {
                reason: format!("Invalid verification key: {e}"),
            }
        })?;
        certs.push(cert);
    }

    let helper = VerifyHelper {
        certs: &certs,
        status: SignatureStatus::NotSigned,
        signer_fingerprint: None,
    };

    let verifier_result = VerifierBuilder::from_bytes(signed_message)
        .map_err(|e| PgpError::CorruptData {
            reason: format!("Failed to parse signed message: {e}"),
        })?
        .with_policy(&policy, None, helper);

    // Graded result: if with_policy() fails, inspect the error before defaulting
    // to Bad. A policy failure due to key expiry should produce Expired status so
    // the UI can show "Ask sender to update" instead of "Content may have been modified."
    let mut verifier = match verifier_result {
        Ok(v) => v,
        Err(e) => {
            let status = if is_expired_error(&e) {
                SignatureStatus::Expired
            } else {
                SignatureStatus::Bad
            };
            return Ok(VerifyResult {
                status,
                signer_fingerprint: None,
                content: None,
            });
        }
    };

    let mut content = Vec::new();
    std::io::Read::read_to_end(&mut verifier, &mut content).map_err(|e| {
        PgpError::CorruptData {
            reason: format!("Read failed: {e}"),
        }
    })?;

    let helper = verifier.into_helper();

    Ok(VerifyResult {
        status: helper.status,
        signer_fingerprint: helper.signer_fingerprint,
        content: Some(content),
    })
}

/// Verify a detached signature against data.
pub fn verify_detached(
    data: &[u8],
    signature: &[u8],
    verification_keys: &[Vec<u8>],
) -> Result<VerifyResult, PgpError> {
    let policy = StandardPolicy::new();

    let mut certs = Vec::new();
    for key_data in verification_keys {
        let cert = openpgp::Cert::from_bytes(key_data).map_err(|e| {
            PgpError::InvalidKeyData {
                reason: format!("Invalid verification key: {e}"),
            }
        })?;
        certs.push(cert);
    }

    let helper = VerifyHelper {
        certs: &certs,
        status: SignatureStatus::NotSigned,
        signer_fingerprint: None,
    };

    let verifier_result = DetachedVerifierBuilder::from_bytes(signature)
        .map_err(|e| PgpError::CorruptData {
            reason: format!("Failed to parse signature: {e}"),
        })?
        .with_policy(&policy, None, helper);

    // Graded result: if with_policy() fails, inspect the error before defaulting to Bad.
    let mut verifier = match verifier_result {
        Ok(v) => v,
        Err(e) => {
            let status = if is_expired_error(&e) {
                SignatureStatus::Expired
            } else {
                SignatureStatus::Bad
            };
            return Ok(VerifyResult {
                status,
                signer_fingerprint: None,
                content: None,
            });
        }
    };

    // verify_bytes may fail for tampered data — return Bad status as graded result.
    if verifier.verify_bytes(data).is_err() {
        let helper = verifier.into_helper();
        return Ok(VerifyResult {
            status: SignatureStatus::Bad,
            signer_fingerprint: helper.signer_fingerprint,
            content: None,
        });
    }

    let helper = verifier.into_helper();

    Ok(VerifyResult {
        status: helper.status,
        signer_fingerprint: helper.signer_fingerprint,
        content: None,
    })
}

/// Helper struct for Sequoia's verification API.
struct VerifyHelper<'a> {
    certs: &'a [openpgp::Cert],
    status: SignatureStatus,
    signer_fingerprint: Option<String>,
}

impl<'a> VerificationHelper for VerifyHelper<'a> {
    fn get_certs(
        &mut self,
        _ids: &[openpgp::KeyHandle],
    ) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(self.certs.to_vec())
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        for layer in structure {
            match layer {
                MessageLayer::SignatureGroup { results } => {
                    for result in results {
                        match result {
                            Ok(GoodChecksum { ka, .. }) => {
                                self.status = SignatureStatus::Valid;
                                self.signer_fingerprint = Some(
                                    ka.cert().fingerprint().to_hex().to_lowercase(),
                                );
                                return Ok(());
                            }
                            Err(VerificationError::MissingKey { .. }) => {
                                self.status = SignatureStatus::UnknownSigner;
                            }
                            Err(VerificationError::BadKey { ka, error, .. }) => {
                                // Distinguish expired signer key from other key issues
                                if is_expired_error(&error) {
                                    self.status = SignatureStatus::Expired;
                                    self.signer_fingerprint = Some(
                                        ka.cert().fingerprint().to_hex().to_lowercase(),
                                    );
                                } else {
                                    self.status = SignatureStatus::Bad;
                                }
                                return Ok(());
                            }
                            Err(_) => {
                                // Graded result: set status but return Ok so the caller
                                // can inspect helper.status. This is consistent with
                                // DecryptHelper::check() which also returns Ok for all
                                // verification outcomes to support graded results.
                                self.status = SignatureStatus::Bad;
                                return Ok(());
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }
}
