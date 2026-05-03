use openpgp::parse::stream::*;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use sequoia_openpgp as openpgp;

use crate::decrypt::{is_expired_error, parse_verification_certs, SignatureStatus};
use crate::error::PgpError;
use crate::signature_details::{
    state_from_legacy_status, LegacyFoldMode, SignatureCollector, VerifyDetailedResult,
};

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

fn empty_detailed_result(status: SignatureStatus) -> VerifyDetailedResult {
    VerifyDetailedResult {
        legacy_status: status.clone(),
        legacy_signer_fingerprint: None,
        summary_state: state_from_legacy_status(&status),
        summary_entry_index: None,
        signatures: Vec::new(),
        content: None,
    }
}

/// Verify a cleartext-signed message.
/// Returns the message content and verification result.
pub fn verify_cleartext(
    signed_message: &[u8],
    verification_keys: &[Vec<u8>],
) -> Result<VerifyResult, PgpError> {
    let detailed = verify_cleartext_detailed(signed_message, verification_keys)?;
    Ok(VerifyResult {
        status: detailed.legacy_status,
        signer_fingerprint: detailed.legacy_signer_fingerprint,
        content: detailed.content,
    })
}

/// Verify a cleartext-signed message and preserve detailed per-signature results.
pub fn verify_cleartext_detailed(
    signed_message: &[u8],
    verification_keys: &[Vec<u8>],
) -> Result<VerifyDetailedResult, PgpError> {
    let policy = StandardPolicy::new();
    let certs = parse_verification_certs(verification_keys)?;
    let helper = VerifyHelper::new(&certs);

    let verifier_result = VerifierBuilder::from_bytes(signed_message)
        .map_err(|e| PgpError::CorruptData {
            reason: format!("Failed to parse signed message: {e}"),
        })?
        .with_policy(&policy, None, helper);

    // Match the current early-setup grading: no observed per-signature results means
    // an empty detailed array and a legacy Bad/Expired status with no content.
    let mut verifier = match verifier_result {
        Ok(v) => v,
        Err(e) => {
            let status = if is_expired_error(&e) {
                SignatureStatus::Expired
            } else {
                SignatureStatus::Bad
            };
            return Ok(empty_detailed_result(status));
        }
    };

    let mut content = Vec::new();
    std::io::Read::read_to_end(&mut verifier, &mut content).map_err(|e| PgpError::CorruptData {
        reason: format!("Read failed: {e}"),
    })?;

    let helper = verifier.into_helper();
    let (legacy_status, legacy_signer_fingerprint, summary_state, summary_entry_index, signatures) =
        helper.collector.into_parts();

    Ok(VerifyDetailedResult {
        legacy_status,
        legacy_signer_fingerprint,
        summary_state,
        summary_entry_index,
        signatures,
        content: Some(content),
    })
}

/// Verify a detached signature against data.
pub fn verify_detached(
    data: &[u8],
    signature: &[u8],
    verification_keys: &[Vec<u8>],
) -> Result<VerifyResult, PgpError> {
    let detailed = verify_detached_detailed(data, signature, verification_keys)?;
    Ok(VerifyResult {
        status: detailed.legacy_status,
        signer_fingerprint: detailed.legacy_signer_fingerprint,
        content: None,
    })
}

/// Verify a detached signature and preserve detailed per-signature results.
pub fn verify_detached_detailed(
    data: &[u8],
    signature: &[u8],
    verification_keys: &[Vec<u8>],
) -> Result<VerifyDetailedResult, PgpError> {
    let policy = StandardPolicy::new();
    let certs = parse_verification_certs(verification_keys)?;
    let helper = VerifyHelper::new(&certs);

    let verifier_result = DetachedVerifierBuilder::from_bytes(signature)
        .map_err(|e| PgpError::CorruptData {
            reason: format!("Failed to parse signature: {e}"),
        })?
        .with_policy(&policy, None, helper);

    let mut verifier = match verifier_result {
        Ok(v) => v,
        Err(e) => {
            let status = if is_expired_error(&e) {
                SignatureStatus::Expired
            } else {
                SignatureStatus::Bad
            };
            return Ok(empty_detailed_result(status));
        }
    };

    if verifier.verify_bytes(data).is_err() {
        let helper = verifier.into_helper();
        return Ok(VerifyDetailedResult {
            legacy_status: SignatureStatus::Bad,
            legacy_signer_fingerprint: helper.collector.legacy_signer_fingerprint(),
            summary_state: helper.collector.summary_state(),
            summary_entry_index: helper.collector.summary_entry_index(),
            signatures: helper.collector.signatures(),
            content: None,
        });
    }

    let helper = verifier.into_helper();
    let (legacy_status, legacy_signer_fingerprint, summary_state, summary_entry_index, signatures) =
        helper.collector.into_parts();

    Ok(VerifyDetailedResult {
        legacy_status,
        legacy_signer_fingerprint,
        summary_state,
        summary_entry_index,
        signatures,
        content: None,
    })
}

/// Helper struct for Sequoia's verification API.
/// `pub(crate)` so that `streaming.rs` can construct this for file-based verification.
pub(crate) struct VerifyHelper<'a> {
    pub(crate) certs: &'a [openpgp::Cert],
    pub(crate) collector: SignatureCollector,
}

impl<'a> VerifyHelper<'a> {
    pub(crate) fn new(certs: &'a [openpgp::Cert]) -> Self {
        Self {
            certs,
            collector: SignatureCollector::new(LegacyFoldMode::VerifyLike),
        }
    }
}

impl<'a> VerificationHelper for VerifyHelper<'a> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(self.certs.to_vec())
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        self.collector.observe_structure(structure);
        Ok(())
    }
}
