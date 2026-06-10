use openpgp::parse::stream::*;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use sequoia_openpgp as openpgp;

use crate::decrypt::{is_expired_error, parse_verification_certs};
use crate::error::PgpError;
use crate::signature_details::{
    SignatureCollector, SignatureVerificationState, SummaryFoldMode, VerifyDetailedResult,
};

fn empty_detailed_result(summary_state: SignatureVerificationState) -> VerifyDetailedResult {
    VerifyDetailedResult {
        summary_state,
        summary_entry_index: None,
        signatures: Vec::new(),
        content: None,
    }
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
    // an empty detailed array and an Expired/Invalid summary with no content.
    let mut verifier = match verifier_result {
        Ok(v) => v,
        Err(e) => {
            let summary_state = if is_expired_error(&e) {
                SignatureVerificationState::Expired
            } else {
                SignatureVerificationState::Invalid
            };
            return Ok(empty_detailed_result(summary_state));
        }
    };

    let mut content = Vec::new();
    std::io::Read::read_to_end(&mut verifier, &mut content).map_err(|e| PgpError::CorruptData {
        reason: format!("Read failed: {e}"),
    })?;

    let helper = verifier.into_helper();
    let (summary_state, summary_entry_index, signatures) = helper.collector.into_parts();

    Ok(VerifyDetailedResult {
        summary_state,
        summary_entry_index,
        signatures,
        content: Some(content),
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
            collector: SignatureCollector::new(SummaryFoldMode::VerifyLike),
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
