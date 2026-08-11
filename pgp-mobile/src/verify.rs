use openpgp::parse::stream::*;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use sequoia_openpgp as openpgp;

use crate::bounded_walk::{self, BoundedHelper};
use crate::decrypt::{
    parse_verification_certs, read_capped_zeroizing, MAX_IN_MEMORY_PLAINTEXT_BYTES,
};
use crate::error::PgpError;
use crate::signature_details::{SignatureCollector, SummaryFoldMode, VerifyDetailedResult};

/// Verify a cleartext-signed message and preserve detailed per-signature results.
pub fn verify_cleartext_detailed(
    signed_message: &[u8],
    verification_keys: &[Vec<u8>],
) -> Result<VerifyDetailedResult, PgpError> {
    let policy = StandardPolicy::new();
    let certs = parse_verification_certs(verification_keys)?;
    let helper = VerifyHelper::new(&certs);

    // Sequoia transparently decompresses an embedded CompressedData packet
    // while streaming, so a few-KB signed message can expand without bound —
    // and the expansion starts in the walk `with_policy` runs to reach the
    // literal data, before there is any output to count. `BoundedHelper` bounds
    // what that walk may consume, and the read below caps what it may produce.
    let verifier_result = VerifierBuilder::from_bytes(signed_message)
        .map_err(|e| PgpError::CorruptData {
            reason: format!("Failed to parse signed message: {e}"),
        })?
        .buffer_size(bounded_walk::SETUP_BUFFER_BYTES)
        .with_policy(
            &policy,
            None,
            BoundedHelper::new(helper, signed_message.len() as u64),
        );

    // A verifier that cannot be constructed has checked nothing, so it has no
    // verdict to report. This is the error channel's business, not the
    // graded-result channel's. A consumption bound that fired while walking the
    // message is a refusal of ours rather than a statement about it, so it
    // keeps its own error.
    let mut verifier = verifier_result.map_err(|error| {
        bounded_walk::walk_bound_error(&error).unwrap_or_else(|| {
            PgpError::VerificationSetupFailed {
                reason: format!("Could not start verifying the signed message: {error}"),
            }
        })
    })?;

    // The 256 MiB output ceiling the decrypt path uses. Without it the OOM
    // would arrive before the trailing signature is checked at EOF, so no valid
    // attacker signature is even required.
    let mut content = Vec::new();
    read_capped_zeroizing(&mut verifier, &mut content, MAX_IN_MEMORY_PLAINTEXT_BYTES)?;

    let helper = verifier.into_helper().into_inner();
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
