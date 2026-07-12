use openpgp::parse::stream::{
    GoodChecksum, MessageLayer, MessageStructure, VerificationError, VerificationResult,
};
use sequoia_openpgp as openpgp;

use crate::decrypt::is_expired_error;

/// Certificate-backed verification state for a signature entry or summary.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SignatureVerificationState {
    NotSigned,
    Verified,
    Invalid,
    Expired,
    SignerCertificateUnavailable,
}

/// Per-signature status preserved by the detailed APIs.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum DetailedSignatureStatus {
    Valid,
    UnknownSigner,
    Bad,
    Expired,
}

impl DetailedSignatureStatus {
    /// Certificate-backed verification state equivalent of this per-signature status.
    pub(crate) fn verification_state(&self) -> SignatureVerificationState {
        match self {
            DetailedSignatureStatus::Valid => SignatureVerificationState::Verified,
            DetailedSignatureStatus::UnknownSigner => {
                SignatureVerificationState::SignerCertificateUnavailable
            }
            DetailedSignatureStatus::Bad => SignatureVerificationState::Invalid,
            DetailedSignatureStatus::Expired => SignatureVerificationState::Expired,
        }
    }
}

/// One observed signature result in parser order.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DetailedSignatureEntry {
    pub status: DetailedSignatureStatus,
    pub signer_primary_fingerprint: Option<String>,
}

/// Detailed result for in-memory verification APIs.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VerifyDetailedResult {
    pub summary_state: SignatureVerificationState,
    pub summary_entry_index: Option<u64>,
    pub signatures: Vec<DetailedSignatureEntry>,
    pub content: Option<Vec<u8>>,
}

/// Detailed result for in-memory decrypt APIs.
///
/// SECURITY: `plaintext` contains sensitive decrypted content. The Swift caller must
/// zeroize this data after use.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DecryptDetailedResult {
    pub summary_state: SignatureVerificationState,
    pub summary_entry_index: Option<u64>,
    pub signatures: Vec<DetailedSignatureEntry>,
    pub plaintext: Vec<u8>,
}

/// Detailed result for file verification APIs.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FileVerifyDetailedResult {
    pub summary_state: SignatureVerificationState,
    pub summary_entry_index: Option<u64>,
    pub signatures: Vec<DetailedSignatureEntry>,
}

/// Detailed result for file decrypt APIs.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FileDecryptDetailedResult {
    pub summary_state: SignatureVerificationState,
    pub summary_entry_index: Option<u64>,
    pub signatures: Vec<DetailedSignatureEntry>,
}

/// Summary selection mode.
///
/// Verify-like routes freeze the summary on the first conclusive result
/// (valid, or any hard failure); decrypt-like routes keep following later
/// results until a valid signature wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SummaryFoldMode {
    VerifyLike,
    DecryptLike,
}

/// Collects detailed per-signature entries and selects the summary signature.
#[derive(Debug, Clone)]
pub(crate) struct SignatureCollector {
    mode: SummaryFoldMode,
    summary_state: Option<SignatureVerificationState>,
    summary_entry_index: Option<u64>,
    summary_stopped: bool,
    signatures: Vec<DetailedSignatureEntry>,
}

impl SignatureCollector {
    pub(crate) fn new(mode: SummaryFoldMode) -> Self {
        Self {
            mode,
            summary_state: None,
            summary_entry_index: None,
            summary_stopped: false,
            signatures: Vec::new(),
        }
    }

    /// Record every observed signature result in global parser order.
    ///
    /// Summary stop conditions only affect the summary selection. Detailed entry
    /// collection must continue for every observed result, even after the summary
    /// winner is known.
    pub(crate) fn observe_structure(&mut self, structure: MessageStructure) {
        for layer in structure {
            if let MessageLayer::SignatureGroup { results } = layer {
                for result in results {
                    self.observe_result(result);
                }
            }
        }
    }

    pub(crate) fn summary_state(&self) -> SignatureVerificationState {
        self.summary_state
            .clone()
            .unwrap_or(SignatureVerificationState::NotSigned)
    }

    pub(crate) fn summary_entry_index(&self) -> Option<u64> {
        self.summary_entry_index
    }

    pub(crate) fn signatures(&self) -> Vec<DetailedSignatureEntry> {
        self.signatures.clone()
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        SignatureVerificationState,
        Option<u64>,
        Vec<DetailedSignatureEntry>,
    ) {
        (
            self.summary_state
                .unwrap_or(SignatureVerificationState::NotSigned),
            self.summary_entry_index,
            self.signatures,
        )
    }

    fn observe_result(&mut self, result: VerificationResult) {
        let entry = entry_from_result(&result);
        let status = entry.status.clone();
        let entry_index = self.signatures.len() as u64;
        self.signatures.push(entry);
        self.fold_summary(status, entry_index);
    }

    fn fold_summary(&mut self, status: DetailedSignatureStatus, entry_index: u64) {
        if self.summary_stopped {
            return;
        }

        self.summary_state = Some(status.verification_state());
        self.summary_entry_index = Some(entry_index);

        match status {
            DetailedSignatureStatus::Valid => {
                self.summary_stopped = true;
            }
            DetailedSignatureStatus::UnknownSigner => {}
            DetailedSignatureStatus::Bad | DetailedSignatureStatus::Expired => {
                if matches!(self.mode, SummaryFoldMode::VerifyLike) {
                    self.summary_stopped = true;
                }
            }
        }
    }
}

fn entry_from_result(result: &VerificationResult) -> DetailedSignatureEntry {
    match result {
        Ok(GoodChecksum { ka, .. }) => DetailedSignatureEntry {
            status: DetailedSignatureStatus::Valid,
            signer_primary_fingerprint: Some(ka.cert().fingerprint().to_hex().to_lowercase()),
        },
        Err(VerificationError::MissingKey { .. }) => DetailedSignatureEntry {
            status: DetailedSignatureStatus::UnknownSigner,
            signer_primary_fingerprint: None,
        },
        Err(VerificationError::BadKey { ka, error, .. }) => DetailedSignatureEntry {
            status: if is_expired_error(error) {
                DetailedSignatureStatus::Expired
            } else {
                DetailedSignatureStatus::Bad
            },
            signer_primary_fingerprint: Some(ka.cert().fingerprint().to_hex().to_lowercase()),
        },
        Err(VerificationError::BadSignature { ka, .. }) => DetailedSignatureEntry {
            status: DetailedSignatureStatus::Bad,
            signer_primary_fingerprint: Some(ka.cert().fingerprint().to_hex().to_lowercase()),
        },
        Err(VerificationError::UnboundKey { cert, .. }) => DetailedSignatureEntry {
            status: DetailedSignatureStatus::Bad,
            signer_primary_fingerprint: Some(cert.fingerprint().to_hex().to_lowercase()),
        },
        Err(VerificationError::MalformedSignature { .. })
        | Err(VerificationError::UnknownSignature { .. })
        | Err(_) => DetailedSignatureEntry {
            status: DetailedSignatureStatus::Bad,
            signer_primary_fingerprint: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl SignatureCollector {
        fn observe_synthetic(
            &mut self,
            status: DetailedSignatureStatus,
            signer_primary_fingerprint: Option<&str>,
        ) {
            self.signatures.push(DetailedSignatureEntry {
                status: status.clone(),
                signer_primary_fingerprint: signer_primary_fingerprint
                    .map(std::string::ToString::to_string),
            });
            let entry_index = (self.signatures.len() - 1) as u64;
            self.fold_summary(status, entry_index);
        }
    }

    #[test]
    fn verify_like_summary_freezes_on_first_valid_while_entries_continue() {
        let mut collector = SignatureCollector::new(SummaryFoldMode::VerifyLike);
        collector.observe_synthetic(DetailedSignatureStatus::Valid, Some("signer-a"));
        collector.observe_synthetic(DetailedSignatureStatus::UnknownSigner, None);
        collector.observe_synthetic(DetailedSignatureStatus::Bad, Some("signer-b"));

        assert_eq!(
            collector.summary_state(),
            SignatureVerificationState::Verified
        );
        assert_eq!(collector.summary_entry_index(), Some(0));
        assert_eq!(collector.signatures.len(), 3);
        assert_eq!(collector.signatures[0].status, DetailedSignatureStatus::Valid);
        assert_eq!(
            collector.signatures[1].status,
            DetailedSignatureStatus::UnknownSigner
        );
        assert_eq!(collector.signatures[2].status, DetailedSignatureStatus::Bad);
    }

    #[test]
    fn decrypt_like_summary_follows_later_results_until_valid() {
        let mut collector = SignatureCollector::new(SummaryFoldMode::DecryptLike);
        collector.observe_synthetic(DetailedSignatureStatus::Bad, Some("bad-fp"));
        collector.observe_synthetic(DetailedSignatureStatus::UnknownSigner, None);
        collector.observe_synthetic(DetailedSignatureStatus::Valid, Some("good-fp"));

        assert_eq!(
            collector.summary_state(),
            SignatureVerificationState::Verified
        );
        assert_eq!(collector.summary_entry_index(), Some(2));
        assert_eq!(collector.signatures.len(), 3);
        assert_eq!(
            collector.signatures[2].signer_primary_fingerprint,
            Some("good-fp".to_string())
        );
    }

    #[test]
    fn verify_like_summary_freezes_on_hard_failure() {
        let mut collector = SignatureCollector::new(SummaryFoldMode::VerifyLike);
        collector.observe_synthetic(DetailedSignatureStatus::Bad, Some("bad-fp"));
        collector.observe_synthetic(DetailedSignatureStatus::Valid, Some("good-fp"));

        assert_eq!(
            collector.summary_state(),
            SignatureVerificationState::Invalid
        );
        assert_eq!(collector.summary_entry_index(), Some(0));
        assert_eq!(collector.signatures.len(), 2);
    }

    #[test]
    fn repeated_signers_are_not_collapsed() {
        let mut collector = SignatureCollector::new(SummaryFoldMode::VerifyLike);
        collector.observe_synthetic(DetailedSignatureStatus::Valid, Some("same-fp"));
        collector.observe_synthetic(DetailedSignatureStatus::Valid, Some("same-fp"));

        assert_eq!(collector.signatures.len(), 2);
        assert_eq!(
            collector.signatures[0].signer_primary_fingerprint,
            Some("same-fp".to_string())
        );
        assert_eq!(
            collector.signatures[1].signer_primary_fingerprint,
            Some("same-fp".to_string())
        );
    }

    #[test]
    fn no_observed_signatures_defaults_to_not_signed() {
        let collector = SignatureCollector::new(SummaryFoldMode::DecryptLike);
        assert_eq!(
            collector.summary_state(),
            SignatureVerificationState::NotSigned
        );
        assert_eq!(collector.summary_entry_index(), None);
        assert!(collector.signatures.is_empty());
    }
}
