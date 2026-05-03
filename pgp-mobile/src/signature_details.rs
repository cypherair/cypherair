use openpgp::packet::Signature;
use openpgp::parse::stream::{
    GoodChecksum, MessageLayer, MessageStructure, VerificationError, VerificationResult,
};
use sequoia_openpgp as openpgp;

use crate::decrypt::{is_expired_error, SignatureStatus};

/// Claimed or observed signer evidence available from signature metadata.
///
/// These values are lookup clues only. They are not proof of signer identity unless
/// `SignatureVerificationState::Verified` is backed by a verification certificate.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SignerEvidence {
    pub issuer_fingerprints: Vec<String>,
    pub issuer_key_ids: Vec<String>,
}

impl SignerEvidence {
    fn empty() -> Self {
        Self {
            issuer_fingerprints: Vec::new(),
            issuer_key_ids: Vec::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.issuer_fingerprints.is_empty() && self.issuer_key_ids.is_empty()
    }
}

/// Certificate-backed verification state for a signature entry or summary.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SignatureVerificationState {
    NotSigned,
    Verified,
    Invalid,
    Expired,
    SignerCertificateUnavailable,
    SignerEvidenceUnavailable,
}

/// Per-signature status preserved by the additive detailed APIs.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum DetailedSignatureStatus {
    Valid,
    UnknownSigner,
    Bad,
    Expired,
}

/// One observed signature result in parser order.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DetailedSignatureEntry {
    pub status: DetailedSignatureStatus,
    pub signer_primary_fingerprint: Option<String>,
    pub state: SignatureVerificationState,
    pub verification_certificate_fingerprint: Option<String>,
    pub signer_evidence: SignerEvidence,
}

/// Detailed result for in-memory verification APIs.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VerifyDetailedResult {
    pub legacy_status: SignatureStatus,
    pub legacy_signer_fingerprint: Option<String>,
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
    pub legacy_status: SignatureStatus,
    pub legacy_signer_fingerprint: Option<String>,
    pub summary_state: SignatureVerificationState,
    pub summary_entry_index: Option<u64>,
    pub signatures: Vec<DetailedSignatureEntry>,
    pub plaintext: Vec<u8>,
}

/// Detailed result for file verification APIs.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FileVerifyDetailedResult {
    pub legacy_status: SignatureStatus,
    pub legacy_signer_fingerprint: Option<String>,
    pub summary_state: SignatureVerificationState,
    pub summary_entry_index: Option<u64>,
    pub signatures: Vec<DetailedSignatureEntry>,
}

/// Detailed result for file decrypt APIs.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FileDecryptDetailedResult {
    pub legacy_status: SignatureStatus,
    pub legacy_signer_fingerprint: Option<String>,
    pub summary_state: SignatureVerificationState,
    pub summary_entry_index: Option<u64>,
    pub signatures: Vec<DetailedSignatureEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LegacyFoldMode {
    VerifyLike,
    DecryptLike,
}

/// Collects detailed per-signature entries while independently reproducing legacy fold behavior.
#[derive(Debug, Clone)]
pub(crate) struct SignatureCollector {
    mode: LegacyFoldMode,
    legacy_status: Option<SignatureStatus>,
    legacy_signer_fingerprint: Option<String>,
    summary_state: Option<SignatureVerificationState>,
    summary_entry_index: Option<u64>,
    legacy_stopped: bool,
    signatures: Vec<DetailedSignatureEntry>,
}

impl SignatureCollector {
    pub(crate) fn new(mode: LegacyFoldMode) -> Self {
        Self {
            mode,
            legacy_status: None,
            legacy_signer_fingerprint: None,
            summary_state: None,
            summary_entry_index: None,
            legacy_stopped: false,
            signatures: Vec::new(),
        }
    }

    /// Record every observed signature result in global parser order.
    ///
    /// Legacy fold stop conditions only affect `legacy_*` fields. Detailed entry collection
    /// must continue for every observed result, even after the legacy winner is known.
    pub(crate) fn observe_structure(&mut self, structure: MessageStructure) {
        for layer in structure {
            if let MessageLayer::SignatureGroup { results } = layer {
                for result in results {
                    self.observe_result(result);
                }
            }
        }
    }

    pub(crate) fn legacy_status(&self) -> SignatureStatus {
        self.legacy_status
            .clone()
            .unwrap_or(SignatureStatus::NotSigned)
    }

    pub(crate) fn legacy_signer_fingerprint(&self) -> Option<String> {
        self.legacy_signer_fingerprint.clone()
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
        SignatureStatus,
        Option<String>,
        SignatureVerificationState,
        Option<u64>,
        Vec<DetailedSignatureEntry>,
    ) {
        (
            self.legacy_status.unwrap_or(SignatureStatus::NotSigned),
            self.legacy_signer_fingerprint,
            self.summary_state
                .unwrap_or(SignatureVerificationState::NotSigned),
            self.summary_entry_index,
            self.signatures,
        )
    }

    fn observe_result(&mut self, result: VerificationResult) {
        let entry = entry_from_result(&result);
        let entry_index = self.signatures.len() as u64;
        self.signatures.push(entry.clone());

        if self.legacy_stopped {
            return;
        }

        match result {
            Ok(GoodChecksum { ka, .. }) => {
                self.legacy_status = Some(SignatureStatus::Valid);
                self.legacy_signer_fingerprint =
                    Some(ka.cert().fingerprint().to_hex().to_lowercase());
                self.summary_state = Some(entry.state);
                self.summary_entry_index = Some(entry_index);
                self.legacy_stopped = true;
            }
            Err(VerificationError::MissingKey { .. }) => {
                self.legacy_status = Some(SignatureStatus::UnknownSigner);
                self.summary_state = Some(entry.state);
                self.summary_entry_index = Some(entry_index);
            }
            Err(VerificationError::BadKey { ka, error, .. }) => {
                if is_expired_error(&error) {
                    self.legacy_status = Some(SignatureStatus::Expired);
                    self.legacy_signer_fingerprint =
                        Some(ka.cert().fingerprint().to_hex().to_lowercase());
                    self.summary_state = Some(SignatureVerificationState::Expired);
                } else {
                    self.legacy_status = Some(SignatureStatus::Bad);
                    self.summary_state = Some(SignatureVerificationState::Invalid);
                }
                self.summary_entry_index = Some(entry_index);

                if matches!(self.mode, LegacyFoldMode::VerifyLike) {
                    self.legacy_stopped = true;
                }
            }
            Err(_) => {
                self.legacy_status = Some(SignatureStatus::Bad);
                self.summary_state = Some(SignatureVerificationState::Invalid);
                self.summary_entry_index = Some(entry_index);
                if matches!(self.mode, LegacyFoldMode::VerifyLike) {
                    self.legacy_stopped = true;
                }
            }
        }
    }
}

fn entry_from_result(result: &VerificationResult) -> DetailedSignatureEntry {
    match result {
        Ok(GoodChecksum { sig, ka, .. }) => {
            let fingerprint = ka.cert().fingerprint().to_hex().to_lowercase();
            DetailedSignatureEntry {
                status: DetailedSignatureStatus::Valid,
                signer_primary_fingerprint: Some(fingerprint.clone()),
                state: SignatureVerificationState::Verified,
                verification_certificate_fingerprint: Some(fingerprint),
                signer_evidence: evidence_from_signature(sig),
            }
        }
        Err(VerificationError::MissingKey { sig }) => {
            let evidence = evidence_from_signature(sig);
            DetailedSignatureEntry {
                status: DetailedSignatureStatus::UnknownSigner,
                signer_primary_fingerprint: None,
                state: if evidence.is_empty() {
                    SignatureVerificationState::SignerEvidenceUnavailable
                } else {
                    SignatureVerificationState::SignerCertificateUnavailable
                },
                verification_certificate_fingerprint: None,
                signer_evidence: evidence,
            }
        }
        Err(VerificationError::BadKey { sig, ka, error, .. }) => {
            let fingerprint = ka.cert().fingerprint().to_hex().to_lowercase();
            let expired = is_expired_error(error);
            DetailedSignatureEntry {
                status: if expired {
                    DetailedSignatureStatus::Expired
                } else {
                    DetailedSignatureStatus::Bad
                },
                signer_primary_fingerprint: Some(fingerprint.clone()),
                state: if expired {
                    SignatureVerificationState::Expired
                } else {
                    SignatureVerificationState::Invalid
                },
                verification_certificate_fingerprint: Some(fingerprint),
                signer_evidence: evidence_from_signature(sig),
            }
        }
        Err(VerificationError::BadSignature { sig, ka, .. }) => {
            let fingerprint = ka.cert().fingerprint().to_hex().to_lowercase();
            DetailedSignatureEntry {
                status: DetailedSignatureStatus::Bad,
                signer_primary_fingerprint: Some(fingerprint.clone()),
                state: SignatureVerificationState::Invalid,
                verification_certificate_fingerprint: Some(fingerprint),
                signer_evidence: evidence_from_signature(sig),
            }
        }
        Err(VerificationError::UnboundKey { sig, cert, .. }) => {
            let fingerprint = cert.fingerprint().to_hex().to_lowercase();
            DetailedSignatureEntry {
                status: DetailedSignatureStatus::Bad,
                signer_primary_fingerprint: Some(fingerprint.clone()),
                state: SignatureVerificationState::Invalid,
                verification_certificate_fingerprint: Some(fingerprint),
                signer_evidence: evidence_from_signature(sig),
            }
        }
        Err(VerificationError::MalformedSignature { .. })
        | Err(VerificationError::UnknownSignature { .. })
        | Err(_) => DetailedSignatureEntry {
            status: DetailedSignatureStatus::Bad,
            signer_primary_fingerprint: None,
            state: SignatureVerificationState::Invalid,
            verification_certificate_fingerprint: None,
            signer_evidence: SignerEvidence::empty(),
        },
    }
}

pub(crate) fn state_from_legacy_status(status: &SignatureStatus) -> SignatureVerificationState {
    match status {
        SignatureStatus::Valid => SignatureVerificationState::Verified,
        SignatureStatus::UnknownSigner => SignatureVerificationState::SignerEvidenceUnavailable,
        SignatureStatus::Bad => SignatureVerificationState::Invalid,
        SignatureStatus::NotSigned => SignatureVerificationState::NotSigned,
        SignatureStatus::Expired => SignatureVerificationState::Expired,
    }
}

fn evidence_from_signature(sig: &Signature) -> SignerEvidence {
    let mut evidence = SignerEvidence::empty();
    for issuer in sig.get_issuers() {
        match issuer {
            openpgp::KeyHandle::Fingerprint(fingerprint) => push_unique(
                &mut evidence.issuer_fingerprints,
                fingerprint.to_hex().to_lowercase(),
            ),
            openpgp::KeyHandle::KeyID(key_id) => {
                push_unique(&mut evidence.issuer_key_ids, key_id.to_hex().to_lowercase())
            }
        }
    }
    evidence
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
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
            let signer_primary_fingerprint =
                signer_primary_fingerprint.map(std::string::ToString::to_string);
            let state = state_from_detailed_status(&status, signer_primary_fingerprint.is_some());
            self.signatures.push(DetailedSignatureEntry {
                status: status.clone(),
                signer_primary_fingerprint: signer_primary_fingerprint.clone(),
                state: state.clone(),
                verification_certificate_fingerprint: signer_primary_fingerprint.clone(),
                signer_evidence: SignerEvidence::empty(),
            });
            let entry_index = (self.signatures.len() - 1) as u64;

            if self.legacy_stopped {
                return;
            }

            match status {
                DetailedSignatureStatus::Valid => {
                    self.legacy_status = Some(SignatureStatus::Valid);
                    self.legacy_signer_fingerprint = signer_primary_fingerprint;
                    self.summary_state = Some(SignatureVerificationState::Verified);
                    self.summary_entry_index = Some(entry_index);
                    self.legacy_stopped = true;
                }
                DetailedSignatureStatus::UnknownSigner => {
                    self.legacy_status = Some(SignatureStatus::UnknownSigner);
                    self.summary_state = Some(state);
                    self.summary_entry_index = Some(entry_index);
                }
                DetailedSignatureStatus::Bad => {
                    self.legacy_status = Some(SignatureStatus::Bad);
                    self.summary_state = Some(SignatureVerificationState::Invalid);
                    self.summary_entry_index = Some(entry_index);
                    if matches!(self.mode, LegacyFoldMode::VerifyLike) {
                        self.legacy_stopped = true;
                    }
                }
                DetailedSignatureStatus::Expired => {
                    self.legacy_status = Some(SignatureStatus::Expired);
                    self.legacy_signer_fingerprint = signer_primary_fingerprint;
                    self.summary_state = Some(SignatureVerificationState::Expired);
                    self.summary_entry_index = Some(entry_index);
                    if matches!(self.mode, LegacyFoldMode::VerifyLike) {
                        self.legacy_stopped = true;
                    }
                }
            }
        }
    }

    #[test]
    fn verify_like_stop_only_affects_legacy_fold() {
        let mut collector = SignatureCollector::new(LegacyFoldMode::VerifyLike);
        collector.observe_synthetic(DetailedSignatureStatus::Valid, Some("signer-a"));
        collector.observe_synthetic(DetailedSignatureStatus::UnknownSigner, None);
        collector.observe_synthetic(DetailedSignatureStatus::Bad, Some("signer-b"));

        assert_eq!(collector.legacy_status(), SignatureStatus::Valid);
        assert_eq!(
            collector.summary_state(),
            SignatureVerificationState::Verified
        );
        assert_eq!(collector.summary_entry_index(), Some(0));
        assert_eq!(
            collector.legacy_signer_fingerprint(),
            Some("signer-a".to_string())
        );
        assert_eq!(collector.signatures.len(), 3);
        assert_eq!(
            collector.signatures[0].state,
            SignatureVerificationState::Verified
        );
        assert_eq!(
            collector.signatures[1].state,
            SignatureVerificationState::SignerEvidenceUnavailable
        );
        assert_eq!(
            collector.signatures[2].state,
            SignatureVerificationState::Invalid
        );
    }

    #[test]
    fn decrypt_like_expired_then_bad_preserves_expired_fingerprint() {
        let mut collector = SignatureCollector::new(LegacyFoldMode::DecryptLike);
        collector.observe_synthetic(DetailedSignatureStatus::Expired, Some("expired-fp"));
        collector.observe_synthetic(DetailedSignatureStatus::Bad, Some("bad-fp"));

        assert_eq!(collector.legacy_status(), SignatureStatus::Bad);
        assert_eq!(
            collector.summary_state(),
            SignatureVerificationState::Invalid
        );
        assert_eq!(collector.summary_entry_index(), Some(1));
        assert_eq!(
            collector.legacy_signer_fingerprint(),
            Some("expired-fp".to_string())
        );
        assert_eq!(collector.signatures.len(), 2);
    }

    #[test]
    fn decrypt_like_expired_then_unknown_signer_preserves_expired_fingerprint() {
        let mut collector = SignatureCollector::new(LegacyFoldMode::DecryptLike);
        collector.observe_synthetic(DetailedSignatureStatus::Expired, Some("expired-fp"));
        collector.observe_synthetic(DetailedSignatureStatus::UnknownSigner, None);

        assert_eq!(collector.legacy_status(), SignatureStatus::UnknownSigner);
        assert_eq!(
            collector.summary_state(),
            SignatureVerificationState::SignerEvidenceUnavailable
        );
        assert_eq!(collector.summary_entry_index(), Some(1));
        assert_eq!(
            collector.legacy_signer_fingerprint(),
            Some("expired-fp".to_string())
        );
        assert_eq!(collector.signatures.len(), 2);
    }

    #[test]
    fn repeated_signers_are_not_collapsed() {
        let mut collector = SignatureCollector::new(LegacyFoldMode::VerifyLike);
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
        let collector = SignatureCollector::new(LegacyFoldMode::DecryptLike);
        assert_eq!(collector.legacy_status(), SignatureStatus::NotSigned);
        assert_eq!(
            collector.summary_state(),
            SignatureVerificationState::NotSigned
        );
        assert_eq!(collector.summary_entry_index(), None);
        assert_eq!(collector.legacy_signer_fingerprint(), None);
        assert!(collector.signatures.is_empty());
    }

    fn state_from_detailed_status(
        status: &DetailedSignatureStatus,
        has_certificate: bool,
    ) -> SignatureVerificationState {
        match status {
            DetailedSignatureStatus::Valid => SignatureVerificationState::Verified,
            DetailedSignatureStatus::UnknownSigner if has_certificate => {
                SignatureVerificationState::SignerCertificateUnavailable
            }
            DetailedSignatureStatus::UnknownSigner => {
                SignatureVerificationState::SignerEvidenceUnavailable
            }
            DetailedSignatureStatus::Bad => SignatureVerificationState::Invalid,
            DetailedSignatureStatus::Expired => SignatureVerificationState::Expired,
        }
    }
}
