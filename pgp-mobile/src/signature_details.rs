use openpgp::parse::stream::{
    GoodChecksum, MessageLayer, MessageStructure, VerificationError, VerificationResult,
};
use sequoia_openpgp as openpgp;

use crate::decrypt::{is_expired_error, SignatureStatus};

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
}

/// Detailed result for in-memory verification APIs.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VerifyDetailedResult {
    pub legacy_status: SignatureStatus,
    pub legacy_signer_fingerprint: Option<String>,
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
    pub signatures: Vec<DetailedSignatureEntry>,
    pub plaintext: Vec<u8>,
}

/// Detailed result for file verification APIs.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FileVerifyDetailedResult {
    pub legacy_status: SignatureStatus,
    pub legacy_signer_fingerprint: Option<String>,
    pub signatures: Vec<DetailedSignatureEntry>,
}

/// Detailed result for file decrypt APIs.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FileDecryptDetailedResult {
    pub legacy_status: SignatureStatus,
    pub legacy_signer_fingerprint: Option<String>,
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
    legacy_stopped: bool,
    signatures: Vec<DetailedSignatureEntry>,
}

impl SignatureCollector {
    pub(crate) fn new(mode: LegacyFoldMode) -> Self {
        Self {
            mode,
            legacy_status: None,
            legacy_signer_fingerprint: None,
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

    pub(crate) fn signatures(&self) -> Vec<DetailedSignatureEntry> {
        self.signatures.clone()
    }

    pub(crate) fn into_parts(
        self,
    ) -> (SignatureStatus, Option<String>, Vec<DetailedSignatureEntry>) {
        (
            self.legacy_status.unwrap_or(SignatureStatus::NotSigned),
            self.legacy_signer_fingerprint,
            self.signatures,
        )
    }

    fn observe_result(&mut self, result: VerificationResult) {
        self.signatures.push(entry_from_result(&result));

        if self.legacy_stopped {
            return;
        }

        match result {
            Ok(GoodChecksum { ka, .. }) => {
                self.legacy_status = Some(SignatureStatus::Valid);
                self.legacy_signer_fingerprint =
                    Some(ka.cert().fingerprint().to_hex().to_lowercase());
                self.legacy_stopped = true;
            }
            Err(VerificationError::MissingKey { .. }) => {
                self.legacy_status = Some(SignatureStatus::UnknownSigner);
            }
            Err(VerificationError::BadKey { ka, error, .. }) => {
                if is_expired_error(&error) {
                    self.legacy_status = Some(SignatureStatus::Expired);
                    self.legacy_signer_fingerprint =
                        Some(ka.cert().fingerprint().to_hex().to_lowercase());
                } else {
                    self.legacy_status = Some(SignatureStatus::Bad);
                }

                if matches!(self.mode, LegacyFoldMode::VerifyLike) {
                    self.legacy_stopped = true;
                }
            }
            Err(_) => {
                self.legacy_status = Some(SignatureStatus::Bad);
                if matches!(self.mode, LegacyFoldMode::VerifyLike) {
                    self.legacy_stopped = true;
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
            let signer_primary_fingerprint =
                signer_primary_fingerprint.map(std::string::ToString::to_string);
            self.signatures.push(DetailedSignatureEntry {
                status: status.clone(),
                signer_primary_fingerprint: signer_primary_fingerprint.clone(),
            });

            if self.legacy_stopped {
                return;
            }

            match status {
                DetailedSignatureStatus::Valid => {
                    self.legacy_status = Some(SignatureStatus::Valid);
                    self.legacy_signer_fingerprint = signer_primary_fingerprint;
                    self.legacy_stopped = true;
                }
                DetailedSignatureStatus::UnknownSigner => {
                    self.legacy_status = Some(SignatureStatus::UnknownSigner);
                }
                DetailedSignatureStatus::Bad => {
                    self.legacy_status = Some(SignatureStatus::Bad);
                    if matches!(self.mode, LegacyFoldMode::VerifyLike) {
                        self.legacy_stopped = true;
                    }
                }
                DetailedSignatureStatus::Expired => {
                    self.legacy_status = Some(SignatureStatus::Expired);
                    self.legacy_signer_fingerprint = signer_primary_fingerprint;
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
            collector.legacy_signer_fingerprint(),
            Some("signer-a".to_string())
        );
        assert_eq!(collector.signatures.len(), 3);
        assert_eq!(
            collector.signatures[0].status,
            DetailedSignatureStatus::Valid
        );
        assert_eq!(
            collector.signatures[1].status,
            DetailedSignatureStatus::UnknownSigner
        );
        assert_eq!(collector.signatures[2].status, DetailedSignatureStatus::Bad);
    }

    #[test]
    fn decrypt_like_expired_then_bad_preserves_expired_fingerprint() {
        let mut collector = SignatureCollector::new(LegacyFoldMode::DecryptLike);
        collector.observe_synthetic(DetailedSignatureStatus::Expired, Some("expired-fp"));
        collector.observe_synthetic(DetailedSignatureStatus::Bad, Some("bad-fp"));

        assert_eq!(collector.legacy_status(), SignatureStatus::Bad);
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
        assert_eq!(collector.legacy_signer_fingerprint(), None);
        assert!(collector.signatures.is_empty());
    }
}
