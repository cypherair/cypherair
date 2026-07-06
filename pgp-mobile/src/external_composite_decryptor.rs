mod core;

use std::sync::Arc;

use sequoia_openpgp as openpgp;
use zeroize::Zeroizing;

use openpgp::crypto::SessionKey;
use openpgp::parse::stream::{DecryptionHelper, MessageStructure, VerificationHelper};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;

use crate::decrypt::{decrypt_with_helper, parse_verification_certs};
use crate::error::PgpError;
use crate::keys::{
    ExternalCompositeKeyAgreementError, ExternalMlKem1024DecapsulationProvider,
    ExternalMlKem1024DecapsulationRequest, ExternalMlKem768DecapsulationProvider,
    ExternalMlKem768DecapsulationRequest,
};
use crate::signature_details::{
    DecryptDetailedResult, FileDecryptDetailedResult, SignatureCollector, SummaryFoldMode,
};

pub(crate) use core::{
    ExternalCompositeDecryptor, ExternalCompositeDecryptorError, ExternalCompositeHighDecryptor,
    ExternalMlKem1024Share, ExternalMlKem768Share,
};

struct ExternalCompositeDecryptHelper {
    recipient_cert: openpgp::Cert,
    verifier_certs: Vec<openpgp::Cert>,
    expected_key_agreement_fingerprint: String,
    classical_ecdh_secret: Zeroizing<Vec<u8>>,
    decapsulation_provider: Arc<dyn ExternalMlKem768DecapsulationProvider>,
    collector: SignatureCollector,
}

impl VerificationHelper for ExternalCompositeDecryptHelper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        let mut all_certs = self.verifier_certs.clone();
        all_certs.push(self.recipient_cert.clone());
        Ok(all_certs)
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        self.collector.observe_structure(structure);
        Ok(())
    }
}

impl DecryptionHelper for ExternalCompositeDecryptHelper {
    fn decrypt(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<openpgp::types::SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<openpgp::types::SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<openpgp::Cert>> {
        let policy = StandardPolicy::new();

        for pkesk in pkesks {
            // An explicit recipient keyid that matches this key means the PKESK
            // is genuinely addressed to it. A wildcard / hidden recipient
            // (`recipient() == None`) speculatively matches every key, so a
            // matching key here may simply not be the intended recipient.
            let explicit_recipient = pkesk.recipient().is_some();
            for ka in self
                .recipient_cert
                .keys()
                .with_policy(&policy, None)
                .supported()
                .key_handles(pkesk.recipient())
                .for_transport_encryption()
            {
                if !fingerprint_matches(
                    &ka.key().fingerprint().to_hex(),
                    &self.expected_key_agreement_fingerprint,
                ) {
                    continue;
                }
                let provider = Arc::clone(&self.decapsulation_provider);
                let mut decryptor = ExternalCompositeDecryptor::new(
                    ka.key().clone().role_into_unspecified(),
                    &self.classical_ecdh_secret,
                    move |request| decapsulate_mlkem768(Arc::clone(&provider), request),
                )?;
                let decrypted = pkesk.decrypt(&mut decryptor, sym_algo);
                if let Some(error) = decryptor.take_last_error() {
                    // Hard-abort fail-closed when the PKESK is explicitly
                    // addressed to this key, or when the classical component or
                    // external decapsulation was actually exercised and failed:
                    // never silently downgrade a genuine failure to "no matching
                    // key".
                    //
                    // For a wildcard / hidden recipient, a pre-callback rejection
                    // (e.g. a non-composite packet intended for a different
                    // recipient) is a non-match: skip it and keep trying later
                    // PKESKs instead of failing an otherwise-decryptable
                    // multi-recipient message.
                    if explicit_recipient || error.is_external_operation_failure() {
                        return Err(error.into());
                    }
                    continue;
                }
                if let Some((algo, session_key)) = decrypted {
                    if decrypt(algo, &session_key) {
                        return Ok(None);
                    }
                }
            }
        }

        Err(openpgp::anyhow::anyhow!("No key to decrypt message"))
    }
}

pub(crate) fn decrypt_detailed_with_external_composite_key_agreement(
    ciphertext: &[u8],
    recipient_public_cert_data: &[u8],
    key_agreement_subkey_fingerprint: &str,
    classical_ecdh_secret: &[u8],
    decapsulation_provider: Arc<dyn ExternalMlKem768DecapsulationProvider>,
    verification_keys: &[Vec<u8>],
) -> Result<DecryptDetailedResult, PgpError> {
    let recipient_cert = openpgp::Cert::from_bytes(recipient_public_cert_data).map_err(|e| {
        PgpError::InvalidKeyData {
            reason: format!("Invalid recipient public certificate: {e}"),
        }
    })?;
    if recipient_cert.is_tsk() {
        return Err(PgpError::InvalidKeyData {
            reason: "External composite key agreement requires a public-only certificate"
                .to_string(),
        });
    }

    select_external_composite_key_agreement_key(&recipient_cert, key_agreement_subkey_fingerprint)?;

    let verifier_certs = parse_verification_certs(verification_keys)?;
    let policy = StandardPolicy::new();
    let helper = ExternalCompositeDecryptHelper {
        recipient_cert,
        verifier_certs,
        expected_key_agreement_fingerprint: key_agreement_subkey_fingerprint.to_string(),
        classical_ecdh_secret: Zeroizing::new(classical_ecdh_secret.to_vec()),
        decapsulation_provider,
        collector: SignatureCollector::new(SummaryFoldMode::DecryptLike),
    };
    let (plaintext, helper) = decrypt_with_helper(ciphertext, &policy, helper)?;
    let (summary_state, summary_entry_index, signatures) = helper.collector.into_parts();

    Ok(DecryptDetailedResult {
        summary_state,
        summary_entry_index,
        signatures,
        plaintext,
    })
}

/// Streaming-file analog of `decrypt_detailed_with_external_composite_key_agreement`.
///
/// Public-only recipient certificate validation, key-agreement subkey selection, and
/// the `ExternalCompositeDecryptHelper` are identical to the in-memory path. Only the
/// transport differs: streaming temp-file I/O with progress/cancellation is delegated
/// to `streaming::decrypt_file_with_helper`, which enforces the success-only output
/// contract. Sequoia still owns session-key validation, payload authentication,
/// verification folding, and plaintext release. There is no secret-certificate path
/// and no software fallback.
pub(crate) fn decrypt_file_detailed_with_external_composite_key_agreement(
    input_path: &str,
    output_path: &str,
    recipient_public_cert_data: &[u8],
    key_agreement_subkey_fingerprint: &str,
    classical_ecdh_secret: &[u8],
    decapsulation_provider: Arc<dyn ExternalMlKem768DecapsulationProvider>,
    verification_keys: &[Vec<u8>],
    progress: Option<Arc<dyn crate::streaming::StreamingProgressReporter>>,
) -> Result<FileDecryptDetailedResult, PgpError> {
    let recipient_cert = openpgp::Cert::from_bytes(recipient_public_cert_data).map_err(|e| {
        PgpError::InvalidKeyData {
            reason: format!("Invalid recipient public certificate: {e}"),
        }
    })?;
    if recipient_cert.is_tsk() {
        return Err(PgpError::InvalidKeyData {
            reason: "External composite key agreement requires a public-only certificate"
                .to_string(),
        });
    }

    select_external_composite_key_agreement_key(&recipient_cert, key_agreement_subkey_fingerprint)?;

    let verifier_certs = parse_verification_certs(verification_keys)?;
    let policy = StandardPolicy::new();
    let helper = ExternalCompositeDecryptHelper {
        recipient_cert,
        verifier_certs,
        expected_key_agreement_fingerprint: key_agreement_subkey_fingerprint.to_string(),
        classical_ecdh_secret: Zeroizing::new(classical_ecdh_secret.to_vec()),
        decapsulation_provider,
        collector: SignatureCollector::new(SummaryFoldMode::DecryptLike),
    };
    let helper = crate::streaming::decrypt_file_with_helper(
        input_path,
        output_path,
        &policy,
        helper,
        progress,
    )?;
    let (summary_state, summary_entry_index, signatures) = helper.collector.into_parts();

    Ok(FileDecryptDetailedResult {
        summary_state,
        summary_entry_index,
        signatures,
    })
}

fn select_external_composite_key_agreement_key(
    recipient_cert: &openpgp::Cert,
    key_agreement_subkey_fingerprint: &str,
) -> Result<(), PgpError> {
    let policy = StandardPolicy::new();
    let mut matches = recipient_cert
        .keys()
        .with_policy(&policy, None)
        .supported()
        .for_transport_encryption()
        .filter(|ka| {
            fingerprint_matches(
                &ka.key().fingerprint().to_hex(),
                key_agreement_subkey_fingerprint,
            )
        });

    let Some(key) = matches.next() else {
        return Err(PgpError::NoMatchingKey);
    };
    if matches.next().is_some() {
        return Err(PgpError::InvalidKeyData {
            reason: "Ambiguous external composite key-agreement subkey".to_string(),
        });
    }
    core::validate_composite_key_agreement_public_key(&key.key().clone().role_into_unspecified())
        .map_err(|e| PgpError::InvalidKeyData {
            reason: format!("Invalid external composite key-agreement subkey: {e}"),
        })
}

fn fingerprint_matches(actual: &str, expected: &str) -> bool {
    actual.eq_ignore_ascii_case(expected)
}

fn decapsulate_mlkem768(
    provider: Arc<dyn ExternalMlKem768DecapsulationProvider>,
    request: ExternalMlKem768DecapsulationRequest,
) -> Result<ExternalMlKem768Share, ExternalCompositeDecryptorError> {
    let response = provider
        .decapsulate_mlkem768(request)
        .map_err(external_key_agreement_error_to_decryptor_error)?;
    Ok(ExternalMlKem768Share::new(response.raw))
}

fn external_key_agreement_error_to_decryptor_error(
    error: ExternalCompositeKeyAgreementError,
) -> ExternalCompositeDecryptorError {
    match error {
        ExternalCompositeKeyAgreementError::Failed { category } => {
            ExternalCompositeDecryptorError::ExternalFailure(category)
        }
        ExternalCompositeKeyAgreementError::OperationCancelled => {
            ExternalCompositeDecryptorError::OperationCancelled
        }
    }
}

// Device-Bound Post-Quantum · High (ML-KEM-1024 + X448) decryption, parallel to
// the 65/768 path above. The helper structure, wildcard-recipient handling, and
// fail-closed error taxonomy are identical; only the provider, decryptor, and
// key-agreement validation are algorithm-specialized.

struct ExternalCompositeHighDecryptHelper {
    recipient_cert: openpgp::Cert,
    verifier_certs: Vec<openpgp::Cert>,
    expected_key_agreement_fingerprint: String,
    classical_ecdh_secret: Zeroizing<Vec<u8>>,
    decapsulation_provider: Arc<dyn ExternalMlKem1024DecapsulationProvider>,
    collector: SignatureCollector,
}

impl VerificationHelper for ExternalCompositeHighDecryptHelper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        let mut all_certs = self.verifier_certs.clone();
        all_certs.push(self.recipient_cert.clone());
        Ok(all_certs)
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        self.collector.observe_structure(structure);
        Ok(())
    }
}

impl DecryptionHelper for ExternalCompositeHighDecryptHelper {
    fn decrypt(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<openpgp::types::SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<openpgp::types::SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<openpgp::Cert>> {
        let policy = StandardPolicy::new();

        for pkesk in pkesks {
            let explicit_recipient = pkesk.recipient().is_some();
            for ka in self
                .recipient_cert
                .keys()
                .with_policy(&policy, None)
                .supported()
                .key_handles(pkesk.recipient())
                .for_transport_encryption()
            {
                if !fingerprint_matches(
                    &ka.key().fingerprint().to_hex(),
                    &self.expected_key_agreement_fingerprint,
                ) {
                    continue;
                }
                let provider = Arc::clone(&self.decapsulation_provider);
                let mut decryptor = ExternalCompositeHighDecryptor::new(
                    ka.key().clone().role_into_unspecified(),
                    &self.classical_ecdh_secret,
                    move |request| decapsulate_mlkem1024(Arc::clone(&provider), request),
                )?;
                let decrypted = pkesk.decrypt(&mut decryptor, sym_algo);
                if let Some(error) = decryptor.take_last_error() {
                    if explicit_recipient || error.is_external_operation_failure() {
                        return Err(error.into());
                    }
                    continue;
                }
                if let Some((algo, session_key)) = decrypted {
                    if decrypt(algo, &session_key) {
                        return Ok(None);
                    }
                }
            }
        }

        Err(openpgp::anyhow::anyhow!("No key to decrypt message"))
    }
}

pub(crate) fn decrypt_detailed_with_external_composite_high_key_agreement(
    ciphertext: &[u8],
    recipient_public_cert_data: &[u8],
    key_agreement_subkey_fingerprint: &str,
    classical_ecdh_secret: &[u8],
    decapsulation_provider: Arc<dyn ExternalMlKem1024DecapsulationProvider>,
    verification_keys: &[Vec<u8>],
) -> Result<DecryptDetailedResult, PgpError> {
    let recipient_cert = openpgp::Cert::from_bytes(recipient_public_cert_data).map_err(|e| {
        PgpError::InvalidKeyData {
            reason: format!("Invalid recipient public certificate: {e}"),
        }
    })?;
    if recipient_cert.is_tsk() {
        return Err(PgpError::InvalidKeyData {
            reason: "External composite key agreement requires a public-only certificate"
                .to_string(),
        });
    }

    select_external_composite_high_key_agreement_key(
        &recipient_cert,
        key_agreement_subkey_fingerprint,
    )?;

    let verifier_certs = parse_verification_certs(verification_keys)?;
    let policy = StandardPolicy::new();
    let helper = ExternalCompositeHighDecryptHelper {
        recipient_cert,
        verifier_certs,
        expected_key_agreement_fingerprint: key_agreement_subkey_fingerprint.to_string(),
        classical_ecdh_secret: Zeroizing::new(classical_ecdh_secret.to_vec()),
        decapsulation_provider,
        collector: SignatureCollector::new(SummaryFoldMode::DecryptLike),
    };
    let (plaintext, helper) = decrypt_with_helper(ciphertext, &policy, helper)?;
    let (summary_state, summary_entry_index, signatures) = helper.collector.into_parts();

    Ok(DecryptDetailedResult {
        summary_state,
        summary_entry_index,
        signatures,
        plaintext,
    })
}

/// Streaming-file analog of `decrypt_detailed_with_external_composite_high_key_agreement`.
pub(crate) fn decrypt_file_detailed_with_external_composite_high_key_agreement(
    input_path: &str,
    output_path: &str,
    recipient_public_cert_data: &[u8],
    key_agreement_subkey_fingerprint: &str,
    classical_ecdh_secret: &[u8],
    decapsulation_provider: Arc<dyn ExternalMlKem1024DecapsulationProvider>,
    verification_keys: &[Vec<u8>],
    progress: Option<Arc<dyn crate::streaming::StreamingProgressReporter>>,
) -> Result<FileDecryptDetailedResult, PgpError> {
    let recipient_cert = openpgp::Cert::from_bytes(recipient_public_cert_data).map_err(|e| {
        PgpError::InvalidKeyData {
            reason: format!("Invalid recipient public certificate: {e}"),
        }
    })?;
    if recipient_cert.is_tsk() {
        return Err(PgpError::InvalidKeyData {
            reason: "External composite key agreement requires a public-only certificate"
                .to_string(),
        });
    }

    select_external_composite_high_key_agreement_key(
        &recipient_cert,
        key_agreement_subkey_fingerprint,
    )?;

    let verifier_certs = parse_verification_certs(verification_keys)?;
    let policy = StandardPolicy::new();
    let helper = ExternalCompositeHighDecryptHelper {
        recipient_cert,
        verifier_certs,
        expected_key_agreement_fingerprint: key_agreement_subkey_fingerprint.to_string(),
        classical_ecdh_secret: Zeroizing::new(classical_ecdh_secret.to_vec()),
        decapsulation_provider,
        collector: SignatureCollector::new(SummaryFoldMode::DecryptLike),
    };
    let helper = crate::streaming::decrypt_file_with_helper(
        input_path,
        output_path,
        &policy,
        helper,
        progress,
    )?;
    let (summary_state, summary_entry_index, signatures) = helper.collector.into_parts();

    Ok(FileDecryptDetailedResult {
        summary_state,
        summary_entry_index,
        signatures,
    })
}

fn select_external_composite_high_key_agreement_key(
    recipient_cert: &openpgp::Cert,
    key_agreement_subkey_fingerprint: &str,
) -> Result<(), PgpError> {
    let policy = StandardPolicy::new();
    let mut matches = recipient_cert
        .keys()
        .with_policy(&policy, None)
        .supported()
        .for_transport_encryption()
        .filter(|ka| {
            fingerprint_matches(
                &ka.key().fingerprint().to_hex(),
                key_agreement_subkey_fingerprint,
            )
        });

    let Some(key) = matches.next() else {
        return Err(PgpError::NoMatchingKey);
    };
    if matches.next().is_some() {
        return Err(PgpError::InvalidKeyData {
            reason: "Ambiguous external composite key-agreement subkey".to_string(),
        });
    }
    core::validate_composite_high_key_agreement_public_key(
        &key.key().clone().role_into_unspecified(),
    )
    .map_err(|e| PgpError::InvalidKeyData {
        reason: format!("Invalid external composite key-agreement subkey: {e}"),
    })
}

fn decapsulate_mlkem1024(
    provider: Arc<dyn ExternalMlKem1024DecapsulationProvider>,
    request: ExternalMlKem1024DecapsulationRequest,
) -> Result<ExternalMlKem1024Share, ExternalCompositeDecryptorError> {
    let response = provider
        .decapsulate_mlkem1024(request)
        .map_err(external_key_agreement_error_to_decryptor_error)?;
    Ok(ExternalMlKem1024Share::new(response.raw))
}

#[cfg(test)]
mod tests;
