mod core;

use std::sync::Arc;

use sequoia_openpgp as openpgp;

use openpgp::crypto::SessionKey;
use openpgp::parse::stream::{DecryptionHelper, MessageStructure, VerificationHelper};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;

use crate::decrypt::{decrypt_with_helper, parse_verification_certs};
use crate::error::PgpError;
use crate::keys::{
    ExternalP256KeyAgreementError, ExternalP256KeyAgreementProvider,
    ExternalP256KeyAgreementRequest,
};
use crate::signature_details::{
    DecryptDetailedResult, FileDecryptDetailedResult, LegacyFoldMode, SignatureCollector,
};

pub(crate) use core::{
    ExternalP256Decryptor, ExternalP256DecryptorError, ExternalP256SharedSecret,
};
#[cfg(test)]
pub(crate) use core::{
    P256_PUBLIC_KEY_LENGTH, P256_SHARED_SECRET_LENGTH, P256_UNCOMPRESSED_POINT_TAG,
};

struct ExternalDecryptHelper {
    recipient_cert: openpgp::Cert,
    verifier_certs: Vec<openpgp::Cert>,
    expected_key_agreement_fingerprint: String,
    key_agreement_provider: Arc<dyn ExternalP256KeyAgreementProvider>,
    collector: SignatureCollector,
}

impl VerificationHelper for ExternalDecryptHelper {
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

impl DecryptionHelper for ExternalDecryptHelper {
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
                let provider = Arc::clone(&self.key_agreement_provider);
                let mut decryptor = ExternalP256Decryptor::new(
                    ka.key().clone().role_into_unspecified(),
                    move |request| derive_shared_secret(Arc::clone(&provider), request),
                )?;
                let decrypted = pkesk.decrypt(&mut decryptor, sym_algo);
                if let Some(error) = decryptor.take_last_error() {
                    // Hard-abort fail-closed when the PKESK is explicitly
                    // addressed to this key, or when the external key-agreement
                    // operation was actually attempted and failed: never silently
                    // downgrade a genuine failure to "no matching key".
                    //
                    // For a wildcard / hidden recipient, a pre-callback rejection
                    // (e.g. a non-ECDH packet intended for a different recipient)
                    // is a non-match: skip it and keep trying later PKESKs instead
                    // of failing an otherwise-decryptable multi-recipient message.
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

pub(crate) fn decrypt_detailed_with_external_p256_key_agreement(
    ciphertext: &[u8],
    recipient_public_cert_data: &[u8],
    key_agreement_subkey_fingerprint: &str,
    key_agreement_provider: Arc<dyn ExternalP256KeyAgreementProvider>,
    verification_keys: &[Vec<u8>],
) -> Result<DecryptDetailedResult, PgpError> {
    let recipient_cert = openpgp::Cert::from_bytes(recipient_public_cert_data).map_err(|e| {
        PgpError::InvalidKeyData {
            reason: format!("Invalid recipient public certificate: {e}"),
        }
    })?;
    if recipient_cert.is_tsk() {
        return Err(PgpError::InvalidKeyData {
            reason: "External P-256 key agreement requires a public-only certificate".to_string(),
        });
    }

    select_external_p256_key_agreement_key(&recipient_cert, key_agreement_subkey_fingerprint)?;

    let verifier_certs = parse_verification_certs(verification_keys)?;
    let policy = StandardPolicy::new();
    let helper = ExternalDecryptHelper {
        recipient_cert,
        verifier_certs,
        expected_key_agreement_fingerprint: key_agreement_subkey_fingerprint.to_string(),
        key_agreement_provider,
        collector: SignatureCollector::new(LegacyFoldMode::DecryptLike),
    };
    let (plaintext, helper) = decrypt_with_helper(ciphertext, &policy, helper)?;
    let (legacy_status, legacy_signer_fingerprint, summary_state, summary_entry_index, signatures) =
        helper.collector.into_parts();

    Ok(DecryptDetailedResult {
        legacy_status,
        legacy_signer_fingerprint,
        summary_state,
        summary_entry_index,
        signatures,
        plaintext,
    })
}

/// Streaming-file analog of `decrypt_detailed_with_external_p256_key_agreement`.
///
/// Public-only recipient certificate validation, key-agreement subkey selection, and
/// the `ExternalDecryptHelper` are identical to the in-memory path. Only the transport
/// differs: streaming temp-file I/O with progress/cancellation is delegated to
/// `streaming::decrypt_file_with_helper`, which enforces the success-only output
/// contract. Sequoia still owns ECDH KDF, AES Key Wrap unwrap, session-key validation,
/// payload authentication, verification folding, and plaintext release. There is no
/// secret-certificate path and no software fallback.
pub(crate) fn decrypt_file_detailed_with_external_p256_key_agreement(
    input_path: &str,
    output_path: &str,
    recipient_public_cert_data: &[u8],
    key_agreement_subkey_fingerprint: &str,
    key_agreement_provider: Arc<dyn ExternalP256KeyAgreementProvider>,
    verification_keys: &[Vec<u8>],
    progress: Option<Arc<dyn crate::streaming::ProgressReporter>>,
) -> Result<FileDecryptDetailedResult, PgpError> {
    let recipient_cert = openpgp::Cert::from_bytes(recipient_public_cert_data).map_err(|e| {
        PgpError::InvalidKeyData {
            reason: format!("Invalid recipient public certificate: {e}"),
        }
    })?;
    if recipient_cert.is_tsk() {
        return Err(PgpError::InvalidKeyData {
            reason: "External P-256 key agreement requires a public-only certificate".to_string(),
        });
    }

    select_external_p256_key_agreement_key(&recipient_cert, key_agreement_subkey_fingerprint)?;

    let verifier_certs = parse_verification_certs(verification_keys)?;
    let policy = StandardPolicy::new();
    let helper = ExternalDecryptHelper {
        recipient_cert,
        verifier_certs,
        expected_key_agreement_fingerprint: key_agreement_subkey_fingerprint.to_string(),
        key_agreement_provider,
        collector: SignatureCollector::new(LegacyFoldMode::DecryptLike),
    };
    let helper =
        crate::streaming::decrypt_file_with_helper(input_path, output_path, &policy, helper, progress)?;
    let (legacy_status, legacy_signer_fingerprint, summary_state, summary_entry_index, signatures) =
        helper.collector.into_parts();

    Ok(FileDecryptDetailedResult {
        legacy_status,
        legacy_signer_fingerprint,
        summary_state,
        summary_entry_index,
        signatures,
    })
}

fn select_external_p256_key_agreement_key(
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
            reason: "Ambiguous external P-256 key-agreement subkey".to_string(),
        });
    }
    core::validate_p256_ecdh_public_key(&key.key().clone().role_into_unspecified()).map_err(|e| {
        PgpError::InvalidKeyData {
            reason: format!("Invalid external P-256 key-agreement subkey: {e}"),
        }
    })
}

fn fingerprint_matches(actual: &str, expected: &str) -> bool {
    actual.eq_ignore_ascii_case(expected)
}

fn derive_shared_secret(
    provider: Arc<dyn ExternalP256KeyAgreementProvider>,
    request: ExternalP256KeyAgreementRequest,
) -> Result<ExternalP256SharedSecret, ExternalP256DecryptorError> {
    let response = provider
        .derive_shared_secret(request)
        .map_err(external_key_agreement_error_to_decryptor_error)?;
    Ok(ExternalP256SharedSecret::new(response.raw))
}

fn external_key_agreement_error_to_decryptor_error(
    error: ExternalP256KeyAgreementError,
) -> ExternalP256DecryptorError {
    match error {
        ExternalP256KeyAgreementError::Failed { category } => {
            ExternalP256DecryptorError::ExternalFailure(category)
        }
        ExternalP256KeyAgreementError::OperationCancelled => {
            ExternalP256DecryptorError::OperationCancelled
        }
    }
}

#[cfg(test)]
mod tests;
