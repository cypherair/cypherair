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
use crate::signature_details::{DecryptDetailedResult, LegacyFoldMode, SignatureCollector};

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
                    if should_propagate_runtime_error(error) {
                        return Err(error.into());
                    }
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
    ExternalP256Decryptor::new(key.key().clone().role_into_unspecified(), |_request| {
        Err(ExternalP256DecryptorError::ExternalFailure(
            crate::keys::ExternalP256KeyAgreementFailureCategory::ExternalOperationFailed,
        ))
    })
    .map(|_| ())
    .map_err(|e| PgpError::InvalidKeyData {
        reason: format!("Invalid external P-256 key-agreement subkey: {e}"),
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

fn should_propagate_runtime_error(error: ExternalP256DecryptorError) -> bool {
    matches!(
        error,
        ExternalP256DecryptorError::OperationCancelled
            | ExternalP256DecryptorError::ExternalFailure(_)
    )
}

#[cfg(test)]
mod tests;
