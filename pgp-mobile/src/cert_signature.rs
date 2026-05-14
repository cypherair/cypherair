use openpgp::packet::{Signature, UserID};
use openpgp::parse::Parse;
use openpgp::serialize::Marshal;
use openpgp::types::SignatureType;
use sequoia_openpgp as openpgp;

use crate::error::PgpError;
use crate::keys::{find_user_id_by_selector, UserIdSelectorInput};

/// OpenPGP certification signature kinds preserved across the FFI boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CertificationKind {
    Generic,
    Persona,
    Casual,
    Positive,
}

/// Status for certificate-signature verification results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CertificateSignatureStatus {
    Valid,
    Invalid,
    SignerMissing,
}

/// Result of certificate-signature verification.
///
/// Fingerprint fields are only populated after successful cryptographic
/// verification. `Invalid` and `SignerMissing` results clear both fields.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CertificateSignatureResult {
    /// Crypto-only verification status.
    pub status: CertificateSignatureStatus,
    /// Certification kind for User ID binding signatures.
    pub certification_kind: Option<CertificationKind>,
    /// Primary fingerprint of the cryptographically confirmed signer
    /// certificate. Populated only when `status == Valid`.
    pub signer_primary_fingerprint: Option<String>,
    /// Signing subkey fingerprint when `status == Valid` and the successful
    /// verification path used a non-primary signer key.
    pub signing_key_fingerprint: Option<String>,
}

pub fn verify_direct_key_signature(
    signature: &[u8],
    target_cert: &[u8],
    candidate_signers: &[Vec<u8>],
) -> Result<CertificateSignatureResult, PgpError> {
    let signature = parse_direct_key_signature(signature)?;
    let target_cert = parse_cert(target_cert, "Invalid target certificate")?;
    let candidate_signers = parse_candidate_signers(candidate_signers)?;

    if let Some(result) =
        verify_direct_key_issuer_guided(&signature, &target_cert, &candidate_signers)
    {
        return Ok(result);
    }

    verify_direct_key_fallback(&signature, &target_cert, &candidate_signers)
}

pub fn verify_user_id_binding_signature_by_selector(
    signature: &[u8],
    target_cert: &[u8],
    user_id_selector: &UserIdSelectorInput,
    candidate_signers: &[Vec<u8>],
) -> Result<CertificateSignatureResult, PgpError> {
    let (signature, certification_kind) = parse_user_id_binding_signature(signature)?;
    let target_cert_data = target_cert;
    let target_cert = parse_cert(target_cert_data, "Invalid target certificate")?;
    let user_id = find_user_id_by_selector(target_cert_data, user_id_selector)?;
    let candidate_signers = parse_candidate_signers(candidate_signers)?;

    if let Some(result) = verify_user_id_issuer_guided(
        &signature,
        &target_cert,
        &user_id,
        &candidate_signers,
        certification_kind,
    ) {
        return Ok(result);
    }

    verify_user_id_fallback(
        &signature,
        &target_cert,
        &user_id,
        &candidate_signers,
        certification_kind,
    )
}

pub fn generate_user_id_certification_by_selector(
    signer_secret_cert: &[u8],
    target_cert: &[u8],
    user_id_selector: &UserIdSelectorInput,
    certification_kind: CertificationKind,
) -> Result<Vec<u8>, PgpError> {
    let signer_cert = parse_cert(signer_secret_cert, "Invalid signer certificate")?;
    if !signer_cert.is_tsk() {
        return Err(PgpError::InvalidKeyData {
            reason: "Certification generation requires secret key material".to_string(),
        });
    }

    let target_cert_data = target_cert;
    let target_cert = parse_cert(target_cert_data, "Invalid target certificate")?;
    let user_id = find_user_id_by_selector(target_cert_data, user_id_selector)?;
    let mut signer = select_certification_signer(&signer_cert)?;
    let certification = user_id
        .certify(
            &mut signer,
            &target_cert,
            certification_kind.signature_type(),
            None,
            None,
        )
        .map_err(|e| PgpError::SigningFailed {
            reason: format!("Failed to generate User ID certification: {e}"),
        })?;

    let mut output = Vec::new();
    openpgp::Packet::from(certification)
        .serialize(&mut output)
        .map_err(|e| PgpError::SigningFailed {
            reason: format!("Failed to serialize User ID certification: {e}"),
        })?;
    Ok(output)
}

impl CertificationKind {
    pub fn signature_type(self) -> SignatureType {
        match self {
            CertificationKind::Generic => SignatureType::GenericCertification,
            CertificationKind::Persona => SignatureType::PersonaCertification,
            CertificationKind::Casual => SignatureType::CasualCertification,
            CertificationKind::Positive => SignatureType::PositiveCertification,
        }
    }
}

fn parse_direct_key_signature(signature: &[u8]) -> Result<Signature, PgpError> {
    let signature = parse_signature_packet(signature)?;
    if signature.typ() != SignatureType::DirectKey {
        return Err(PgpError::CorruptData {
            reason: format!("Expected direct-key signature, found {:?}", signature.typ()),
        });
    }
    Ok(signature)
}

fn parse_user_id_binding_signature(
    signature: &[u8],
) -> Result<(Signature, CertificationKind), PgpError> {
    let signature = parse_signature_packet(signature)?;
    let certification_kind =
        certification_kind_from_signature_type(signature.typ()).ok_or_else(|| {
            PgpError::CorruptData {
                reason: format!(
                    "Expected User ID certification signature, found {:?}",
                    signature.typ()
                ),
            }
        })?;
    Ok((signature, certification_kind))
}

fn parse_signature_packet(signature: &[u8]) -> Result<Signature, PgpError> {
    let packet = openpgp::Packet::from_bytes(signature).map_err(|e| PgpError::CorruptData {
        reason: format!("Failed to parse signature packet: {e}"),
    })?;
    match packet {
        openpgp::Packet::Signature(signature) => Ok(signature),
        _ => Err(PgpError::CorruptData {
            reason: "Expected a single signature packet".to_string(),
        }),
    }
}

fn parse_candidate_signers(candidate_signers: &[Vec<u8>]) -> Result<Vec<openpgp::Cert>, PgpError> {
    candidate_signers
        .iter()
        .map(|candidate| parse_cert(candidate, "Invalid candidate signer certificate"))
        .collect()
}

fn parse_cert(cert_data: &[u8], reason_prefix: &str) -> Result<openpgp::Cert, PgpError> {
    openpgp::Cert::from_bytes(cert_data).map_err(|e| PgpError::InvalidKeyData {
        reason: format!("{reason_prefix}: {e}"),
    })
}

fn certification_kind_from_signature_type(
    signature_type: SignatureType,
) -> Option<CertificationKind> {
    match signature_type {
        SignatureType::GenericCertification => Some(CertificationKind::Generic),
        SignatureType::PersonaCertification => Some(CertificationKind::Persona),
        SignatureType::CasualCertification => Some(CertificationKind::Casual),
        SignatureType::PositiveCertification => Some(CertificationKind::Positive),
        _ => None,
    }
}

type VerificationPublicKey =
    openpgp::packet::Key<openpgp::packet::key::PublicParts, openpgp::packet::key::UnspecifiedRole>;

struct EligibleVerificationKey<'a> {
    cert: &'a openpgp::Cert,
    key: VerificationPublicKey,
    selected_key_is_primary: bool,
}

fn eligible_verification_keys(cert: &openpgp::Cert) -> Vec<EligibleVerificationKey<'_>> {
    let mut eligible_keys = vec![EligibleVerificationKey {
        cert,
        key: cert.primary_key().key().clone().role_into_unspecified(),
        selected_key_is_primary: true,
    }];

    for subkey in cert.keys().subkeys() {
        if !is_explicit_certification_capable(&subkey) {
            continue;
        }

        eligible_keys.push(EligibleVerificationKey {
            cert,
            key: subkey.key().clone().role_into_unspecified(),
            selected_key_is_primary: false,
        });
    }

    eligible_keys
}

fn verify_direct_key_issuer_guided(
    signature: &Signature,
    target_cert: &openpgp::Cert,
    candidate_signers: &[openpgp::Cert],
) -> Option<CertificateSignatureResult> {
    let issuers = signature.get_issuers();
    if issuers.is_empty() {
        return None;
    }

    let mut saw_match = false;
    for cert in candidate_signers {
        for key in eligible_verification_keys(cert) {
            if issuers
                .iter()
                .any(|issuer| issuer.aliases(key.key.key_handle()))
            {
                saw_match = true;
                if signature
                    .verify_direct_key(&key.key, target_cert.primary_key().key())
                    .is_ok()
                {
                    return Some(valid_result(
                        key.cert,
                        key.selected_key_is_primary,
                        key.key.fingerprint().to_hex().to_lowercase(),
                        None,
                    ));
                }
            }
        }
    }

    saw_match.then_some(invalid_result(None))
}

fn verify_direct_key_fallback(
    signature: &Signature,
    target_cert: &openpgp::Cert,
    candidate_signers: &[openpgp::Cert],
) -> Result<CertificateSignatureResult, PgpError> {
    let mut attempted = false;

    for cert in candidate_signers {
        attempted = true;
        for key in eligible_verification_keys(cert) {
            if signature
                .verify_direct_key(&key.key, target_cert.primary_key().key())
                .is_ok()
            {
                return Ok(valid_result(
                    key.cert,
                    key.selected_key_is_primary,
                    key.key.fingerprint().to_hex().to_lowercase(),
                    None,
                ));
            }
        }
    }

    Ok(if attempted {
        invalid_result(None)
    } else {
        signer_missing_result(None)
    })
}

fn verify_user_id_issuer_guided(
    signature: &Signature,
    target_cert: &openpgp::Cert,
    user_id: &UserID,
    candidate_signers: &[openpgp::Cert],
    certification_kind: CertificationKind,
) -> Option<CertificateSignatureResult> {
    let issuers = signature.get_issuers();
    if issuers.is_empty() {
        return None;
    }

    let mut saw_match = false;
    for cert in candidate_signers {
        for key in eligible_verification_keys(cert) {
            if issuers
                .iter()
                .any(|issuer| issuer.aliases(key.key.key_handle()))
            {
                saw_match = true;
                if signature
                    .verify_userid_binding(&key.key, target_cert.primary_key().key(), user_id)
                    .is_ok()
                {
                    return Some(valid_result(
                        key.cert,
                        key.selected_key_is_primary,
                        key.key.fingerprint().to_hex().to_lowercase(),
                        Some(certification_kind),
                    ));
                }
            }
        }
    }

    saw_match.then_some(invalid_result(Some(certification_kind)))
}

fn verify_user_id_fallback(
    signature: &Signature,
    target_cert: &openpgp::Cert,
    user_id: &UserID,
    candidate_signers: &[openpgp::Cert],
    certification_kind: CertificationKind,
) -> Result<CertificateSignatureResult, PgpError> {
    let mut attempted = false;

    for cert in candidate_signers {
        attempted = true;
        for key in eligible_verification_keys(cert) {
            if signature
                .verify_userid_binding(&key.key, target_cert.primary_key().key(), user_id)
                .is_ok()
            {
                return Ok(valid_result(
                    key.cert,
                    key.selected_key_is_primary,
                    key.key.fingerprint().to_hex().to_lowercase(),
                    Some(certification_kind),
                ));
            }
        }
    }

    Ok(if attempted {
        invalid_result(Some(certification_kind))
    } else {
        signer_missing_result(Some(certification_kind))
    })
}

fn valid_result(
    cert: &openpgp::Cert,
    selected_key_is_primary: bool,
    selected_key_fingerprint: String,
    certification_kind: Option<CertificationKind>,
) -> CertificateSignatureResult {
    CertificateSignatureResult {
        status: CertificateSignatureStatus::Valid,
        certification_kind,
        signer_primary_fingerprint: Some(cert.fingerprint().to_hex().to_lowercase()),
        signing_key_fingerprint: if selected_key_is_primary {
            None
        } else {
            Some(selected_key_fingerprint)
        },
    }
}

fn invalid_result(certification_kind: Option<CertificationKind>) -> CertificateSignatureResult {
    CertificateSignatureResult {
        status: CertificateSignatureStatus::Invalid,
        certification_kind,
        signer_primary_fingerprint: None,
        signing_key_fingerprint: None,
    }
}

fn signer_missing_result(
    certification_kind: Option<CertificationKind>,
) -> CertificateSignatureResult {
    CertificateSignatureResult {
        status: CertificateSignatureStatus::SignerMissing,
        certification_kind,
        signer_primary_fingerprint: None,
        signing_key_fingerprint: None,
    }
}

fn select_certification_signer(cert: &openpgp::Cert) -> Result<openpgp::crypto::KeyPair, PgpError> {
    if let Ok(primary) = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .and_then(|key| key.into_keypair())
    {
        return Ok(primary);
    }

    for subkey in cert.keys().subkeys() {
        if !is_explicit_certification_capable(&subkey) {
            continue;
        }

        if let Ok(signer) = subkey
            .key()
            .clone()
            .parts_into_secret()
            .and_then(|key| key.into_keypair())
        {
            return Ok(signer);
        }
    }

    Err(PgpError::SigningFailed {
        reason: "No usable certification-capable secret key found".to_string(),
    })
}

fn is_explicit_certification_capable<P, R, R2>(
    key: &openpgp::cert::prelude::KeyAmalgamation<'_, P, R, R2>,
) -> bool
where
    P: openpgp::packet::key::KeyParts,
    R: openpgp::packet::key::KeyRole,
    R2: Copy + std::fmt::Debug,
{
    key.self_signatures().any(|signature| {
        signature
            .key_flags()
            .map(|flags| flags.for_certification())
            .unwrap_or(false)
    })
}
