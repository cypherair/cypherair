use super::*;
use crate::external_composite_signer::composite_signer_for_provider;
use crate::external_signer::{map_external_signing_error, signer_for_provider};
use crate::keys::{ExternalMlDsa65SigningProvider, ExternalP256SigningProvider};
use openpgp::packet::signature::SignatureBuilder;
use openpgp::packet::{key, Key};
use openpgp::types::{HashAlgorithm, RevocationStatus};
use std::sync::Arc;

/// Result of modifying a certificate's expiration time.
///
/// SECURITY: `cert_data` contains unencrypted secret key material. The Swift caller must:
/// 1. SE-wrap `cert_data` immediately.
/// 2. Zeroize `cert_data` (via `resetBytes(in:)`) after wrapping is confirmed.
#[derive(Debug, uniffi::Record)]
pub struct ModifyExpiryResult {
    /// Updated full certificate (public + secret) in binary OpenPGP format.
    /// MUST be zeroized by the caller after SE wrapping.
    pub cert_data: Vec<u8>,
    /// Updated public key only in binary OpenPGP format.
    pub public_key_data: Vec<u8>,
    /// Updated key info with new expiry status.
    pub key_info: KeyInfo,
}

/// Public-only result of modifying a Secure Enclave custody certificate's
/// expiration time through an external signer.
#[derive(Debug, uniffi::Record)]
pub struct ModifyExpiryPublicResult {
    /// Updated public certificate in binary OpenPGP format.
    pub public_key_data: Vec<u8>,
    /// Updated key info with new expiry status.
    pub key_info: KeyInfo,
}

#[derive(Clone, Copy)]
enum ExpirySignatureHashStrategy {
    PreserveTemplate,
    Force(HashAlgorithm),
}

impl ExpirySignatureHashStrategy {
    fn apply(self, builder: SignatureBuilder, template_hash: HashAlgorithm) -> SignatureBuilder {
        match self {
            Self::PreserveTemplate => builder.set_hash_algo(template_hash),
            Self::Force(hash) => builder.set_hash_algo(hash),
        }
    }

    fn resolve(self, template_hash: HashAlgorithm) -> HashAlgorithm {
        match self {
            Self::PreserveTemplate => template_hash,
            Self::Force(hash) => hash,
        }
    }
}

/// Modify the expiration time of an existing certificate.
///
/// Requires the full certificate with secret key material, because updating the expiry
/// requires re-signing the primary key's binding signatures (direct key sig + all User ID
/// binding sigs) and any current non-revoked subkey binding signatures that carry their
/// own validity period. Works identically for v4 (Profile A) and v6 (Profile B) keys.
///
/// - `cert_data`: Full certificate with secret key material (binary OpenPGP format).
/// - `new_expiry_seconds`: Duration from now in seconds. `None` removes expiry (never expire).
///
/// Returns the updated certificate (with secret keys) and updated public key + key info.
pub fn modify_expiry(
    cert_data: &[u8],
    new_expiry_seconds: Option<u64>,
) -> Result<ModifyExpiryResult, PgpError> {
    let cert = openpgp::Cert::from_bytes(cert_data).map_err(|e| PgpError::InvalidKeyData {
        reason: e.to_string(),
    })?;

    let policy = StandardPolicy::new();

    // Extract the primary key as a KeyPair for signing the new binding signatures.
    // SECURITY: `keypair` holds secret key material. Sequoia's KeyPair uses Protected<>
    // internally, which zeroizes on Drop.
    let mut keypair = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .map_err(|e| PgpError::InvalidKeyData {
            reason: format!("No secret key material for re-signing: {e}"),
        })?
        .into_keypair()
        .map_err(|e| PgpError::InvalidKeyData {
            reason: format!("Cannot create keypair from secret key: {e}"),
        })?;

    let reference_time = SystemTime::now();
    let updated_public = modify_expiry_with_signer(
        cert,
        &policy,
        &mut keypair,
        true,
        ExpirySignatureHashStrategy::PreserveTemplate,
        new_expiry_seconds,
        reference_time,
    )
    .map_err(|error| {
        map_external_signing_error(error, |reason| PgpError::KeyGenerationFailed { reason })
    })?;

    // Serialize the updated full cert (public + secret).
    // SECURITY: Wrapped in Zeroizing<> for automatic cleanup on error paths.
    let mut cert_output = Zeroizing::new(Vec::new());
    updated_public
        .as_tsk()
        .serialize(&mut *cert_output)
        .map_err(|e| PgpError::KeyGenerationFailed {
            reason: format!("Failed to serialize updated certificate: {e}"),
        })?;

    let public_result = serialize_public_modify_expiry_result(&updated_public)?;

    Ok(ModifyExpiryResult {
        cert_data: std::mem::take(&mut *cert_output),
        public_key_data: public_result.public_key_data,
        key_info: public_result.key_info,
    })
}

/// Modify the expiration time of a public-only P-256 certificate through an
/// external signing provider.
pub fn modify_expiry_with_external_p256_signer(
    public_cert_data: &[u8],
    signing_key_fingerprint: &str,
    signer: Arc<dyn ExternalP256SigningProvider>,
    new_expiry_seconds: Option<u64>,
) -> Result<ModifyExpiryPublicResult, PgpError> {
    let policy = StandardPolicy::new();
    let cert =
        openpgp::Cert::from_bytes(public_cert_data).map_err(|error| PgpError::InvalidKeyData {
            reason: format!("Invalid external signer public certificate: {error}"),
        })?;
    if cert.is_tsk() {
        return Err(PgpError::InvalidKeyData {
            reason: "External expiry modification requires a public certificate".to_string(),
        });
    }

    let reference_time = SystemTime::now();
    ensure_external_expiry_signer_is_primary(&cert, signing_key_fingerprint)?;
    ensure_external_expiry_subkeys_do_not_require_subkey_signers(&cert, &policy, reference_time)
        .map_err(|error| PgpError::SigningFailed {
            reason: format!("External expiry modification is not supported: {error}"),
        })?;

    let signing_public_key = select_external_expiry_primary_signing_key(
        &cert,
        signing_key_fingerprint,
        &policy,
        reference_time,
    )?;
    let mut external_signer = signer_for_provider(signing_public_key, signer).map_err(|error| {
        PgpError::SigningFailed {
            reason: format!("External signer setup failed: {error}"),
        }
    })?;

    let updated_public = modify_expiry_with_signer(
        cert,
        &policy,
        &mut external_signer,
        false,
        ExpirySignatureHashStrategy::Force(HashAlgorithm::SHA256),
        new_expiry_seconds,
        reference_time,
    )
    .map_err(|error| {
        map_external_signing_error(error, |reason| PgpError::KeyGenerationFailed { reason })
    })?;
    serialize_public_modify_expiry_result(&updated_public)
}

/// Modify the expiration time of a public-only split-custody composite
/// certificate through an external signing provider.
pub fn modify_expiry_with_external_composite_signer(
    public_cert_data: &[u8],
    signing_key_fingerprint: &str,
    classical_eddsa_secret: &[u8],
    signer: Arc<dyn ExternalMlDsa65SigningProvider>,
    new_expiry_seconds: Option<u64>,
) -> Result<ModifyExpiryPublicResult, PgpError> {
    let policy = StandardPolicy::new();
    let cert =
        openpgp::Cert::from_bytes(public_cert_data).map_err(|error| PgpError::InvalidKeyData {
            reason: format!("Invalid external signer public certificate: {error}"),
        })?;
    if cert.is_tsk() {
        return Err(PgpError::InvalidKeyData {
            reason: "External expiry modification requires a public certificate".to_string(),
        });
    }

    let reference_time = SystemTime::now();
    ensure_external_expiry_signer_is_primary(&cert, signing_key_fingerprint)?;
    ensure_external_expiry_subkeys_do_not_require_subkey_signers(&cert, &policy, reference_time)
        .map_err(|error| PgpError::SigningFailed {
            reason: format!("External expiry modification is not supported: {error}"),
        })?;

    let signing_public_key = select_external_expiry_primary_signing_key(
        &cert,
        signing_key_fingerprint,
        &policy,
        reference_time,
    )?;
    let mut external_signer =
        composite_signer_for_provider(signing_public_key, classical_eddsa_secret, signer).map_err(
            |error| PgpError::SigningFailed {
                reason: format!("External signer setup failed: {error}"),
            },
        )?;

    let updated_public = modify_expiry_with_signer(
        cert,
        &policy,
        &mut external_signer,
        false,
        ExpirySignatureHashStrategy::Force(HashAlgorithm::SHA512),
        new_expiry_seconds,
        reference_time,
    )
    .map_err(|error| {
        map_external_signing_error(error, |reason| PgpError::KeyGenerationFailed { reason })
    })?;
    serialize_public_modify_expiry_result(&updated_public)
}

fn modify_expiry_with_signer(
    cert: openpgp::Cert,
    policy: &StandardPolicy,
    primary_signer: &mut dyn openpgp::crypto::Signer,
    allow_secret_subkey_signers: bool,
    hash_strategy: ExpirySignatureHashStrategy,
    new_expiry_seconds: Option<u64>,
    reference_time: SystemTime,
) -> openpgp::Result<openpgp::Cert> {
    ensure_expiry_certificate_not_revoked(&cert, policy, reference_time)?;

    let mutation_time = mutation_signature_creation_time(latest_binding_signature_time(
        &cert,
        policy,
        reference_time,
    )?)?;
    let expiration_time = new_expiry_seconds.map(|secs| mutation_time + Duration::from_secs(secs));

    let mut sigs = primary_expiration_signatures(
        &cert,
        policy,
        primary_signer,
        reference_time,
        mutation_time,
        hash_strategy,
        expiration_time,
    )?;
    sigs.append(&mut subkey_expiration_signatures(
        &cert,
        policy,
        primary_signer,
        allow_secret_subkey_signers,
        reference_time,
        mutation_time,
        hash_strategy,
        expiration_time,
    )?);

    let (updated_cert, _) = cert.insert_packets(sigs)?;
    Ok(updated_cert)
}

fn ensure_external_expiry_signer_is_primary(
    cert: &openpgp::Cert,
    signing_key_fingerprint: &str,
) -> Result<(), PgpError> {
    let expected_fingerprint = signing_key_fingerprint.trim();
    if expected_fingerprint.is_empty() {
        return Err(PgpError::InvalidKeyData {
            reason: "External expiry signer expected fingerprint must not be empty".to_string(),
        });
    }

    let primary_fingerprint = cert.primary_key().key().fingerprint().to_hex();
    if !primary_fingerprint.eq_ignore_ascii_case(expected_fingerprint) {
        return Err(PgpError::SigningFailed {
            reason: "External expiry modification requires the primary signing key".to_string(),
        });
    }

    Ok(())
}

fn select_external_expiry_primary_signing_key(
    cert: &openpgp::Cert,
    signing_key_fingerprint: &str,
    policy: &StandardPolicy,
    reference_time: SystemTime,
) -> Result<Key<key::PublicParts, key::UnspecifiedRole>, PgpError> {
    let expected_fingerprint = signing_key_fingerprint.trim();
    if expected_fingerprint.is_empty() {
        return Err(PgpError::InvalidKeyData {
            reason: "External expiry signer expected fingerprint must not be empty".to_string(),
        });
    }

    let primary = cert
        .primary_key()
        .with_policy(policy, Some(reference_time))
        .map_err(|error| PgpError::SigningFailed {
            reason: format!("No policy-valid external expiry primary key found: {error}"),
        })?;
    if !primary
        .key()
        .fingerprint()
        .to_hex()
        .eq_ignore_ascii_case(expected_fingerprint)
    {
        return Err(PgpError::SigningFailed {
            reason: "External expiry modification requires the primary signing key".to_string(),
        });
    }
    if !primary.key().pk_algo().is_supported() {
        return Err(PgpError::SigningFailed {
            reason: "External expiry primary signing key uses an unsupported algorithm".to_string(),
        });
    }
    if !primary.for_signing() {
        return Err(PgpError::SigningFailed {
            reason: "External expiry primary key is not signing-capable".to_string(),
        });
    }

    Ok(primary.key().role_as_unspecified().clone())
}

fn ensure_external_expiry_subkeys_do_not_require_subkey_signers(
    cert: &openpgp::Cert,
    policy: &StandardPolicy,
    reference_time: SystemTime,
) -> openpgp::Result<()> {
    let valid_cert = cert.with_policy(policy, Some(reference_time))?;
    for subkey in valid_cert.keys().subkeys().revoked(false) {
        if subkey.binding_signature().key_validity_period().is_none() {
            continue;
        }
        if subkey_requires_subkey_signer(&subkey) {
            return Err(openpgp::Error::InvalidArgument(
                "signing-capable subkey expiry refresh requires a subkey signer".to_string(),
            )
            .into());
        }
    }
    Ok(())
}

fn ensure_expiry_certificate_not_revoked(
    cert: &openpgp::Cert,
    policy: &StandardPolicy,
    reference_time: SystemTime,
) -> openpgp::Result<()> {
    let valid_cert = cert.with_policy(policy, Some(reference_time))?;
    match valid_cert.revocation_status() {
        RevocationStatus::NotAsFarAsWeKnow => Ok(()),
        RevocationStatus::Revoked(_) => Err(openpgp::Error::InvalidArgument(
            "Cannot modify expiry of a revoked certificate".to_string(),
        )
        .into()),
        RevocationStatus::CouldBe(_) => Err(openpgp::Error::InvalidArgument(
            "Cannot modify expiry of a certificate with unresolved revocation status".to_string(),
        )
        .into()),
    }
}

fn primary_expiration_signatures(
    cert: &openpgp::Cert,
    policy: &StandardPolicy,
    primary_signer: &mut dyn openpgp::crypto::Signer,
    reference_time: SystemTime,
    mutation_time: SystemTime,
    hash_strategy: ExpirySignatureHashStrategy,
    expiration_time: Option<SystemTime>,
) -> openpgp::Result<Vec<Signature>> {
    let valid_cert = cert.with_policy(policy, Some(reference_time))?;
    let active_primary_binding = valid_cert
        .primary_userid()
        .map(|user_id| user_id.binding_signature())
        .or_else(|_| {
            cert.primary_key()
                .binding_signature(policy, Some(reference_time))
        })?;
    let primary_validity =
        key_validity_period(cert.primary_key().key().creation_time(), expiration_time)?;

    let (direct_template, direct_template_hash) = valid_cert
        .primary_key()
        .direct_key_signature()
        .map(|sig| (SignatureBuilder::from(sig.clone()), sig.hash_algo()))
        .unwrap_or_else(|_| {
            (
                SignatureBuilder::from(active_primary_binding.clone())
                    .set_type(SignatureType::DirectKey),
                active_primary_binding.hash_algo(),
            )
        });
    let mut direct_template = hash_strategy.apply(direct_template, direct_template_hash);

    use openpgp::packet::signature::subpacket::SubpacketTag::*;
    let hashed_area = direct_template.hashed_area_mut();
    hashed_area.remove_all(ExportableCertification);
    hashed_area.remove_all(Revocable);
    hashed_area.remove_all(TrustSignature);
    hashed_area.remove_all(RegularExpression);
    hashed_area.remove_all(PrimaryUserID);
    hashed_area.remove_all(SignersUserID);
    hashed_area.remove_all(ReasonForRevocation);
    hashed_area.remove_all(SignatureTarget);
    hashed_area.remove_all(EmbeddedSignature);

    let mut sigs = vec![direct_template
        .set_signature_creation_time(mutation_time)?
        .set_key_validity_period(primary_validity)?
        .sign_direct_key(primary_signer, None)?];

    let primary_userid = valid_cert
        .primary_userid()
        .ok()
        .map(|primary| primary.userid().clone());
    for user_id in valid_cert.userids().revoked(false) {
        let binding_signature = user_id.binding_signature();
        let binding_template = hash_strategy
            .apply(
                SignatureBuilder::from(binding_signature.clone()),
                binding_signature.hash_algo(),
            )
            .set_signature_creation_time(mutation_time)?
            .set_key_validity_period(primary_validity)?
            .set_primary_userid(
                primary_userid
                    .as_ref()
                    .map(|primary| user_id.userid() == primary)
                    .unwrap_or(false),
            )?;
        sigs.push(binding_template.sign_userid_binding(
            primary_signer,
            cert.primary_key().component(),
            user_id.userid(),
        )?);
    }

    Ok(sigs)
}

fn subkey_expiration_signatures(
    cert: &openpgp::Cert,
    policy: &StandardPolicy,
    primary_signer: &mut dyn openpgp::crypto::Signer,
    allow_secret_subkey_signers: bool,
    reference_time: SystemTime,
    mutation_time: SystemTime,
    hash_strategy: ExpirySignatureHashStrategy,
    expiration_time: Option<SystemTime>,
) -> openpgp::Result<Vec<Signature>> {
    let mut sigs = Vec::new();
    let valid_cert = cert.with_policy(policy, Some(reference_time))?;

    for subkey in valid_cert.keys().subkeys().revoked(false) {
        if subkey.binding_signature().key_validity_period().is_none() {
            continue;
        }

        if subkey_requires_subkey_signer(&subkey) {
            if !allow_secret_subkey_signers {
                return Err(openpgp::Error::InvalidArgument(
                    "signing-capable subkey expiry refresh requires a subkey signer".to_string(),
                )
                .into());
            }

            let mut subkey_signer = subkey
                .key()
                .clone()
                .parts_into_secret()
                .map_err(|error| {
                    openpgp::Error::InvalidArgument(format!(
                        "Missing subkey secret material for expiry refresh: {error}"
                    ))
                })?
                .into_keypair()
                .map_err(|error| {
                    openpgp::Error::InvalidArgument(format!(
                        "Cannot create subkey signer for expiry refresh: {error}"
                    ))
                })?;
            let backsig = SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
                .set_hash_algo(hash_strategy.resolve(subkey.binding_signature().hash_algo()))
                .set_signature_creation_time(mutation_time)?
                .sign_primary_key_binding(
                    &mut subkey_signer,
                    cert.primary_key().key(),
                    subkey.key().role_as_subordinate(),
                )?;
            sigs.push(subkey_expiration_signature(
                cert,
                primary_signer,
                &subkey,
                Some(backsig),
                mutation_time,
                hash_strategy,
                expiration_time,
            )?);
        } else {
            sigs.push(subkey_expiration_signature(
                cert,
                primary_signer,
                &subkey,
                None,
                mutation_time,
                hash_strategy,
                expiration_time,
            )?);
        }
    }

    Ok(sigs)
}

fn subkey_expiration_signature<P>(
    cert: &openpgp::Cert,
    primary_signer: &mut dyn openpgp::crypto::Signer,
    subkey: &ValidSubordinateKeyAmalgamation<'_, P>,
    backsig: Option<Signature>,
    mutation_time: SystemTime,
    hash_strategy: ExpirySignatureHashStrategy,
    expiration_time: Option<SystemTime>,
) -> openpgp::Result<Signature>
where
    P: openpgp::packet::key::KeyParts,
{
    let subkey_validity = key_validity_period(subkey.key().creation_time(), expiration_time)?;
    let binding_signature = subkey.binding_signature();
    let mut builder = hash_strategy
        .apply(
            SignatureBuilder::from(binding_signature.clone()),
            binding_signature.hash_algo(),
        )
        .set_signature_creation_time(mutation_time)?
        .set_key_validity_period(subkey_validity)?;

    if let Some(backsig) = backsig {
        builder = builder.set_embedded_signature(backsig)?;
    }

    builder.sign_subkey_binding(
        primary_signer,
        cert.primary_key().component(),
        subkey.key().role_as_subordinate(),
    )
}

fn subkey_requires_subkey_signer<P>(subkey: &ValidSubordinateKeyAmalgamation<'_, P>) -> bool
where
    P: openpgp::packet::key::KeyParts,
{
    subkey.for_certification() || subkey.for_signing() || subkey.for_authentication()
}

fn key_validity_period(
    key_creation_time: SystemTime,
    expiration_time: Option<SystemTime>,
) -> openpgp::Result<Option<Duration>> {
    if let Some(expiration_time) = expiration_time {
        expiration_time
            .duration_since(key_creation_time)
            .map(Some)
            .map_err(|_| {
                openpgp::Error::InvalidArgument(
                    "Expiration time predates key creation time".to_string(),
                )
                .into()
            })
    } else {
        Ok(None)
    }
}

fn latest_binding_signature_time(
    cert: &openpgp::Cert,
    policy: &StandardPolicy,
    reference_time: SystemTime,
) -> openpgp::Result<Option<SystemTime>> {
    let valid_cert = cert.with_policy(policy, Some(reference_time))?;
    let mut latest = valid_cert
        .primary_key()
        .binding_signature()
        .signature_creation_time();

    if let Ok(direct) = valid_cert.primary_key().direct_key_signature() {
        latest = latest.max(direct.signature_creation_time());
    }

    for user_id in valid_cert.userids().revoked(false) {
        latest = latest.max(user_id.binding_signature().signature_creation_time());
    }

    for subkey in valid_cert.keys().subkeys().revoked(false) {
        latest = latest.max(subkey.binding_signature().signature_creation_time());
    }

    Ok(latest)
}

fn mutation_signature_creation_time(
    latest_signature_time: Option<SystemTime>,
) -> openpgp::Result<SystemTime> {
    let now = SystemTime::now();
    let Some(latest_signature_time) = latest_signature_time else {
        return Ok(now);
    };
    let latest_signature_second = unix_seconds(latest_signature_time)?;
    let now_second = unix_seconds(now)?;
    let required_second = latest_signature_second.checked_add(1).ok_or_else(|| {
        openpgp::Error::InvalidArgument(
            "Self-signature creation time cannot be advanced".to_string(),
        )
    })?;
    let mutation_time =
        std::time::UNIX_EPOCH + Duration::from_secs(now_second.max(required_second));
    if mutation_time <= now {
        return Ok(mutation_time);
    }

    let wait = mutation_time.duration_since(now).map_err(|_| {
        openpgp::Error::InvalidArgument(
            "Self-signature creation time is not comparable to the system clock".to_string(),
        )
    })?;
    if wait > Duration::from_secs(2) {
        return Err(openpgp::Error::InvalidArgument(
            "Self-signature creation time is too far in the future".to_string(),
        )
        .into());
    }
    std::thread::sleep(wait);
    Ok(mutation_time)
}

fn unix_seconds(time: SystemTime) -> openpgp::Result<u64> {
    time.duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| {
            openpgp::Error::InvalidArgument(
                "Self-signature creation time predates the Unix epoch".to_string(),
            )
            .into()
        })
}

fn serialize_public_modify_expiry_result(
    updated_cert: &openpgp::Cert,
) -> Result<ModifyExpiryPublicResult, PgpError> {
    let mut public_key_data = Vec::new();
    updated_cert
        .serialize(&mut public_key_data)
        .map_err(|e| PgpError::KeyGenerationFailed {
            reason: format!("Failed to serialize updated public key: {e}"),
        })?;
    let key_info = parse_key_info(&public_key_data)?;

    Ok(ModifyExpiryPublicResult {
        public_key_data,
        key_info,
    })
}
