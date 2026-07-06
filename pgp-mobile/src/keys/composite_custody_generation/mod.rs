use super::*;

use openpgp::crypto::{mpi, Signer};
use openpgp::packet::{key, signature, Key, Packet, UserID};
use openpgp::types::{
    Features, HashAlgorithm, KeyFlags, PublicKeyAlgorithm, SignatureType, SymmetricAlgorithm,
};

use crate::composite_classical;
use crate::external_composite_signer::{
    composite_high_signer_for_provider, composite_signer_for_provider,
};
use crate::external_signer::map_external_signing_error;

const MLDSA65_PUBLIC_KEY_LENGTH: usize = 1952;
const MLKEM768_PUBLIC_KEY_LENGTH: usize = 1184;
/// FIPS 203 ML-KEM-768 encapsulation keys pack three 384-byte polynomial
/// vectors ahead of the 32-byte seed ρ.
const MLKEM768_PACKED_VECTOR_LENGTH: usize = 1152;
const MLDSA87_PUBLIC_KEY_LENGTH: usize = 2592;
const MLKEM1024_PUBLIC_KEY_LENGTH: usize = 1568;
/// FIPS 203 ML-KEM-1024 encapsulation keys pack four 384-byte polynomial
/// vectors ahead of the 32-byte seed ρ.
const MLKEM1024_PACKED_VECTOR_LENGTH: usize = 1536;
/// FIPS 203 modulus q: every 12-bit packed coefficient must be canonical.
const MLKEM_Q: u16 = 3329;
const DEFAULT_VALIDITY_SECONDS: u64 = 2 * 365 * 24 * 60 * 60;

/// The certificate-derived outputs of `assemble_composite_public_certificate`,
/// before the tier's classical component secrets are attached.
struct AssembledCompositeCertificate {
    public_key_data: Vec<u8>,
    revocation_cert: Vec<u8>,
    fingerprint: String,
    key_version: u8,
    signing_key_fingerprint: String,
    key_agreement_subkey_fingerprint: String,
}

/// Assemble and self-sign a split-custody composite certificate from the two
/// already-built composite keys.
///
/// This is the tier-agnostic heart of certificate generation: the v6
/// self-signature policy (SHA-512, SEIPDv2 features, AES-256-first symmetric
/// preferences, validity), the User ID and key-agreement subkey bindings, and
/// the pre-generated key revocation. Every binding is produced through the
/// external composite signer, which self-verifies before releasing a signature.
/// Both PQC tiers share this single definition so the self-signature policy can
/// only ever be changed in one place.
fn assemble_composite_public_certificate<S: Signer>(
    mut external_signer: S,
    signing_public: &Key<key::PublicParts, key::UnspecifiedRole>,
    signing_key: Key<key::PublicParts, key::PrimaryRole>,
    key_agreement_key: Key<key::PublicParts, key::SubordinateRole>,
    user_id: String,
    validity: Duration,
) -> Result<AssembledCompositeCertificate, PgpError> {
    let mut cert = openpgp::Cert::try_from(vec![Packet::from(signing_key)]).map_err(|error| {
        PgpError::KeyGenerationFailed {
            reason: format!("Failed to create public certificate: {error}"),
        }
    })?;

    let user_id_packet = UserID::from(user_id);
    let user_id_builder = signature::SignatureBuilder::new(SignatureType::PositiveCertification)
        .set_hash_algo(HashAlgorithm::SHA512)
        .set_key_flags(KeyFlags::empty().set_certification().set_signing())
        .map_err(|error| PgpError::KeyGenerationFailed {
            reason: format!("Failed to set user ID key flags: {error}"),
        })?
        .set_key_validity_period(validity)
        .map_err(|error| PgpError::KeyGenerationFailed {
            reason: format!("Failed to set key validity period: {error}"),
        })?
        .set_features(Features::empty().set_seipdv2())
        .map_err(|error| PgpError::KeyGenerationFailed {
            reason: format!("Failed to set v6 features: {error}"),
        })?
        .set_preferred_symmetric_algorithms(vec![
            SymmetricAlgorithm::AES256,
            SymmetricAlgorithm::AES128,
        ])
        .map_err(|error| PgpError::KeyGenerationFailed {
            reason: format!("Failed to set symmetric preferences: {error}"),
        })?
        .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512, HashAlgorithm::SHA256])
        .map_err(|error| PgpError::KeyGenerationFailed {
            reason: format!("Failed to set hash preferences: {error}"),
        })?;

    let user_id_binding = user_id_packet
        .bind(&mut external_signer, &cert, user_id_builder)
        .map_err(|error| {
            map_external_composite_signing_key_generation_error("Failed to bind user ID", error)
        })?;
    cert = cert
        .insert_packets(vec![Packet::from(user_id_packet), user_id_binding.into()])
        .map_err(|error| PgpError::KeyGenerationFailed {
            reason: format!("Failed to insert user ID binding: {error}"),
        })?
        .0;

    let subkey_binding = key_agreement_key
        .bind(
            &mut external_signer,
            &cert,
            signature::SignatureBuilder::new(SignatureType::SubkeyBinding)
                .set_hash_algo(HashAlgorithm::SHA512)
                .set_key_flags(KeyFlags::empty().set_transport_encryption())
                .map_err(|error| PgpError::KeyGenerationFailed {
                    reason: format!("Failed to set subkey key flags: {error}"),
                })?
                .set_key_validity_period(validity)
                .map_err(|error| PgpError::KeyGenerationFailed {
                    reason: format!("Failed to set subkey validity period: {error}"),
                })?,
        )
        .map_err(|error| {
            map_external_composite_signing_key_generation_error(
                "Failed to bind key-agreement subkey",
                error,
            )
        })?;
    let key_agreement_fingerprint = key_agreement_key.fingerprint().to_hex().to_lowercase();
    cert = cert
        .insert_packets(vec![Packet::from(key_agreement_key), subkey_binding.into()])
        .map_err(|error| PgpError::KeyGenerationFailed {
            reason: format!("Failed to insert key-agreement subkey: {error}"),
        })?
        .0;

    let revocation = openpgp::cert::CertRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::KeyRetired, b"")
        .map_err(|error| PgpError::RevocationError {
            reason: format!("Failed to configure key revocation: {error}"),
        })?
        .build(&mut external_signer, &cert, HashAlgorithm::SHA512)
        .map_err(|error| {
            map_external_composite_signing_revocation_error(
                "Failed to generate key revocation",
                error,
            )
        })?;

    let mut public_key_data = Vec::new();
    cert.serialize(&mut public_key_data)
        .map_err(|error| PgpError::KeyGenerationFailed {
            reason: format!("Failed to serialize public certificate: {error}"),
        })?;
    let mut revocation_cert = Vec::new();
    Packet::from(revocation)
        .serialize(&mut revocation_cert)
        .map_err(|error| PgpError::RevocationError {
            reason: format!("Failed to serialize revocation cert: {error}"),
        })?;

    Ok(AssembledCompositeCertificate {
        public_key_data,
        revocation_cert,
        fingerprint: cert.fingerprint().to_hex().to_lowercase(),
        key_version: cert.primary_key().key().version(),
        signing_key_fingerprint: signing_public.fingerprint().to_hex().to_lowercase(),
        key_agreement_subkey_fingerprint: key_agreement_fingerprint,
    })
}

/// Compose the self-certified User ID string, rejecting an empty identity.
fn composite_user_id(name: &str, email: Option<&str>) -> Result<String, PgpError> {
    let user_id = match email {
        Some(email) => format!("{name} <{email}>"),
        None => name.to_string(),
    };
    if user_id.trim().is_empty() {
        return Err(PgpError::InvalidKeyData {
            reason: "Split-custody composite User ID must not be empty".to_string(),
        });
    }
    Ok(user_id)
}

/// Build the Device-Bound Post-Quantum split-custody certificate.
///
/// The primary key is an RFC 9980 ML-DSA-65 + Ed25519 composite
/// (certification + signing) and the single subkey an ML-KEM-768 + X25519
/// composite (transport encryption). The PQ component public keys come from
/// Secure Enclave generation on the Swift side; the classical Ed25519/X25519
/// components are generated here and their secrets returned for enveloping.
pub fn generate_secure_enclave_composite_public_certificate(
    input: SecureEnclaveCompositePublicCertificateInput,
    signer: Arc<dyn ExternalMlDsa65SigningProvider>,
) -> Result<SecureEnclaveCompositeGeneratedCertificate, PgpError> {
    validate_mldsa65_public_key(&input.mldsa65_signing_public_key)?;
    validate_mlkem768_public_key(&input.mlkem768_key_agreement_public_key)?;
    let user_id = composite_user_id(&input.name, input.email.as_deref())?;

    let (classical_eddsa_secret, classical_eddsa_public) =
        composite_classical::generate_ed25519_component()
            .map_err(map_component_generation_error)?;
    let (classical_ecdh_secret, classical_ecdh_public) =
        composite_classical::generate_x25519_component().map_err(map_component_generation_error)?;

    let created_at = SystemTime::now();
    let signing_key = make_composite_signing_key(
        created_at,
        classical_eddsa_public,
        &input.mldsa65_signing_public_key,
    )?;
    let key_agreement_key = make_composite_key_agreement_key(
        created_at,
        classical_ecdh_public,
        &input.mlkem768_key_agreement_public_key,
    )?;
    let signing_public = signing_key.clone().role_as_unspecified().clone();
    let validity = Duration::from_secs(input.expiry_seconds.unwrap_or(DEFAULT_VALIDITY_SECONDS));

    let external_signer =
        composite_signer_for_provider(signing_public.clone(), &classical_eddsa_secret, signer)
            .map_err(|error| PgpError::KeyGenerationFailed {
                reason: error.to_string(),
            })?;
    let assembled = assemble_composite_public_certificate(
        external_signer,
        &signing_public,
        signing_key,
        key_agreement_key,
        user_id,
        validity,
    )?;

    Ok(SecureEnclaveCompositeGeneratedCertificate {
        public_key_data: assembled.public_key_data,
        revocation_cert: assembled.revocation_cert,
        fingerprint: assembled.fingerprint,
        key_version: assembled.key_version,
        signing_key_fingerprint: assembled.signing_key_fingerprint,
        key_agreement_subkey_fingerprint: assembled.key_agreement_subkey_fingerprint,
        classical_eddsa_secret: classical_eddsa_secret.to_vec(),
        classical_ecdh_secret: classical_ecdh_secret.to_vec(),
    })
}

/// Build the Device-Bound Post-Quantum · High split-custody certificate.
///
/// The primary key is an RFC 9980 ML-DSA-87 + Ed448 composite (certification +
/// signing) and the single subkey an ML-KEM-1024 + X448 composite (transport
/// encryption). The PQ component public keys come from Secure Enclave generation
/// on the Swift side; the classical Ed448/X448 components are generated here and
/// their secrets returned for enveloping.
pub fn generate_secure_enclave_composite_high_public_certificate(
    input: SecureEnclaveCompositeHighPublicCertificateInput,
    signer: Arc<dyn ExternalMlDsa87SigningProvider>,
) -> Result<SecureEnclaveCompositeGeneratedCertificate, PgpError> {
    validate_mldsa87_public_key(&input.mldsa87_signing_public_key)?;
    validate_mlkem1024_public_key(&input.mlkem1024_key_agreement_public_key)?;
    let user_id = composite_user_id(&input.name, input.email.as_deref())?;

    let (classical_eddsa_secret, classical_eddsa_public) =
        composite_classical::generate_ed448_component().map_err(map_component_generation_error)?;
    let (classical_ecdh_secret, classical_ecdh_public) =
        composite_classical::generate_x448_component().map_err(map_component_generation_error)?;

    let created_at = SystemTime::now();
    let signing_key = make_composite_high_signing_key(
        created_at,
        classical_eddsa_public,
        &input.mldsa87_signing_public_key,
    )?;
    let key_agreement_key = make_composite_high_key_agreement_key(
        created_at,
        classical_ecdh_public,
        &input.mlkem1024_key_agreement_public_key,
    )?;
    let signing_public = signing_key.clone().role_as_unspecified().clone();
    let validity = Duration::from_secs(input.expiry_seconds.unwrap_or(DEFAULT_VALIDITY_SECONDS));

    let external_signer =
        composite_high_signer_for_provider(signing_public.clone(), &classical_eddsa_secret, signer)
            .map_err(|error| PgpError::KeyGenerationFailed {
                reason: error.to_string(),
            })?;
    let assembled = assemble_composite_public_certificate(
        external_signer,
        &signing_public,
        signing_key,
        key_agreement_key,
        user_id,
        validity,
    )?;

    Ok(SecureEnclaveCompositeGeneratedCertificate {
        public_key_data: assembled.public_key_data,
        revocation_cert: assembled.revocation_cert,
        fingerprint: assembled.fingerprint,
        key_version: assembled.key_version,
        signing_key_fingerprint: assembled.signing_key_fingerprint,
        key_agreement_subkey_fingerprint: assembled.key_agreement_subkey_fingerprint,
        classical_eddsa_secret: classical_eddsa_secret.to_vec(),
        classical_ecdh_secret: classical_ecdh_secret.to_vec(),
    })
}

/// Human-facing algorithm labels for a tier's inspection error messages.
struct CompositeInspectionLabels {
    /// Tier suffix in messages ("" for the base tier, " · High" for High).
    tier: &'static str,
    /// Signing-key composite algorithm name (e.g. "ML-DSA-65+Ed25519").
    signing_algo: &'static str,
    /// Key-agreement composite algorithm name (e.g. "ML-KEM-768+X25519").
    key_agreement_algo: &'static str,
}

/// The tier-agnostic public bindings extracted from a split-custody composite
/// certificate.
struct CompositeBindingExtract {
    fingerprint: String,
    key_version: u8,
    signing_key_fingerprint: String,
    key_agreement_subkey_fingerprint: String,
    mldsa_signing_public_key: Vec<u8>,
    mlkem_key_agreement_public_key: Vec<u8>,
    eddsa_signing_public_key: Vec<u8>,
    ecdh_key_agreement_public_key: Vec<u8>,
}

/// Tier-agnostic split-custody composite certificate inspection.
///
/// Enforces public-only material, extracts the composite component public keys
/// via the tier's MPI matchers, and applies the shared structural rules — the
/// primary must be this tier's composite signing key, there must be exactly one
/// transport-encryption composite key-agreement subkey, and that subkey must be
/// transport-encryption capable under some binding-signature reference time. The
/// single-subkey rule and the per-reference-time capability check live here so
/// both PQC tiers stay in lockstep.
fn inspect_composite_bindings(
    public_key_data: &[u8],
    extract_primary: impl Fn(&mpi::PublicKey) -> Option<(Vec<u8>, Vec<u8>)>,
    validate_signing_public_key: impl Fn(&[u8]) -> Result<(), PgpError>,
    extract_key_agreement: impl Fn(&mpi::PublicKey) -> Option<(Vec<u8>, Vec<u8>)>,
    validate_key_agreement_public_key: impl Fn(&[u8]) -> Result<(), PgpError>,
    labels: CompositeInspectionLabels,
) -> Result<CompositeBindingExtract, PgpError> {
    reject_armored_certificate_input(public_key_data)?;

    let cert =
        openpgp::Cert::from_bytes(public_key_data).map_err(|error| PgpError::InvalidKeyData {
            reason: format!("Invalid split-custody composite public certificate: {error}"),
        })?;
    if cert.is_tsk() {
        return Err(PgpError::InvalidKeyData {
            reason: "Split-custody composite inspection requires public certificate material"
                .to_string(),
        });
    }

    let primary = cert.primary_key().key();
    let (eddsa_signing_public_key, mldsa_signing_public_key) = extract_primary(primary.mpis())
        .ok_or_else(|| PgpError::InvalidKeyData {
            reason: format!(
                "Split-custody composite{} primary key must be {}",
                labels.tier, labels.signing_algo
            ),
        })?;
    validate_signing_public_key(&mldsa_signing_public_key)?;

    let mut composite_key_agreement_subkeys = cert
        .keys()
        .subkeys()
        .filter_map(|subkey| {
            extract_key_agreement(subkey.key().mpis()).map(|(ecdh, mlkem)| {
                (
                    subkey.key().fingerprint().to_hex().to_lowercase(),
                    ecdh,
                    mlkem,
                )
            })
        })
        .collect::<Vec<_>>();

    if composite_key_agreement_subkeys.is_empty() {
        return Err(PgpError::InvalidKeyData {
            reason: format!(
                "Split-custody composite{} certificate is missing an {} subkey",
                labels.tier, labels.key_agreement_algo
            ),
        });
    }
    if composite_key_agreement_subkeys.len() != 1 {
        return Err(PgpError::InvalidKeyData {
            reason: format!(
                "Split-custody composite{} certificate must contain exactly one {} subkey",
                labels.tier, labels.key_agreement_algo
            ),
        });
    }
    let (
        key_agreement_subkey_fingerprint,
        ecdh_key_agreement_public_key,
        mlkem_key_agreement_public_key,
    ) = composite_key_agreement_subkeys.remove(0);
    validate_key_agreement_public_key(&mlkem_key_agreement_public_key)?;

    let policy = StandardPolicy::new();
    let is_transport_encryption_capable = cert.keys().subkeys().any(|subkey| {
        if subkey.key().fingerprint().to_hex().to_lowercase() != key_agreement_subkey_fingerprint {
            return false;
        }

        let mut binding_reference_times = subkey
            .self_signatures()
            .filter_map(|signature| signature.signature_creation_time())
            .collect::<Vec<_>>();
        binding_reference_times.sort_unstable();
        binding_reference_times.dedup();
        binding_reference_times.into_iter().any(|reference_time| {
            subkey
                .binding_signature(&policy, Some(reference_time))
                .ok()
                .and_then(|signature| signature.key_flags())
                .is_some_and(|flags| flags.for_transport_encryption())
        })
    });
    if !is_transport_encryption_capable {
        return Err(PgpError::InvalidKeyData {
            reason: format!(
                "Split-custody composite{} key-agreement subkey is not transport-encryption capable",
                labels.tier
            ),
        });
    }

    Ok(CompositeBindingExtract {
        fingerprint: cert.fingerprint().to_hex().to_lowercase(),
        key_version: primary.version(),
        signing_key_fingerprint: primary.fingerprint().to_hex().to_lowercase(),
        key_agreement_subkey_fingerprint,
        mldsa_signing_public_key,
        mlkem_key_agreement_public_key,
        eddsa_signing_public_key,
        ecdh_key_agreement_public_key,
    })
}

pub fn inspect_secure_enclave_composite_bindings(
    public_key_data: &[u8],
) -> Result<SecureEnclaveCompositeBindingInspection, PgpError> {
    let extract = inspect_composite_bindings(
        public_key_data,
        |mpis| match mpis {
            mpi::PublicKey::MLDSA65_Ed25519 { eddsa, mldsa } => {
                Some((eddsa.to_vec(), mldsa.to_vec()))
            }
            _ => None,
        },
        validate_mldsa65_public_key,
        |mpis| match mpis {
            mpi::PublicKey::MLKEM768_X25519 { ecdh, mlkem } => {
                Some((ecdh.to_vec(), mlkem.to_vec()))
            }
            _ => None,
        },
        validate_mlkem768_public_key,
        CompositeInspectionLabels {
            tier: "",
            signing_algo: "ML-DSA-65+Ed25519",
            key_agreement_algo: "ML-KEM-768+X25519",
        },
    )?;

    Ok(SecureEnclaveCompositeBindingInspection {
        fingerprint: extract.fingerprint,
        key_version: extract.key_version,
        signing_key_fingerprint: extract.signing_key_fingerprint,
        key_agreement_subkey_fingerprint: extract.key_agreement_subkey_fingerprint,
        mldsa65_signing_public_key: extract.mldsa_signing_public_key,
        mlkem768_key_agreement_public_key: extract.mlkem_key_agreement_public_key,
        eddsa_signing_public_key: extract.eddsa_signing_public_key,
        ecdh_key_agreement_public_key: extract.ecdh_key_agreement_public_key,
    })
}

pub fn inspect_secure_enclave_composite_high_bindings(
    public_key_data: &[u8],
) -> Result<SecureEnclaveCompositeHighBindingInspection, PgpError> {
    let extract = inspect_composite_bindings(
        public_key_data,
        |mpis| match mpis {
            mpi::PublicKey::MLDSA87_Ed448 { eddsa, mldsa } => {
                Some((eddsa.to_vec(), mldsa.to_vec()))
            }
            _ => None,
        },
        validate_mldsa87_public_key,
        |mpis| match mpis {
            mpi::PublicKey::MLKEM1024_X448 { ecdh, mlkem } => Some((ecdh.to_vec(), mlkem.to_vec())),
            _ => None,
        },
        validate_mlkem1024_public_key,
        CompositeInspectionLabels {
            tier: " · High",
            signing_algo: "ML-DSA-87+Ed448",
            key_agreement_algo: "ML-KEM-1024+X448",
        },
    )?;

    Ok(SecureEnclaveCompositeHighBindingInspection {
        fingerprint: extract.fingerprint,
        key_version: extract.key_version,
        signing_key_fingerprint: extract.signing_key_fingerprint,
        key_agreement_subkey_fingerprint: extract.key_agreement_subkey_fingerprint,
        mldsa87_signing_public_key: extract.mldsa_signing_public_key,
        mlkem1024_key_agreement_public_key: extract.mlkem_key_agreement_public_key,
        eddsa_signing_public_key: extract.eddsa_signing_public_key,
        ecdh_key_agreement_public_key: extract.ecdh_key_agreement_public_key,
    })
}

fn make_composite_signing_key(
    created_at: SystemTime,
    classical_eddsa_public: [u8; composite_classical::ED25519_PUBLIC_KEY_LENGTH],
    mldsa65_public_key: &[u8],
) -> Result<Key<key::PublicParts, key::PrimaryRole>, PgpError> {
    let mldsa: Box<[u8; MLDSA65_PUBLIC_KEY_LENGTH]> = mldsa65_public_key
        .to_vec()
        .into_boxed_slice()
        .try_into()
        .map_err(|_| PgpError::InvalidKeyData {
            reason: "ML-DSA-65 signing public key must be 1952 bytes".to_string(),
        })?;
    let mpis = mpi::PublicKey::MLDSA65_Ed25519 {
        eddsa: Box::new(classical_eddsa_public),
        mldsa,
    };
    Ok(
        key::Key6::new(created_at, PublicKeyAlgorithm::MLDSA65_Ed25519, mpis)
            .map_err(map_key_generation_error)?
            .into(),
    )
}

fn make_composite_key_agreement_key(
    created_at: SystemTime,
    classical_ecdh_public: [u8; composite_classical::X25519_PUBLIC_KEY_LENGTH],
    mlkem768_public_key: &[u8],
) -> Result<Key<key::PublicParts, key::SubordinateRole>, PgpError> {
    let mlkem: Box<[u8; MLKEM768_PUBLIC_KEY_LENGTH]> = mlkem768_public_key
        .to_vec()
        .into_boxed_slice()
        .try_into()
        .map_err(|_| PgpError::InvalidKeyData {
            reason: "ML-KEM-768 key-agreement public key must be 1184 bytes".to_string(),
        })?;
    let mpis = mpi::PublicKey::MLKEM768_X25519 {
        ecdh: Box::new(classical_ecdh_public),
        mlkem,
    };
    Ok(
        key::Key6::new(created_at, PublicKeyAlgorithm::MLKEM768_X25519, mpis)
            .map_err(map_key_generation_error)?
            .into(),
    )
}

fn make_composite_high_signing_key(
    created_at: SystemTime,
    classical_eddsa_public: [u8; composite_classical::ED448_PUBLIC_KEY_LENGTH],
    mldsa87_public_key: &[u8],
) -> Result<Key<key::PublicParts, key::PrimaryRole>, PgpError> {
    let mldsa: Box<[u8; MLDSA87_PUBLIC_KEY_LENGTH]> = mldsa87_public_key
        .to_vec()
        .into_boxed_slice()
        .try_into()
        .map_err(|_| PgpError::InvalidKeyData {
            reason: "ML-DSA-87 signing public key must be 2592 bytes".to_string(),
        })?;
    let mpis = mpi::PublicKey::MLDSA87_Ed448 {
        eddsa: Box::new(classical_eddsa_public),
        mldsa,
    };
    Ok(
        key::Key6::new(created_at, PublicKeyAlgorithm::MLDSA87_Ed448, mpis)
            .map_err(map_key_generation_error)?
            .into(),
    )
}

fn make_composite_high_key_agreement_key(
    created_at: SystemTime,
    classical_ecdh_public: [u8; composite_classical::X448_PUBLIC_KEY_LENGTH],
    mlkem1024_public_key: &[u8],
) -> Result<Key<key::PublicParts, key::SubordinateRole>, PgpError> {
    let mlkem: Box<[u8; MLKEM1024_PUBLIC_KEY_LENGTH]> = mlkem1024_public_key
        .to_vec()
        .into_boxed_slice()
        .try_into()
        .map_err(|_| PgpError::InvalidKeyData {
            reason: "ML-KEM-1024 key-agreement public key must be 1568 bytes".to_string(),
        })?;
    let mpis = mpi::PublicKey::MLKEM1024_X448 {
        ecdh: Box::new(classical_ecdh_public),
        mlkem,
    };
    Ok(
        key::Key6::new(created_at, PublicKeyAlgorithm::MLKEM1024_X448, mpis)
            .map_err(map_key_generation_error)?
            .into(),
    )
}

fn validate_mldsa65_public_key(public_key: &[u8]) -> Result<(), PgpError> {
    if public_key.len() != MLDSA65_PUBLIC_KEY_LENGTH {
        return Err(PgpError::InvalidKeyData {
            reason: "ML-DSA-65 signing public key must be 1952 bytes".to_string(),
        });
    }
    if public_key.iter().all(|byte| *byte == 0) {
        return Err(PgpError::InvalidKeyData {
            reason: "ML-DSA-65 signing public key must not be all zeros".to_string(),
        });
    }
    Ok(())
}

/// FIPS 203 encapsulation-key input validation: exact length plus the modulus
/// check — every packed 12-bit coefficient of the t-hat vectors must be
/// canonical (< q). The trailing 32 bytes are the opaque seed ρ.
fn validate_mlkem768_public_key(public_key: &[u8]) -> Result<(), PgpError> {
    if public_key.len() != MLKEM768_PUBLIC_KEY_LENGTH {
        return Err(PgpError::InvalidKeyData {
            reason: "ML-KEM-768 key-agreement public key must be 1184 bytes".to_string(),
        });
    }
    if public_key.iter().all(|byte| *byte == 0) {
        return Err(PgpError::InvalidKeyData {
            reason: "ML-KEM-768 key-agreement public key must not be all zeros".to_string(),
        });
    }
    if !mlkem_packed_vector_is_canonical(&public_key[..MLKEM768_PACKED_VECTOR_LENGTH]) {
        return Err(PgpError::InvalidKeyData {
            reason: "ML-KEM-768 key-agreement public key has non-canonical coefficients"
                .to_string(),
        });
    }
    Ok(())
}

fn validate_mldsa87_public_key(public_key: &[u8]) -> Result<(), PgpError> {
    if public_key.len() != MLDSA87_PUBLIC_KEY_LENGTH {
        return Err(PgpError::InvalidKeyData {
            reason: "ML-DSA-87 signing public key must be 2592 bytes".to_string(),
        });
    }
    if public_key.iter().all(|byte| *byte == 0) {
        return Err(PgpError::InvalidKeyData {
            reason: "ML-DSA-87 signing public key must not be all zeros".to_string(),
        });
    }
    Ok(())
}

/// FIPS 203 ML-KEM-1024 encapsulation-key input validation. Same modulus check
/// as the 768 tier, over the four-vector (1536-byte) packed prefix.
fn validate_mlkem1024_public_key(public_key: &[u8]) -> Result<(), PgpError> {
    if public_key.len() != MLKEM1024_PUBLIC_KEY_LENGTH {
        return Err(PgpError::InvalidKeyData {
            reason: "ML-KEM-1024 key-agreement public key must be 1568 bytes".to_string(),
        });
    }
    if public_key.iter().all(|byte| *byte == 0) {
        return Err(PgpError::InvalidKeyData {
            reason: "ML-KEM-1024 key-agreement public key must not be all zeros".to_string(),
        });
    }
    if !mlkem_packed_vector_is_canonical(&public_key[..MLKEM1024_PACKED_VECTOR_LENGTH]) {
        return Err(PgpError::InvalidKeyData {
            reason: "ML-KEM-1024 key-agreement public key has non-canonical coefficients"
                .to_string(),
        });
    }
    Ok(())
}

/// FIPS 203 modulus check shared across ML-KEM parameter sets: every packed
/// 12-bit coefficient of the t-hat vectors must be canonical (< q). `packed` is
/// the polynomial-vector prefix of the encapsulation key, ahead of the opaque
/// 32-byte seed ρ.
fn mlkem_packed_vector_is_canonical(packed: &[u8]) -> bool {
    for chunk in packed.chunks_exact(3) {
        let low = u16::from(chunk[0]) | (u16::from(chunk[1] & 0x0F) << 8);
        let high = u16::from(chunk[1] >> 4) | (u16::from(chunk[2]) << 4);
        if low >= MLKEM_Q || high >= MLKEM_Q {
            return false;
        }
    }
    true
}

fn map_component_generation_error(error: composite_classical::ClassicalComponentError) -> PgpError {
    PgpError::KeyGenerationFailed {
        reason: format!("Failed to generate classical component: {error}"),
    }
}

fn map_external_composite_signing_key_generation_error(
    context: &str,
    error: openpgp::anyhow::Error,
) -> PgpError {
    map_external_signing_error(error, |reason| PgpError::KeyGenerationFailed {
        reason: format!("{context}: {reason}"),
    })
}

fn map_external_composite_signing_revocation_error(
    context: &str,
    error: openpgp::anyhow::Error,
) -> PgpError {
    map_external_signing_error(error, |reason| PgpError::RevocationError {
        reason: format!("{context}: {reason}"),
    })
}

fn map_key_generation_error(error: impl std::fmt::Display) -> PgpError {
    PgpError::KeyGenerationFailed {
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests;
