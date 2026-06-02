use super::*;

use openpgp::crypto::mpi;
use openpgp::packet::{key, signature, Key, Packet, UserID};
use openpgp::types::{
    Curve, Features, HashAlgorithm, KeyFlags, PublicKeyAlgorithm, SignatureType, SymmetricAlgorithm,
};
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcPoint};
use openssl::nid::Nid;

use crate::external_signer::{map_external_signing_error, signer_for_provider};

const P256_X963_PUBLIC_KEY_LENGTH: usize = 65;
#[cfg(test)]
const P256_SCALAR_LENGTH: usize = 32;
const DEFAULT_VALIDITY_SECONDS: u64 = 2 * 365 * 24 * 60 * 60;

pub fn generate_secure_enclave_public_certificate(
    input: SecureEnclavePublicCertificateInput,
    signer: Arc<dyn ExternalP256SigningProvider>,
) -> Result<SecureEnclaveGeneratedPublicCertificate, PgpError> {
    validate_public_key_point(&input.signing_public_key_x963, "signing public key")?;
    validate_public_key_point(
        &input.key_agreement_public_key_x963,
        "key-agreement public key",
    )?;
    if input.signing_public_key_x963 == input.key_agreement_public_key_x963 {
        return Err(PgpError::InvalidKeyData {
            reason: "Secure Enclave custody roles require distinct public keys".to_string(),
        });
    }

    let user_id = match &input.email {
        Some(email) => format!("{} <{}>", input.name, email),
        None => input.name.clone(),
    };
    if user_id.trim().is_empty() {
        return Err(PgpError::InvalidKeyData {
            reason: "Secure Enclave custody User ID must not be empty".to_string(),
        });
    }

    let created_at = SystemTime::now();
    let signing_key = make_signing_key(
        input.version,
        created_at,
        input.signing_public_key_x963.as_slice(),
    )?;
    let key_agreement_key = make_key_agreement_key(
        input.version,
        created_at,
        input.key_agreement_public_key_x963.as_slice(),
    )?;
    let signing_public = signing_key.clone().role_as_unspecified().clone();
    let validity = Duration::from_secs(input.expiry_seconds.unwrap_or(DEFAULT_VALIDITY_SECONDS));

    let mut external_signer =
        signer_for_provider(signing_public.clone(), signer.clone()).map_err(|error| {
            PgpError::KeyGenerationFailed {
                reason: error.to_string(),
            }
        })?;

    let mut cert = openpgp::Cert::try_from(vec![Packet::from(signing_key)]).map_err(|error| {
        PgpError::KeyGenerationFailed {
            reason: format!("Failed to create public certificate: {error}"),
        }
    })?;

    let user_id_packet = UserID::from(user_id);
    let mut user_id_builder =
        signature::SignatureBuilder::new(SignatureType::PositiveCertification)
            .set_hash_algo(HashAlgorithm::SHA256)
            .set_key_flags(KeyFlags::empty().set_certification().set_signing())
            .map_err(|error| PgpError::KeyGenerationFailed {
                reason: format!("Failed to set user ID key flags: {error}"),
            })?
            .set_key_validity_period(validity)
            .map_err(|error| PgpError::KeyGenerationFailed {
                reason: format!("Failed to set key validity period: {error}"),
            })?;
    user_id_builder = match input.version {
        SecureEnclaveCertificateVersion::V4 => user_id_builder
            .set_features(Features::empty().set_seipdv1())
            .map_err(|error| PgpError::KeyGenerationFailed {
                reason: format!("Failed to set v4 features: {error}"),
            })?,
        SecureEnclaveCertificateVersion::V6 => user_id_builder
            .set_features(Features::empty().set_seipdv2())
            .map_err(|error| PgpError::KeyGenerationFailed {
                reason: format!("Failed to set v6 features: {error}"),
            })?,
    };

    let user_id_binding = user_id_packet
        .bind(&mut external_signer, &cert, user_id_builder)
        .map_err(|error| {
            map_external_signing_key_generation_error("Failed to bind user ID", error)
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
                .set_hash_algo(HashAlgorithm::SHA256)
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
            map_external_signing_key_generation_error("Failed to bind key-agreement subkey", error)
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
        .build(&mut external_signer, &cert, HashAlgorithm::SHA256)
        .map_err(|error| {
            map_external_signing_revocation_error("Failed to generate key revocation", error)
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

    Ok(SecureEnclaveGeneratedPublicCertificate {
        public_key_data,
        revocation_cert,
        fingerprint: cert.fingerprint().to_hex().to_lowercase(),
        key_version: cert.primary_key().key().version(),
        signing_key_fingerprint: signing_public.fingerprint().to_hex().to_lowercase(),
        key_agreement_subkey_fingerprint: key_agreement_fingerprint,
    })
}

pub fn inspect_secure_enclave_public_bindings(
    public_key_data: &[u8],
) -> Result<SecureEnclavePublicBindingInspection, PgpError> {
    reject_armored_certificate_input(public_key_data)?;

    let cert =
        openpgp::Cert::from_bytes(public_key_data).map_err(|error| PgpError::InvalidKeyData {
            reason: format!("Invalid Secure Enclave custody public certificate: {error}"),
        })?;
    if cert.is_tsk() {
        return Err(PgpError::InvalidKeyData {
            reason: "Secure Enclave custody inspection requires public certificate material"
                .to_string(),
        });
    }

    let primary = cert.primary_key().key();
    let signing_public_key_x963 = match primary.mpis() {
        mpi::PublicKey::ECDSA {
            curve: Curve::NistP256,
            q,
        } => q.value().to_vec(),
        _ => {
            return Err(PgpError::InvalidKeyData {
                reason: "Secure Enclave custody primary key must be ECDSA P-256".to_string(),
            })
        }
    };
    validate_public_key_point(&signing_public_key_x963, "signing public key")?;

    let mut raw_p256_ecdh_subkeys = cert
        .keys()
        .subkeys()
        .filter_map(|subkey| match subkey.key().mpis() {
            mpi::PublicKey::ECDH {
                curve: Curve::NistP256,
                q,
                hash: HashAlgorithm::SHA256,
                sym: SymmetricAlgorithm::AES256,
            } => Some((
                subkey.key().fingerprint().to_hex().to_lowercase(),
                q.value().to_vec(),
            )),
            _ => None,
        })
        .collect::<Vec<_>>();

    if raw_p256_ecdh_subkeys.is_empty() {
        return Err(PgpError::InvalidKeyData {
            reason: "Secure Enclave custody certificate is missing a P-256 ECDH subkey".to_string(),
        });
    }
    if raw_p256_ecdh_subkeys.len() != 1 {
        return Err(PgpError::InvalidKeyData {
            reason: "Secure Enclave custody certificate must contain exactly one P-256 ECDH subkey"
                .to_string(),
        });
    }
    let (key_agreement_subkey_fingerprint, key_agreement_public_key_x963) =
        raw_p256_ecdh_subkeys.remove(0);
    validate_public_key_point(&key_agreement_public_key_x963, "key-agreement public key")?;
    if signing_public_key_x963 == key_agreement_public_key_x963 {
        return Err(PgpError::InvalidKeyData {
            reason: "Secure Enclave custody roles require distinct public keys".to_string(),
        });
    }

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
            reason:
                "Secure Enclave custody key-agreement subkey is not transport-encryption capable"
                    .to_string(),
        });
    }

    Ok(SecureEnclavePublicBindingInspection {
        fingerprint: cert.fingerprint().to_hex().to_lowercase(),
        key_version: primary.version(),
        signing_key_fingerprint: primary.fingerprint().to_hex().to_lowercase(),
        key_agreement_subkey_fingerprint,
        signing_public_key_x963,
        key_agreement_public_key_x963,
    })
}

fn make_signing_key(
    version: SecureEnclaveCertificateVersion,
    created_at: SystemTime,
    public_key_x963: &[u8],
) -> Result<Key<key::PublicParts, key::PrimaryRole>, PgpError> {
    let mpis = mpi::PublicKey::ECDSA {
        curve: Curve::NistP256,
        q: mpi::MPI::new(public_key_x963),
    };
    let key = match version {
        SecureEnclaveCertificateVersion::V4 => {
            key::Key4::new(created_at, PublicKeyAlgorithm::ECDSA, mpis)
                .map_err(map_key_generation_error)?
                .into()
        }
        SecureEnclaveCertificateVersion::V6 => {
            key::Key6::new(created_at, PublicKeyAlgorithm::ECDSA, mpis)
                .map_err(map_key_generation_error)?
                .into()
        }
    };
    Ok(key)
}

fn make_key_agreement_key(
    version: SecureEnclaveCertificateVersion,
    created_at: SystemTime,
    public_key_x963: &[u8],
) -> Result<Key<key::PublicParts, key::SubordinateRole>, PgpError> {
    let mpis = mpi::PublicKey::ECDH {
        curve: Curve::NistP256,
        q: mpi::MPI::new(public_key_x963),
        hash: HashAlgorithm::SHA256,
        sym: SymmetricAlgorithm::AES256,
    };
    let key = match version {
        SecureEnclaveCertificateVersion::V4 => {
            key::Key4::new(created_at, PublicKeyAlgorithm::ECDH, mpis)
                .map_err(map_key_generation_error)?
                .into()
        }
        SecureEnclaveCertificateVersion::V6 => {
            key::Key6::new(created_at, PublicKeyAlgorithm::ECDH, mpis)
                .map_err(map_key_generation_error)?
                .into()
        }
    };
    Ok(key)
}

fn map_external_signing_key_generation_error(
    context: &str,
    error: openpgp::anyhow::Error,
) -> PgpError {
    map_external_signing_error(error, |reason| PgpError::KeyGenerationFailed {
        reason: format!("{context}: {reason}"),
    })
}

fn map_external_signing_revocation_error(context: &str, error: openpgp::anyhow::Error) -> PgpError {
    map_external_signing_error(error, |reason| PgpError::RevocationError {
        reason: format!("{context}: {reason}"),
    })
}

fn validate_public_key_point(public_key_x963: &[u8], label: &str) -> Result<(), PgpError> {
    if public_key_x963.len() != P256_X963_PUBLIC_KEY_LENGTH || public_key_x963[0] != 0x04 {
        return Err(PgpError::InvalidKeyData {
            reason: format!("{label} must be an uncompressed P-256 X9.63 public key"),
        });
    }
    if public_key_x963[1..].iter().all(|byte| *byte == 0) {
        return Err(PgpError::InvalidKeyData {
            reason: format!("{label} must not be the point at infinity"),
        });
    }

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|error| {
        PgpError::InternalError {
            reason: format!("Failed to initialize P-256 group: {error}"),
        }
    })?;
    let mut context = BigNumContext::new().map_err(|error| PgpError::InternalError {
        reason: format!("Failed to initialize P-256 context: {error}"),
    })?;
    let point = EcPoint::from_bytes(&group, public_key_x963, &mut context).map_err(|_| {
        PgpError::InvalidKeyData {
            reason: format!("{label} is not a valid P-256 public point"),
        }
    })?;
    let on_curve =
        point
            .is_on_curve(&group, &mut context)
            .map_err(|_| PgpError::InvalidKeyData {
                reason: format!("{label} is not a valid P-256 public point"),
            })?;
    if !on_curve {
        return Err(PgpError::InvalidKeyData {
            reason: format!("{label} is not a valid P-256 public point"),
        });
    }
    Ok(())
}

fn map_key_generation_error(error: impl std::fmt::Display) -> PgpError {
    PgpError::KeyGenerationFailed {
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests;
