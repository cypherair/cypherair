use super::*;

use openpgp::crypto::mpi;
use openpgp::packet::{key, signature, Key, Packet, UserID};
use openpgp::types::{
    Curve, Features, HashAlgorithm, KeyFlags, PublicKeyAlgorithm, SignatureType, SymmetricAlgorithm,
};
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcPoint};
use openssl::nid::Nid;

use crate::external_signer::{ExternalP256Signature, ExternalP256Signer, ExternalP256SignerError};

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
    let is_transport_encryption_capable = cert
        .keys()
        .subkeys()
        .with_policy(&policy, None)
        .supported()
        .for_transport_encryption()
        .any(|subkey| {
            subkey.key().fingerprint().to_hex().to_lowercase() == key_agreement_subkey_fingerprint
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

fn signer_for_provider(
    public_key: Key<key::PublicParts, key::UnspecifiedRole>,
    provider: Arc<dyn ExternalP256SigningProvider>,
) -> openpgp::Result<
    ExternalP256Signer<
        impl FnMut(HashAlgorithm, &[u8]) -> Result<ExternalP256Signature, ExternalP256SignerError>
            + Send
            + Sync,
    >,
> {
    ExternalP256Signer::new(public_key, move |hash_algorithm, digest| {
        if hash_algorithm != HashAlgorithm::SHA256 {
            return Err(ExternalP256SignerError::InvalidRequest(
                "external P-256 signer supports SHA-256 only",
            ));
        }
        let signature = provider
            .sign_sha256_digest(digest.to_vec())
            .map_err(external_signing_error_to_signer_error)?;
        Ok(ExternalP256Signature::new(signature.r, signature.s))
    })
}

fn external_signing_error_to_signer_error(
    error: ExternalP256SigningError,
) -> ExternalP256SignerError {
    match error {
        ExternalP256SigningError::Failed { category } => {
            ExternalP256SignerError::ExternalFailure(category)
        }
        ExternalP256SigningError::OperationCancelled => ExternalP256SignerError::OperationCancelled,
    }
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

fn map_external_signing_error(
    error: openpgp::anyhow::Error,
    fallback: impl FnOnce(String) -> PgpError,
) -> PgpError {
    if let Some(external_error) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<ExternalP256SignerError>().copied())
    {
        match external_error {
            ExternalP256SignerError::OperationCancelled => PgpError::OperationCancelled,
            ExternalP256SignerError::ExternalFailure(category) => {
                fallback(category.stable_reason().to_string())
            }
            ExternalP256SignerError::InvalidRequest(reason)
            | ExternalP256SignerError::InvalidResponse(reason) => fallback(reason.to_string()),
        }
    } else {
        fallback(error.to_string())
    }
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
mod tests {
    use super::*;

    use std::sync::{Arc, Mutex};

    use openpgp::crypto::Signer;
    use openpgp::parse::Parse;
    use openpgp::policy::StandardPolicy;

    struct OracleSigningProvider {
        keypair: Mutex<openpgp::crypto::KeyPair>,
    }

    impl ExternalP256SigningProvider for OracleSigningProvider {
        fn sign_sha256_digest(
            &self,
            digest: Vec<u8>,
        ) -> Result<P256EcdsaSignature, ExternalP256SigningError> {
            let mut keypair = self
                .keypair
                .lock()
                .map_err(|_| external_operation_failed())?;
            match keypair.sign(HashAlgorithm::SHA256, &digest) {
                Ok(mpi::Signature::ECDSA { r, s }) => Ok(P256EcdsaSignature {
                    r: r.value_padded(P256_SCALAR_LENGTH)
                        .map_err(|_| external_operation_failed())?
                        .into_owned(),
                    s: s.value_padded(P256_SCALAR_LENGTH)
                        .map_err(|_| external_operation_failed())?
                        .into_owned(),
                }),
                Ok(_) | Err(_) => Err(external_operation_failed()),
            }
        }
    }

    fn external_operation_failed() -> ExternalP256SigningError {
        ExternalP256SigningError::Failed {
            category: ExternalP256SigningFailureCategory::ExternalOperationFailed,
        }
    }

    struct FailingSigningProvider;

    impl ExternalP256SigningProvider for FailingSigningProvider {
        fn sign_sha256_digest(
            &self,
            _digest: Vec<u8>,
        ) -> Result<P256EcdsaSignature, ExternalP256SigningError> {
            Err(external_operation_failed())
        }
    }

    struct CategoryFailureSigningProvider {
        category: ExternalP256SigningFailureCategory,
    }

    impl ExternalP256SigningProvider for CategoryFailureSigningProvider {
        fn sign_sha256_digest(
            &self,
            _digest: Vec<u8>,
        ) -> Result<P256EcdsaSignature, ExternalP256SigningError> {
            Err(ExternalP256SigningError::Failed {
                category: self.category,
            })
        }
    }

    struct CancelledSigningProvider;

    impl ExternalP256SigningProvider for CancelledSigningProvider {
        fn sign_sha256_digest(
            &self,
            _digest: Vec<u8>,
        ) -> Result<P256EcdsaSignature, ExternalP256SigningError> {
            Err(ExternalP256SigningError::OperationCancelled)
        }
    }

    struct MalformedSigningProvider;

    impl ExternalP256SigningProvider for MalformedSigningProvider {
        fn sign_sha256_digest(
            &self,
            _digest: Vec<u8>,
        ) -> Result<P256EcdsaSignature, ExternalP256SigningError> {
            Ok(P256EcdsaSignature {
                r: vec![1u8; P256_SCALAR_LENGTH - 1],
                s: vec![1u8; P256_SCALAR_LENGTH],
            })
        }
    }

    struct WrongDigestSigningProvider {
        keypair: Mutex<openpgp::crypto::KeyPair>,
    }

    impl ExternalP256SigningProvider for WrongDigestSigningProvider {
        fn sign_sha256_digest(
            &self,
            mut digest: Vec<u8>,
        ) -> Result<P256EcdsaSignature, ExternalP256SigningError> {
            digest[0] ^= 1;
            let mut keypair = self
                .keypair
                .lock()
                .map_err(|_| external_operation_failed())?;
            match keypair.sign(HashAlgorithm::SHA256, &digest) {
                Ok(mpi::Signature::ECDSA { r, s }) => Ok(P256EcdsaSignature {
                    r: r.value_padded(P256_SCALAR_LENGTH)
                        .map_err(|_| external_operation_failed())?
                        .into_owned(),
                    s: s.value_padded(P256_SCALAR_LENGTH)
                        .map_err(|_| external_operation_failed())?
                        .into_owned(),
                }),
                _ => Err(external_operation_failed()),
            }
        }
    }

    struct PublicMaterial {
        signing_public_key_x963: Vec<u8>,
        key_agreement_public_key_x963: Vec<u8>,
        signing_keypair: openpgp::crypto::KeyPair,
    }

    fn public_material(
        version: SecureEnclaveCertificateVersion,
    ) -> openpgp::Result<PublicMaterial> {
        let signing: Key<key::SecretParts, key::PrimaryRole> = match version {
            SecureEnclaveCertificateVersion::V4 => {
                key::Key4::generate_ecc(true, Curve::NistP256)?.into()
            }
            SecureEnclaveCertificateVersion::V6 => {
                key::Key6::generate_ecc(true, Curve::NistP256)?.into()
            }
        };
        let key_agreement: Key<key::SecretParts, key::SubordinateRole> = match version {
            SecureEnclaveCertificateVersion::V4 => {
                key::Key4::generate_ecc(false, Curve::NistP256)?.into()
            }
            SecureEnclaveCertificateVersion::V6 => {
                key::Key6::generate_ecc(false, Curve::NistP256)?.into()
            }
        };
        let signing_public_key_x963 =
            public_key_x963(signing.parts_as_public().role_as_unspecified())?;
        let key_agreement_public_key_x963 =
            public_key_x963(key_agreement.parts_as_public().role_as_unspecified())?;
        Ok(PublicMaterial {
            signing_public_key_x963,
            key_agreement_public_key_x963,
            signing_keypair: signing.role_into_unspecified().into_keypair()?,
        })
    }

    fn public_key_x963(
        key: &Key<key::PublicParts, key::UnspecifiedRole>,
    ) -> openpgp::Result<Vec<u8>> {
        match key.mpis() {
            mpi::PublicKey::ECDSA { q, .. } | mpi::PublicKey::ECDH { q, .. } => {
                Ok(q.value().into())
            }
            _ => Err(
                openpgp::Error::InvalidOperation("expected P-256 public point".to_string()).into(),
            ),
        }
    }

    fn input_for(
        version: SecureEnclaveCertificateVersion,
        material: &PublicMaterial,
    ) -> SecureEnclavePublicCertificateInput {
        SecureEnclavePublicCertificateInput {
            name: format!("Secure Enclave {:?}", version),
            email: Some("secure-enclave@example.test".to_string()),
            expiry_seconds: Some(3600),
            version,
            signing_public_key_x963: material.signing_public_key_x963.clone(),
            key_agreement_public_key_x963: material.key_agreement_public_key_x963.clone(),
        }
    }

    fn provider_for(material: PublicMaterial) -> Arc<dyn ExternalP256SigningProvider> {
        Arc::new(OracleSigningProvider {
            keypair: Mutex::new(material.signing_keypair),
        })
    }

    fn assert_valid_result(
        version: SecureEnclaveCertificateVersion,
        result: &SecureEnclaveGeneratedPublicCertificate,
        signing_public_key_x963: &[u8],
        key_agreement_public_key_x963: &[u8],
    ) {
        let cert = openpgp::Cert::from_bytes(&result.public_key_data).expect("cert should parse");
        assert!(
            !cert.is_tsk(),
            "Secure Enclave generated certificate must be public-only"
        );
        assert_eq!(
            cert.primary_key().key().version(),
            match version {
                SecureEnclaveCertificateVersion::V4 => 4,
                SecureEnclaveCertificateVersion::V6 => 6,
            }
        );
        assert_eq!(result.key_version, cert.primary_key().key().version());
        assert_eq!(
            result.fingerprint,
            cert.fingerprint().to_hex().to_lowercase()
        );
        assert_eq!(
            result.signing_key_fingerprint,
            cert.primary_key()
                .key()
                .fingerprint()
                .to_hex()
                .to_lowercase()
        );

        let primary = cert.primary_key().key();
        match primary.mpis() {
            mpi::PublicKey::ECDSA {
                curve: Curve::NistP256,
                q,
            } => assert_eq!(q.value(), signing_public_key_x963),
            _ => panic!("primary key should be ECDSA P-256"),
        }

        let subkey = cert
            .keys()
            .subkeys()
            .next()
            .expect("subkey should exist")
            .key();
        match subkey.mpis() {
            mpi::PublicKey::ECDH {
                curve: Curve::NistP256,
                q,
                hash: HashAlgorithm::SHA256,
                sym: SymmetricAlgorithm::AES256,
            } => assert_eq!(q.value(), key_agreement_public_key_x963),
            _ => panic!("subkey should be ECDH P-256 SHA-256/AES-256"),
        }
        assert_eq!(
            result.key_agreement_subkey_fingerprint,
            subkey.fingerprint().to_hex().to_lowercase()
        );
        let policy = StandardPolicy::new();
        let valid_cert = cert
            .with_policy(&policy, None)
            .expect("certificate should validate with standard policy");
        let features = valid_cert
            .primary_userid()
            .expect("primary user ID should exist")
            .binding_signature()
            .features()
            .expect("primary user ID binding should advertise features");
        match version {
            SecureEnclaveCertificateVersion::V4 => {
                assert!(features.supports_seipdv1());
                assert!(!features.supports_seipdv2());
            }
            SecureEnclaveCertificateVersion::V6 => {
                assert!(features.supports_seipdv2());
            }
        }

        let validation = validate_public_certificate(&result.public_key_data)
            .expect("public certificate should validate");
        assert!(validation.key_info.has_encryption_subkey);
        assert_eq!(
            validation.key_info.key_version,
            match version {
                SecureEnclaveCertificateVersion::V4 => 4,
                SecureEnclaveCertificateVersion::V6 => 6,
            }
        );
        let selectors = discover_certificate_selectors(&result.public_key_data)
            .expect("selectors should be discoverable");
        assert_eq!(selectors.user_ids.len(), 1);
        assert_eq!(selectors.subkeys.len(), 1);
        parse_revocation_cert(&result.revocation_cert, &result.public_key_data)
            .expect("revocation should verify with public cert");

        let inspection = inspect_secure_enclave_public_bindings(&result.public_key_data)
            .expect("Secure Enclave bindings should inspect");
        assert_eq!(inspection.fingerprint, result.fingerprint);
        assert_eq!(inspection.key_version, result.key_version);
        assert_eq!(
            inspection.signing_key_fingerprint,
            result.signing_key_fingerprint
        );
        assert_eq!(
            inspection.key_agreement_subkey_fingerprint,
            result.key_agreement_subkey_fingerprint
        );
        assert_eq!(inspection.signing_public_key_x963, signing_public_key_x963);
        assert_eq!(
            inspection.key_agreement_public_key_x963,
            key_agreement_public_key_x963
        );
    }

    #[test]
    fn test_secure_enclave_public_certificate_generation_v4_v6() {
        for version in [
            SecureEnclaveCertificateVersion::V4,
            SecureEnclaveCertificateVersion::V6,
        ] {
            let material = public_material(version).expect("material should generate");
            let input = input_for(version, &material);
            let signing_public_key_x963 = material.signing_public_key_x963.clone();
            let key_agreement_public_key_x963 = material.key_agreement_public_key_x963.clone();
            let result = generate_secure_enclave_public_certificate(input, provider_for(material))
                .expect("certificate should generate");
            assert_valid_result(
                version,
                &result,
                &signing_public_key_x963,
                &key_agreement_public_key_x963,
            );
        }
    }

    #[test]
    fn test_secure_enclave_public_certificate_rejects_invalid_or_duplicate_public_keys() {
        let material =
            public_material(SecureEnclaveCertificateVersion::V4).expect("material should generate");
        let mut invalid_shape = input_for(SecureEnclaveCertificateVersion::V4, &material);
        invalid_shape.signing_public_key_x963 = vec![0x04; P256_X963_PUBLIC_KEY_LENGTH - 1];
        assert!(generate_secure_enclave_public_certificate(
            invalid_shape,
            provider_for(public_material(SecureEnclaveCertificateVersion::V4).unwrap()),
        )
        .is_err());

        let mut duplicate = input_for(SecureEnclaveCertificateVersion::V4, &material);
        duplicate.key_agreement_public_key_x963 = duplicate.signing_public_key_x963.clone();
        assert!(
            generate_secure_enclave_public_certificate(duplicate, provider_for(material),).is_err()
        );
    }

    #[test]
    fn test_secure_enclave_public_binding_inspection_rejects_non_se_certificates() {
        let generated = generate_key_with_profile(
            "Software".to_string(),
            Some("software@example.test".to_string()),
            Some(3600),
            KeyProfile::Universal,
        )
        .expect("software key should generate");
        assert!(inspect_secure_enclave_public_bindings(&generated.public_key_data).is_err());
    }

    #[test]
    fn test_secure_enclave_public_binding_inspection_rejects_missing_or_wrong_role_material() {
        let material =
            public_material(SecureEnclaveCertificateVersion::V4).expect("material should generate");
        let created_at = SystemTime::now();

        let signing_key = make_signing_key(
            SecureEnclaveCertificateVersion::V4,
            created_at,
            &material.signing_public_key_x963,
        )
        .expect("signing key should build");
        let signing_only_cert = openpgp::Cert::try_from(vec![Packet::from(signing_key)])
            .expect("signing-only cert should build");
        let mut signing_only_data = Vec::new();
        signing_only_cert
            .serialize(&mut signing_only_data)
            .expect("signing-only cert should serialize");
        assert!(inspect_secure_enclave_public_bindings(&signing_only_data).is_err());

        let ecdh_primary_mpis = mpi::PublicKey::ECDH {
            curve: Curve::NistP256,
            q: mpi::MPI::new(&material.key_agreement_public_key_x963),
            hash: HashAlgorithm::SHA256,
            sym: SymmetricAlgorithm::AES256,
        };
        let ecdh_primary: Key<key::PublicParts, key::PrimaryRole> =
            key::Key4::new(created_at, PublicKeyAlgorithm::ECDH, ecdh_primary_mpis)
                .expect("ECDH primary should build")
                .into();
        let wrong_role_cert = openpgp::Cert::try_from(vec![Packet::from(ecdh_primary)])
            .expect("wrong-role cert should build");
        let mut wrong_role_data = Vec::new();
        wrong_role_cert
            .serialize(&mut wrong_role_data)
            .expect("wrong-role cert should serialize");
        assert!(inspect_secure_enclave_public_bindings(&wrong_role_data).is_err());
    }

    #[test]
    fn test_secure_enclave_public_binding_inspection_rejects_non_distinct_role_points() {
        let material =
            public_material(SecureEnclaveCertificateVersion::V4).expect("material should generate");
        let created_at = SystemTime::now();
        let signing_key = make_signing_key(
            SecureEnclaveCertificateVersion::V4,
            created_at,
            &material.signing_public_key_x963,
        )
        .expect("signing key should build");
        let key_agreement_key = make_key_agreement_key(
            SecureEnclaveCertificateVersion::V4,
            created_at,
            &material.signing_public_key_x963,
        )
        .expect("key-agreement key should build");
        let cert = openpgp::Cert::try_from(vec![
            Packet::from(signing_key),
            Packet::from(key_agreement_key),
        ])
        .expect("non-distinct role cert should build");
        let mut data = Vec::new();
        cert.serialize(&mut data)
            .expect("non-distinct role cert should serialize");

        assert!(inspect_secure_enclave_public_bindings(&data).is_err());
    }

    #[test]
    fn test_secure_enclave_public_certificate_external_signer_failures_fail_closed() {
        let material =
            public_material(SecureEnclaveCertificateVersion::V4).expect("material should generate");
        let input = input_for(SecureEnclaveCertificateVersion::V4, &material);
        assert!(generate_secure_enclave_public_certificate(
            input.clone(),
            Arc::new(FailingSigningProvider),
        )
        .is_err());
        assert!(generate_secure_enclave_public_certificate(
            input,
            Arc::new(MalformedSigningProvider),
        )
        .is_err());
    }

    #[test]
    fn test_secure_enclave_public_certificate_preserves_typed_callback_failure_category() {
        let material =
            public_material(SecureEnclaveCertificateVersion::V4).expect("material should generate");
        let input = input_for(SecureEnclaveCertificateVersion::V4, &material);
        let error = generate_secure_enclave_public_certificate(
            input,
            Arc::new(CategoryFailureSigningProvider {
                category: ExternalP256SigningFailureCategory::HardwareUnavailable,
            }),
        )
        .expect_err("callback failure should fail generation");

        match error {
            PgpError::KeyGenerationFailed { reason } => {
                assert!(reason.contains("hardwareUnavailable"));
                assert!(!reason.contains("raw-secret"));
                assert!(!reason.contains("/tmp"));
                assert!(!reason.contains("capability"));
            }
            other => panic!("expected key generation failure, got {other:?}"),
        }
    }

    #[test]
    fn test_secure_enclave_public_certificate_preserves_typed_callback_cancellation() {
        let material =
            public_material(SecureEnclaveCertificateVersion::V4).expect("material should generate");
        let input = input_for(SecureEnclaveCertificateVersion::V4, &material);
        let error =
            generate_secure_enclave_public_certificate(input, Arc::new(CancelledSigningProvider))
                .expect_err("callback cancellation should fail generation");

        assert!(matches!(error, PgpError::OperationCancelled));
    }

    #[test]
    fn test_secure_enclave_public_certificate_rejects_wrong_digest_signature() {
        let material =
            public_material(SecureEnclaveCertificateVersion::V4).expect("material should generate");
        let input = input_for(SecureEnclaveCertificateVersion::V4, &material);
        assert!(generate_secure_enclave_public_certificate(
            input,
            Arc::new(WrongDigestSigningProvider {
                keypair: Mutex::new(material.signing_keypair),
            }),
        )
        .is_err());
    }

    #[test]
    fn test_secure_enclave_public_certificate_rejects_wrong_public_key_signature() {
        let material =
            public_material(SecureEnclaveCertificateVersion::V4).expect("material should generate");
        let other =
            public_material(SecureEnclaveCertificateVersion::V4).expect("other should generate");
        let input = input_for(SecureEnclaveCertificateVersion::V4, &material);
        assert!(generate_secure_enclave_public_certificate(
            input,
            Arc::new(OracleSigningProvider {
                keypair: Mutex::new(other.signing_keypair),
            }),
        )
        .is_err());
    }
}
