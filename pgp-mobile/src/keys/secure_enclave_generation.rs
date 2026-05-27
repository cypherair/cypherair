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
    if matches!(input.version, SecureEnclaveCertificateVersion::V4) {
        user_id_builder = user_id_builder
            .set_features(Features::empty().set_seipdv1())
            .map_err(|error| PgpError::KeyGenerationFailed {
                reason: format!("Failed to set v4 features: {error}"),
            })?;
    }

    let user_id_binding = user_id_packet
        .bind(&mut external_signer, &cert, user_id_builder)
        .map_err(|error| PgpError::KeyGenerationFailed {
            reason: format!("Failed to bind user ID: {error}"),
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
        .map_err(|error| PgpError::KeyGenerationFailed {
            reason: format!("Failed to bind key-agreement subkey: {error}"),
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
        .map_err(|error| PgpError::RevocationError {
            reason: format!("Failed to generate key revocation: {error}"),
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
        let signature = provider.sign_sha256_digest(digest.to_vec()).map_err(|_| {
            ExternalP256SignerError::ExternalFailure("external P-256 signer failed")
        })?;
        Ok(ExternalP256Signature::new(signature.r, signature.s))
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
        fn sign_sha256_digest(&self, digest: Vec<u8>) -> Result<P256EcdsaSignature, PgpError> {
            let mut keypair = self.keypair.lock().map_err(|_| PgpError::InternalError {
                reason: "oracle signer lock poisoned".to_string(),
            })?;
            match keypair.sign(HashAlgorithm::SHA256, &digest) {
                Ok(mpi::Signature::ECDSA { r, s }) => Ok(P256EcdsaSignature {
                    r: r.value_padded(P256_SCALAR_LENGTH)
                        .map_err(|error| PgpError::SigningFailed {
                            reason: error.to_string(),
                        })?
                        .into_owned(),
                    s: s.value_padded(P256_SCALAR_LENGTH)
                        .map_err(|error| PgpError::SigningFailed {
                            reason: error.to_string(),
                        })?
                        .into_owned(),
                }),
                Ok(_) => Err(PgpError::SigningFailed {
                    reason: "oracle signer returned a non-ECDSA signature".to_string(),
                }),
                Err(error) => Err(PgpError::SigningFailed {
                    reason: error.to_string(),
                }),
            }
        }
    }

    struct FailingSigningProvider;

    impl ExternalP256SigningProvider for FailingSigningProvider {
        fn sign_sha256_digest(&self, _digest: Vec<u8>) -> Result<P256EcdsaSignature, PgpError> {
            Err(PgpError::SigningFailed {
                reason: "synthetic signer failure".to_string(),
            })
        }
    }

    struct MalformedSigningProvider;

    impl ExternalP256SigningProvider for MalformedSigningProvider {
        fn sign_sha256_digest(&self, _digest: Vec<u8>) -> Result<P256EcdsaSignature, PgpError> {
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
        fn sign_sha256_digest(&self, mut digest: Vec<u8>) -> Result<P256EcdsaSignature, PgpError> {
            digest[0] ^= 1;
            let mut keypair = self.keypair.lock().map_err(|_| PgpError::InternalError {
                reason: "oracle signer lock poisoned".to_string(),
            })?;
            match keypair.sign(HashAlgorithm::SHA256, &digest) {
                Ok(mpi::Signature::ECDSA { r, s }) => Ok(P256EcdsaSignature {
                    r: r.value_padded(P256_SCALAR_LENGTH)
                        .map_err(|error| PgpError::SigningFailed {
                            reason: error.to_string(),
                        })?
                        .into_owned(),
                    s: s.value_padded(P256_SCALAR_LENGTH)
                        .map_err(|error| PgpError::SigningFailed {
                            reason: error.to_string(),
                        })?
                        .into_owned(),
                }),
                _ => Err(PgpError::SigningFailed {
                    reason: "oracle signer failed".to_string(),
                }),
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
        assert!(cert.with_policy(&StandardPolicy::new(), None).is_ok());

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
