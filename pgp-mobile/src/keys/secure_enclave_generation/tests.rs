use super::*;

use std::sync::{Arc, Mutex};

use openpgp::crypto::Signer;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::types::RevocationStatus;

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

fn public_material(version: SecureEnclaveCertificateVersion) -> openpgp::Result<PublicMaterial> {
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
    let signing_public_key_x963 = public_key_x963(signing.parts_as_public().role_as_unspecified())?;
    let key_agreement_public_key_x963 =
        public_key_x963(key_agreement.parts_as_public().role_as_unspecified())?;
    Ok(PublicMaterial {
        signing_public_key_x963,
        key_agreement_public_key_x963,
        signing_keypair: signing.role_into_unspecified().into_keypair()?,
    })
}

fn public_key_x963(key: &Key<key::PublicParts, key::UnspecifiedRole>) -> openpgp::Result<Vec<u8>> {
    match key.mpis() {
        mpi::PublicKey::ECDSA { q, .. } | mpi::PublicKey::ECDH { q, .. } => Ok(q.value().into()),
        _ => {
            Err(openpgp::Error::InvalidOperation("expected P-256 public point".to_string()).into())
        }
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
    let revocation_packet = Packet::from_bytes(&result.revocation_cert)
        .expect("revocation artifact should parse as one OpenPGP packet");
    match &revocation_packet {
        Packet::Signature(signature) => {
            assert_eq!(signature.typ(), SignatureType::KeyRevocation);
        }
        other => panic!("revocation artifact should be a signature packet, got {other:?}"),
    }
    let (revoked_cert, _) = cert
        .clone()
        .insert_packets(vec![revocation_packet])
        .expect("revocation artifact should merge into public cert");
    assert!(
        matches!(
            revoked_cert.revocation_status(&policy, None),
            RevocationStatus::Revoked(_)
        ),
        "merged revocation artifact should revoke the public cert"
    );

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
    let generated = generate_key_with_suite(
        "Software".to_string(),
        Some("software@example.test".to_string()),
        Some(3600),
        KeySuite::Ed25519LegacyCurve25519Legacy,
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
fn test_secure_enclave_public_binding_inspection_preserves_expired_bindings() {
    let cases = [
        SecureEnclaveCertificateVersion::V4,
        SecureEnclaveCertificateVersion::V6,
    ]
    .into_iter()
    .map(|version| {
        let material = public_material(version).expect("material should generate");
        let signing_public_key_x963 = material.signing_public_key_x963.clone();
        let key_agreement_public_key_x963 = material.key_agreement_public_key_x963.clone();
        let mut input = input_for(version, &material);
        input.expiry_seconds = Some(1);
        let result = generate_secure_enclave_public_certificate(input, provider_for(material))
            .expect("certificate should generate");
        (
            result,
            signing_public_key_x963,
            key_agreement_public_key_x963,
        )
    })
    .collect::<Vec<_>>();

    std::thread::sleep(Duration::from_secs(2));

    for (result, signing_public_key_x963, key_agreement_public_key_x963) in cases {
        let cert =
            openpgp::Cert::from_bytes(&result.public_key_data).expect("public cert should parse");
        let policy = StandardPolicy::new();
        let expiration_time = cert
            .with_policy(&policy, None)
            .expect("certificate should remain structurally policy-valid")
            .primary_key()
            .key_expiration_time()
            .expect("test certificate should have an expiration time");
        assert!(
            expiration_time <= SystemTime::now(),
            "test certificate should be past its advertised expiration time"
        );

        let inspection = inspect_secure_enclave_public_bindings(&result.public_key_data)
            .expect("expired Secure Enclave bindings should remain recoverable");
        assert_eq!(inspection.signing_public_key_x963, signing_public_key_x963);
        assert_eq!(
            inspection.key_agreement_public_key_x963,
            key_agreement_public_key_x963
        );
    }
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
    assert!(
        generate_secure_enclave_public_certificate(input, Arc::new(MalformedSigningProvider),)
            .is_err()
    );
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
        PgpError::ExternalP256SigningFailed { category } => {
            assert_eq!(
                category,
                ExternalP256SigningFailureCategory::HardwareUnavailable
            );
        }
        other => panic!("expected external signing failure, got {other:?}"),
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
