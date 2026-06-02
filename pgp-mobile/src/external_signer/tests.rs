use super::*;

use openpgp::crypto::{mpi, Signer};
use openpgp::packet::{key, signature, Key, Packet, UserID};
use openpgp::serialize::Serialize;
use openpgp::types::{Curve, Features, HashAlgorithm, KeyFlags, SignatureType};
use sequoia_openpgp as openpgp;

use crate::decrypt::SignatureStatus;
use crate::error::PgpError;
use crate::keys::ExternalP256SigningFailureCategory;
use crate::{sign, streaming};
use tempfile::NamedTempFile;

#[derive(Clone, Copy, Debug)]
enum CandidateVersion {
    V4,
    V6,
}

impl CandidateVersion {
    fn all() -> [CandidateVersion; 2] {
        [CandidateVersion::V4, CandidateVersion::V6]
    }

    fn label(self) -> &'static str {
        match self {
            CandidateVersion::V4 => "v4",
            CandidateVersion::V6 => "v6",
        }
    }
}

struct CandidateMaterial {
    public_cert: Vec<u8>,
    signing_public_key: Key<key::PublicParts, key::UnspecifiedRole>,
    signing_keypair: openpgp::crypto::KeyPair,
}

fn build_candidate(version: CandidateVersion) -> openpgp::Result<CandidateMaterial> {
    build_candidate_with_expiry(version, None)
}

fn build_candidate_with_expiry(
    version: CandidateVersion,
    expiry_seconds: Option<u64>,
) -> openpgp::Result<CandidateMaterial> {
    let primary: Key<key::SecretParts, key::PrimaryRole> = match version {
        CandidateVersion::V4 => key::Key4::generate_ecc(true, Curve::NistP256)?.into(),
        CandidateVersion::V6 => key::Key6::generate_ecc(true, Curve::NistP256)?.into(),
    };
    let subkey: Key<key::PublicParts, key::SubordinateRole> = match version {
        CandidateVersion::V4 => key::Key4::generate_ecc(false, Curve::NistP256)?
            .parts_into_public()
            .into(),
        CandidateVersion::V6 => key::Key6::generate_ecc(false, Curve::NistP256)?
            .parts_into_public()
            .into(),
    };

    let signing_public_key = primary.parts_as_public().role_as_unspecified().clone();
    let mut oracle = primary.role_into_unspecified().into_keypair()?;

    let primary_public = signing_public_key.clone().role_into_primary();
    let mut cert = openpgp::Cert::try_from(vec![Packet::from(primary_public)])?;
    let user_id = UserID::from(format!(
        "SE {label} <se-{label}@example.test>",
        label = version.label()
    ));
    let mut user_id_builder =
        signature::SignatureBuilder::new(SignatureType::PositiveCertification)
            .set_hash_algo(HashAlgorithm::SHA256)
            .set_key_flags(KeyFlags::empty().set_certification().set_signing())?;
    let validity = expiry_seconds.map(std::time::Duration::from_secs);
    user_id_builder = user_id_builder.set_key_validity_period(validity)?;
    if matches!(version, CandidateVersion::V4) {
        user_id_builder = user_id_builder.set_features(Features::empty().set_seipdv1())?;
    }

    let user_id_binding = user_id.bind(
        &mut signer_for(&signing_public_key, &mut oracle)?,
        &cert,
        user_id_builder,
    )?;
    cert = cert
        .insert_packets(vec![Packet::from(user_id), user_id_binding.into()])?
        .0;

    let subkey_binding = subkey.bind(
        &mut signer_for(&signing_public_key, &mut oracle)?,
        &cert,
        signature::SignatureBuilder::new(SignatureType::SubkeyBinding)
            .set_hash_algo(HashAlgorithm::SHA256)
            .set_key_flags(KeyFlags::empty().set_transport_encryption())?
            .set_key_validity_period(validity)?,
    )?;
    cert = cert
        .insert_packets(vec![Packet::from(subkey), subkey_binding.into()])?
        .0;

    let mut public_cert = Vec::new();
    cert.serialize(&mut public_cert)?;

    Ok(CandidateMaterial {
        public_cert,
        signing_public_key,
        signing_keypair: oracle,
    })
}

fn signer_for<'a>(
    public_key: &Key<key::PublicParts, key::UnspecifiedRole>,
    oracle: &'a mut openpgp::crypto::KeyPair,
) -> openpgp::Result<
    ExternalP256Signer<
        impl FnMut(HashAlgorithm, &[u8]) -> Result<ExternalP256Signature, ExternalP256SignerError>
            + Send
            + Sync
            + 'a,
    >,
> {
    ExternalP256Signer::new(public_key.clone(), move |hash_algo, digest| {
        match oracle.sign(hash_algo, digest) {
            Ok(mpi::Signature::ECDSA { r, s }) => Ok(ExternalP256Signature::new(
                r.value_padded(P256_SCALAR_LENGTH)
                    .map_err(|_| ExternalP256SignerError::external_operation_failed())?
                    .into_owned(),
                s.value_padded(P256_SCALAR_LENGTH)
                    .map_err(|_| ExternalP256SignerError::external_operation_failed())?
                    .into_owned(),
            )),
            Ok(_) | Err(_) => Err(ExternalP256SignerError::external_operation_failed()),
        }
    })
}

fn write_temp_data_file(data: &[u8]) -> NamedTempFile {
    let input = NamedTempFile::new().expect("temp input should be created");
    std::fs::write(input.path(), data).expect("temp input should be written");
    input
}
#[test]
fn test_external_signer_detached_signatures_verify_for_v4_and_v6() {
    for version in CandidateVersion::all() {
        let mut material = build_candidate(version).expect("candidate should build");
        let signer = signer_for(&material.signing_public_key, &mut material.signing_keypair)
            .expect("external signer should initialize");
        let data = format!("detached external signer {}", version.label()).into_bytes();
        let signature =
            sign::sign_detached_with_signer(&data, signer).expect("detached signing succeeds");
        let input = write_temp_data_file(&data);

        let result = streaming::verify_detached_file_detailed(
            input.path().to_str().unwrap(),
            &signature,
            &[material.public_cert],
            None,
        )
        .expect("external detached signature should verify");
        assert_eq!(result.legacy_status, SignatureStatus::Valid);
    }
}

#[test]
fn test_external_signer_failure_does_not_fallback_to_secret_certificate_signing() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let signer = ExternalP256Signer::new(material.signing_public_key, |_hash, _digest| {
        Err(ExternalP256SignerError::external_operation_failed())
    })
    .expect("external signer should initialize");

    let result = sign::sign_cleartext_with_signer(b"must not fallback", signer);
    assert!(matches!(
        result,
        Err(PgpError::ExternalP256SigningFailed {
            category: ExternalP256SigningFailureCategory::ExternalOperationFailed
        })
    ));
}

#[test]
fn test_external_signer_rejects_key_agreement_role() {
    let agreement: Key<key::SecretParts, key::SubordinateRole> =
        key::Key4::generate_ecc(false, Curve::NistP256)
            .expect("P-256 ECDH key should generate")
            .into();

    assert!(ExternalP256Signer::new(
        agreement.parts_as_public().role_as_unspecified().clone(),
        |_hash, _digest| Ok(ExternalP256Signature::new(
            vec![1u8; P256_SCALAR_LENGTH],
            vec![1u8; P256_SCALAR_LENGTH],
        )),
    )
    .is_err());
}

#[test]
fn test_external_signer_rejects_unsupported_hash_and_invalid_shapes() {
    let mut material = build_candidate(CandidateVersion::V4).expect("candidate should build");

    {
        let mut unsupported_hash_signer =
            signer_for(&material.signing_public_key, &mut material.signing_keypair)
                .expect("external signer should initialize");
        assert!(unsupported_hash_signer
            .sign(HashAlgorithm::SHA512, &[0u8; P256_SCALAR_LENGTH])
            .is_err());
    }

    {
        let mut invalid_digest_signer =
            signer_for(&material.signing_public_key, &mut material.signing_keypair)
                .expect("external signer should initialize");
        assert!(invalid_digest_signer
            .sign(HashAlgorithm::SHA256, &[0u8; P256_SCALAR_LENGTH - 1])
            .is_err());
    }

    let mut invalid_response_signer =
        ExternalP256Signer::new(material.signing_public_key, |_hash, _digest| {
            Ok(ExternalP256Signature::new(
                vec![1u8; P256_SCALAR_LENGTH - 1],
                vec![1u8; P256_SCALAR_LENGTH],
            ))
        })
        .expect("external signer should initialize");
    assert!(invalid_response_signer
        .sign(HashAlgorithm::SHA256, &[0u8; P256_SCALAR_LENGTH])
        .is_err());
}

#[test]
fn test_external_signer_rejects_wrong_digest_signature() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let mut oracle = material.signing_keypair;
    let mut signer = ExternalP256Signer::new(material.signing_public_key, move |hash, digest| {
        let mut wrong_digest = digest.to_vec();
        wrong_digest[0] ^= 1;
        match oracle.sign(hash, &wrong_digest) {
            Ok(mpi::Signature::ECDSA { r, s }) => Ok(ExternalP256Signature::new(
                r.value_padded(P256_SCALAR_LENGTH)
                    .map_err(|_| ExternalP256SignerError::external_operation_failed())?
                    .into_owned(),
                s.value_padded(P256_SCALAR_LENGTH)
                    .map_err(|_| ExternalP256SignerError::external_operation_failed())?
                    .into_owned(),
            )),
            _ => Err(ExternalP256SignerError::external_operation_failed()),
        }
    })
    .expect("external signer should initialize");

    assert!(signer
        .sign(HashAlgorithm::SHA256, &[7u8; P256_SCALAR_LENGTH])
        .is_err());
}

#[test]
fn test_external_signer_rejects_wrong_public_key_signature() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let other = build_candidate(CandidateVersion::V4).expect("other candidate should build");
    let mut oracle = other.signing_keypair;
    let mut signer =
        ExternalP256Signer::new(
            material.signing_public_key,
            move |hash, digest| match oracle.sign(hash, digest) {
                Ok(mpi::Signature::ECDSA { r, s }) => Ok(ExternalP256Signature::new(
                    r.value_padded(P256_SCALAR_LENGTH)
                        .map_err(|_| ExternalP256SignerError::external_operation_failed())?
                        .into_owned(),
                    s.value_padded(P256_SCALAR_LENGTH)
                        .map_err(|_| ExternalP256SignerError::external_operation_failed())?
                        .into_owned(),
                )),
                _ => Err(ExternalP256SignerError::external_operation_failed()),
            },
        )
        .expect("external signer should initialize");

    assert!(signer
        .sign(HashAlgorithm::SHA256, &[9u8; P256_SCALAR_LENGTH])
        .is_err());
}
