use sequoia_openpgp as openpgp;

use openpgp::crypto::{mpi, Signer};
use openpgp::packet::{key, Key};
use openpgp::types::{Curve, HashAlgorithm, PublicKeyAlgorithm};

const P256_SCALAR_LENGTH: usize = 32;
const P256_ACCEPTABLE_HASHES: &[HashAlgorithm] = &[HashAlgorithm::SHA256];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExternalP256Signature {
    r: Vec<u8>,
    s: Vec<u8>,
}

impl ExternalP256Signature {
    pub(crate) fn new(r: Vec<u8>, s: Vec<u8>) -> Self {
        Self { r, s }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExternalP256SignerError {
    InvalidRequest(&'static str),
    InvalidResponse(&'static str),
    ExternalFailure(&'static str),
}

impl ExternalP256SignerError {
    fn sanitized_reason(self) -> &'static str {
        match self {
            ExternalP256SignerError::InvalidRequest(reason)
            | ExternalP256SignerError::InvalidResponse(reason)
            | ExternalP256SignerError::ExternalFailure(reason) => reason,
        }
    }
}

pub(crate) struct ExternalP256Signer<F>
where
    F: FnMut(HashAlgorithm, &[u8]) -> Result<ExternalP256Signature, ExternalP256SignerError>,
{
    public_key: Key<key::PublicParts, key::UnspecifiedRole>,
    sign_operation: F,
}

impl<F> ExternalP256Signer<F>
where
    F: FnMut(HashAlgorithm, &[u8]) -> Result<ExternalP256Signature, ExternalP256SignerError>,
{
    pub(crate) fn new(
        public_key: Key<key::PublicParts, key::UnspecifiedRole>,
        sign_operation: F,
    ) -> openpgp::Result<Self> {
        match (public_key.pk_algo(), public_key.mpis()) {
            (
                PublicKeyAlgorithm::ECDSA,
                mpi::PublicKey::ECDSA {
                    curve: Curve::NistP256,
                    ..
                },
            ) => Ok(Self {
                public_key,
                sign_operation,
            }),
            _ => Err(openpgp::Error::InvalidOperation(
                "external P-256 signer requires an ECDSA P-256 public key".to_string(),
            )
            .into()),
        }
    }

    fn validate_request(
        hash_algo: HashAlgorithm,
        digest: &[u8],
    ) -> Result<(), ExternalP256SignerError> {
        if hash_algo != HashAlgorithm::SHA256 {
            return Err(ExternalP256SignerError::InvalidRequest(
                "external P-256 signer supports SHA-256 only",
            ));
        }

        if digest.len() != P256_SCALAR_LENGTH {
            return Err(ExternalP256SignerError::InvalidRequest(
                "external P-256 signer received an invalid digest length",
            ));
        }

        Ok(())
    }

    fn validate_response(
        signature: ExternalP256Signature,
    ) -> Result<mpi::Signature, ExternalP256SignerError> {
        if signature.r.len() != P256_SCALAR_LENGTH || signature.s.len() != P256_SCALAR_LENGTH {
            return Err(ExternalP256SignerError::InvalidResponse(
                "external P-256 signer returned an invalid signature shape",
            ));
        }

        if signature.r.iter().all(|byte| *byte == 0) || signature.s.iter().all(|byte| *byte == 0) {
            return Err(ExternalP256SignerError::InvalidResponse(
                "external P-256 signer returned an invalid zero scalar",
            ));
        }

        Ok(mpi::Signature::ECDSA {
            r: mpi::MPI::new(&signature.r),
            s: mpi::MPI::new(&signature.s),
        })
    }
}

impl<F> Signer for ExternalP256Signer<F>
where
    F: FnMut(HashAlgorithm, &[u8]) -> Result<ExternalP256Signature, ExternalP256SignerError>
        + Send
        + Sync,
{
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        &self.public_key
    }

    fn acceptable_hashes(&self) -> &[HashAlgorithm] {
        P256_ACCEPTABLE_HASHES
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8]) -> openpgp::Result<mpi::Signature> {
        Self::validate_request(hash_algo, digest).map_err(|error| {
            openpgp::Error::InvalidOperation(error.sanitized_reason().to_string())
        })?;

        let signature = (self.sign_operation)(hash_algo, digest).map_err(|error| {
            openpgp::Error::InvalidOperation(error.sanitized_reason().to_string())
        })?;

        Self::validate_response(signature).map_err(|error| {
            openpgp::Error::InvalidOperation(error.sanitized_reason().to_string()).into()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use openpgp::packet::{key, signature, Packet, UserID};
    use openpgp::parse::Parse;
    use openpgp::policy::StandardPolicy;
    use openpgp::serialize::Serialize;
    use openpgp::types::{Features, KeyFlags, SignatureType};

    use crate::decrypt::SignatureStatus;
    use crate::error::PgpError;
    use crate::{keys, sign, verify};

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

        fn expected_key_version(self) -> u8 {
            match self {
                CandidateVersion::V4 => 4,
                CandidateVersion::V6 => 6,
            }
        }
    }

    struct CandidateMaterial {
        public_cert: Vec<u8>,
        signing_public_key: Key<key::PublicParts, key::UnspecifiedRole>,
        signing_keypair: openpgp::crypto::KeyPair,
    }

    fn build_candidate(version: CandidateVersion) -> openpgp::Result<CandidateMaterial> {
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
                .set_key_flags(KeyFlags::empty().set_transport_encryption())?,
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
            impl FnMut(
                    HashAlgorithm,
                    &[u8],
                ) -> Result<ExternalP256Signature, ExternalP256SignerError>
                + Send
                + Sync
                + 'a,
        >,
    > {
        ExternalP256Signer::new(public_key.clone(), move |hash_algo, digest| {
            match oracle.sign(hash_algo, digest) {
                Ok(mpi::Signature::ECDSA { r, s }) => Ok(ExternalP256Signature::new(
                    r.value_padded(P256_SCALAR_LENGTH)
                        .map_err(|_| {
                            ExternalP256SignerError::ExternalFailure("external P-256 oracle failed")
                        })?
                        .into_owned(),
                    s.value_padded(P256_SCALAR_LENGTH)
                        .map_err(|_| {
                            ExternalP256SignerError::ExternalFailure("external P-256 oracle failed")
                        })?
                        .into_owned(),
                )),
                Ok(_) => Err(ExternalP256SignerError::ExternalFailure(
                    "external P-256 oracle returned a non-ECDSA signature",
                )),
                Err(_) => Err(ExternalP256SignerError::ExternalFailure(
                    "external P-256 oracle failed",
                )),
            }
        })
    }

    fn assert_valid_public_candidate(version: CandidateVersion, public_cert: &[u8]) {
        let parsed = openpgp::Cert::from_bytes(public_cert).expect("candidate should parse");
        assert!(
            !parsed.is_tsk(),
            "Secure Enclave-shaped candidate must not contain secret key material"
        );
        let primary = parsed.primary_key().key();
        assert_eq!(primary.version(), version.expected_key_version());
        assert!(matches!(
            primary.mpis(),
            mpi::PublicKey::ECDSA {
                curve: Curve::NistP256,
                ..
            }
        ));
        let subkey = parsed
            .keys()
            .subkeys()
            .next()
            .expect("candidate should have one key-agreement subkey")
            .key();
        assert_ne!(primary.fingerprint(), subkey.fingerprint());
        assert!(matches!(
            subkey.mpis(),
            mpi::PublicKey::ECDH {
                curve: Curve::NistP256,
                ..
            }
        ));
        assert!(parsed.with_policy(&StandardPolicy::new(), None).is_ok());

        let validation = keys::validate_public_certificate(public_cert)
            .expect("candidate public certificate should validate");
        assert_eq!(
            validation.key_info.key_version,
            version.expected_key_version()
        );
        assert!(validation.key_info.has_encryption_subkey);

        let selectors = keys::discover_certificate_selectors(public_cert)
            .expect("candidate selectors should be discoverable");
        assert_eq!(selectors.user_ids.len(), 1);
        assert_eq!(selectors.subkeys.len(), 1);
    }

    #[test]
    fn test_external_signer_builds_valid_public_only_p256_certificates() {
        for version in CandidateVersion::all() {
            let material = build_candidate(version).expect("candidate should build");
            assert_valid_public_candidate(version, &material.public_cert);
        }
    }

    #[test]
    fn test_external_signer_cleartext_signatures_verify_for_v4_and_v6() {
        for version in CandidateVersion::all() {
            let mut material = build_candidate(version).expect("candidate should build");
            let signer = signer_for(&material.signing_public_key, &mut material.signing_keypair)
                .expect("external signer should initialize");
            let signed = sign::sign_cleartext_with_signer(
                format!("external signer {}", version.label()).as_bytes(),
                signer,
            )
            .expect("external cleartext signing should succeed");

            let result = verify::verify_cleartext_detailed(&signed, &[material.public_cert])
                .expect("external cleartext signature should verify");
            assert_eq!(result.legacy_status, SignatureStatus::Valid);
        }
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

            let result =
                verify::verify_detached_detailed(&data, &signature, &[material.public_cert])
                    .expect("external detached signature should verify");
            assert_eq!(result.legacy_status, SignatureStatus::Valid);
        }
    }

    #[test]
    fn test_external_signer_failure_does_not_fallback_to_secret_certificate_signing() {
        let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
        let signer = ExternalP256Signer::new(material.signing_public_key, |_hash, _digest| {
            Err(ExternalP256SignerError::ExternalFailure(
                "external P-256 signer failed",
            ))
        })
        .expect("external signer should initialize");

        let result = sign::sign_cleartext_with_signer(b"must not fallback", signer);
        assert!(matches!(result, Err(PgpError::SigningFailed { .. })));
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
}
