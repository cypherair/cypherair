use sequoia_openpgp as openpgp;
use std::sync::Arc;

use openpgp::crypto::{mpi, Signer};
use openpgp::packet::{key, Key};
use openpgp::types::{Curve, HashAlgorithm, PublicKeyAlgorithm};

use crate::error::PgpError;
use crate::keys::{
    ExternalP256SigningError, ExternalP256SigningFailureCategory, ExternalP256SigningProvider,
};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ExternalP256SignerError {
    #[error("external P-256 signer invalid request: {0}")]
    InvalidRequest(&'static str),
    #[error("external P-256 signer invalid response: {0}")]
    InvalidResponse(&'static str),
    #[error("external P-256 signer failed: {}", .0.stable_reason())]
    ExternalFailure(ExternalP256SigningFailureCategory),
    #[error("external P-256 signer operation cancelled")]
    OperationCancelled,
}

impl ExternalP256SignerError {
    #[cfg(test)]
    pub(crate) fn external_operation_failed() -> Self {
        Self::ExternalFailure(ExternalP256SigningFailureCategory::ExternalOperationFailed)
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
        public_key: &Key<key::PublicParts, key::UnspecifiedRole>,
        hash_algo: HashAlgorithm,
        digest: &[u8],
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

        let signature = mpi::Signature::ECDSA {
            r: mpi::MPI::new(&signature.r),
            s: mpi::MPI::new(&signature.s),
        };

        public_key
            .verify(&signature, hash_algo, digest)
            .map_err(|_| {
                ExternalP256SignerError::InvalidResponse(
                    "external P-256 signer returned an unverified signature",
                )
            })?;

        Ok(signature)
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
        Self::validate_request(hash_algo, digest)?;
        let signature = (self.sign_operation)(hash_algo, digest)?;
        Ok(Self::validate_response(
            &self.public_key,
            hash_algo,
            digest,
            signature,
        )?)
    }
}

pub(crate) fn signer_for_provider(
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

pub(crate) fn map_external_signing_error(
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
                PgpError::ExternalP256SigningFailed { category }
            }
            ExternalP256SignerError::InvalidRequest(reason)
            | ExternalP256SignerError::InvalidResponse(reason) => fallback(reason.to_string()),
        }
    } else {
        fallback(error.to_string())
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    use openpgp::packet::{key, signature, Packet, UserID};
    use openpgp::parse::Parse;
    use openpgp::policy::StandardPolicy;
    use openpgp::serialize::Serialize;
    use openpgp::types::{Features, KeyFlags, SignatureType};
    use std::sync::{Arc, Mutex};

    use crate::decrypt::SignatureStatus;
    use crate::error::PgpError;
    use crate::keys::{
        ExternalP256SigningError, ExternalP256SigningFailureCategory, ExternalP256SigningProvider,
        P256EcdsaSignature,
    };
    use crate::{keys, sign, streaming, verify};
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

    fn write_temp_data_file(data: &[u8]) -> NamedTempFile {
        let input = NamedTempFile::new().expect("temp input should be created");
        std::fs::write(input.path(), data).expect("temp input should be written");
        input
    }

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
            sign_digest_with_keypair(&mut keypair, &digest)
        }
    }

    struct FailingRuntimeSigningProvider {
        category: ExternalP256SigningFailureCategory,
    }

    impl ExternalP256SigningProvider for FailingRuntimeSigningProvider {
        fn sign_sha256_digest(
            &self,
            _digest: Vec<u8>,
        ) -> Result<P256EcdsaSignature, ExternalP256SigningError> {
            Err(ExternalP256SigningError::Failed {
                category: self.category,
            })
        }
    }

    struct CancelledRuntimeSigningProvider;

    impl ExternalP256SigningProvider for CancelledRuntimeSigningProvider {
        fn sign_sha256_digest(
            &self,
            _digest: Vec<u8>,
        ) -> Result<P256EcdsaSignature, ExternalP256SigningError> {
            Err(ExternalP256SigningError::OperationCancelled)
        }
    }

    struct MalformedRuntimeSigningProvider {
        r: Vec<u8>,
        s: Vec<u8>,
    }

    impl ExternalP256SigningProvider for MalformedRuntimeSigningProvider {
        fn sign_sha256_digest(
            &self,
            _digest: Vec<u8>,
        ) -> Result<P256EcdsaSignature, ExternalP256SigningError> {
            Ok(P256EcdsaSignature {
                r: self.r.clone(),
                s: self.s.clone(),
            })
        }
    }

    struct WrongDigestRuntimeSigningProvider {
        keypair: Mutex<openpgp::crypto::KeyPair>,
    }

    impl ExternalP256SigningProvider for WrongDigestRuntimeSigningProvider {
        fn sign_sha256_digest(
            &self,
            mut digest: Vec<u8>,
        ) -> Result<P256EcdsaSignature, ExternalP256SigningError> {
            digest[0] ^= 1;
            let mut keypair = self
                .keypair
                .lock()
                .map_err(|_| external_operation_failed())?;
            sign_digest_with_keypair(&mut keypair, &digest)
        }
    }

    struct UnexpectedRuntimeSigningProvider;

    impl ExternalP256SigningProvider for UnexpectedRuntimeSigningProvider {
        fn sign_sha256_digest(
            &self,
            _digest: Vec<u8>,
        ) -> Result<P256EcdsaSignature, ExternalP256SigningError> {
            panic!("runtime signing provider should not be called")
        }
    }

    fn runtime_provider(keypair: openpgp::crypto::KeyPair) -> Arc<dyn ExternalP256SigningProvider> {
        Arc::new(OracleSigningProvider {
            keypair: Mutex::new(keypair),
        })
    }

    fn external_operation_failed() -> ExternalP256SigningError {
        ExternalP256SigningError::Failed {
            category: ExternalP256SigningFailureCategory::ExternalOperationFailed,
        }
    }

    fn sign_digest_with_keypair(
        keypair: &mut openpgp::crypto::KeyPair,
        digest: &[u8],
    ) -> Result<P256EcdsaSignature, ExternalP256SigningError> {
        match keypair.sign(HashAlgorithm::SHA256, digest) {
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
    fn test_external_signer_runtime_cleartext_api_verifies_for_v4_and_v6() {
        for version in CandidateVersion::all() {
            let material = build_candidate(version).expect("candidate should build");
            let signing_key_fingerprint = material
                .signing_public_key
                .fingerprint()
                .to_hex()
                .to_lowercase();
            let signed = sign::sign_cleartext_with_external_p256_signer(
                format!("runtime external signer {}", version.label()).as_bytes(),
                &material.public_cert,
                &signing_key_fingerprint,
                runtime_provider(material.signing_keypair),
            )
            .expect("runtime external cleartext signing should succeed");

            let result = verify::verify_cleartext_detailed(&signed, &[material.public_cert])
                .expect("runtime external cleartext signature should verify");
            assert_eq!(result.legacy_status, SignatureStatus::Valid);
        }
    }

    #[test]
    fn test_external_signer_runtime_cleartext_cancellation_is_preserved() {
        let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
        let signing_key_fingerprint = material
            .signing_public_key
            .fingerprint()
            .to_hex()
            .to_lowercase();

        let result = sign::sign_cleartext_with_external_p256_signer(
            b"cancel runtime signing",
            &material.public_cert,
            &signing_key_fingerprint,
            Arc::new(CancelledRuntimeSigningProvider),
        );

        assert!(matches!(result, Err(PgpError::OperationCancelled)));
    }

    #[test]
    fn test_external_signer_runtime_cleartext_sanitizes_callback_failures() {
        let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
        let signing_key_fingerprint = material
            .signing_public_key
            .fingerprint()
            .to_hex()
            .to_lowercase();

        let result = sign::sign_cleartext_with_external_p256_signer(
            b"fail runtime signing",
            &material.public_cert,
            &signing_key_fingerprint,
            Arc::new(FailingRuntimeSigningProvider {
                category: ExternalP256SigningFailureCategory::PrivateHandleMissing,
            }),
        );

        match result {
            Err(PgpError::ExternalP256SigningFailed { category }) => {
                assert_eq!(
                    category,
                    ExternalP256SigningFailureCategory::PrivateHandleMissing
                );
            }
            other => panic!("expected sanitized ExternalP256SigningFailed, got {other:?}"),
        }
    }

    #[test]
    fn test_external_signer_runtime_cleartext_rejects_invalid_responses() {
        let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
        let signing_key_fingerprint = material
            .signing_public_key
            .fingerprint()
            .to_hex()
            .to_lowercase();

        for provider in [
            Arc::new(MalformedRuntimeSigningProvider {
                r: vec![1u8; P256_SCALAR_LENGTH - 1],
                s: vec![1u8; P256_SCALAR_LENGTH],
            }) as Arc<dyn ExternalP256SigningProvider>,
            Arc::new(MalformedRuntimeSigningProvider {
                r: vec![0u8; P256_SCALAR_LENGTH],
                s: vec![1u8; P256_SCALAR_LENGTH],
            }) as Arc<dyn ExternalP256SigningProvider>,
            Arc::new(WrongDigestRuntimeSigningProvider {
                keypair: Mutex::new(material.signing_keypair),
            }) as Arc<dyn ExternalP256SigningProvider>,
        ] {
            let result = sign::sign_cleartext_with_external_p256_signer(
                b"invalid runtime response",
                &material.public_cert,
                &signing_key_fingerprint,
                provider,
            );
            assert!(matches!(result, Err(PgpError::SigningFailed { .. })));
        }
    }

    #[test]
    fn test_external_signer_runtime_cleartext_rejects_wrong_public_key_signature() {
        let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
        let other = build_candidate(CandidateVersion::V4).expect("other should build");
        let signing_key_fingerprint = material
            .signing_public_key
            .fingerprint()
            .to_hex()
            .to_lowercase();

        let result = sign::sign_cleartext_with_external_p256_signer(
            b"wrong public key",
            &material.public_cert,
            &signing_key_fingerprint,
            runtime_provider(other.signing_keypair),
        );

        assert!(matches!(result, Err(PgpError::SigningFailed { .. })));
    }

    #[test]
    fn test_external_signer_runtime_cleartext_rejects_mismatched_fingerprint() {
        let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
        let other = build_candidate(CandidateVersion::V4).expect("other should build");
        let wrong_fingerprint = other
            .signing_public_key
            .fingerprint()
            .to_hex()
            .to_lowercase();

        let result = sign::sign_cleartext_with_external_p256_signer(
            b"wrong fingerprint",
            &material.public_cert,
            &wrong_fingerprint,
            runtime_provider(material.signing_keypair),
        );

        assert!(matches!(result, Err(PgpError::SigningFailed { .. })));
    }

    #[test]
    fn test_external_signer_runtime_cleartext_rejects_secret_non_p256_and_wrong_role_inputs() {
        let secret = keys::generate_key_with_profile(
            "Software Secret".to_string(),
            Some("software-secret@example.test".to_string()),
            None,
            keys::KeyProfile::Universal,
        )
        .expect("software key should generate");
        let secret_result = sign::sign_cleartext_with_external_p256_signer(
            b"secret-bearing input",
            &secret.cert_data,
            &secret.fingerprint,
            Arc::new(UnexpectedRuntimeSigningProvider),
        );
        assert!(matches!(
            secret_result,
            Err(PgpError::InvalidKeyData { .. })
        ));

        let non_p256_result = sign::sign_cleartext_with_external_p256_signer(
            b"non-p256 input",
            &secret.public_key_data,
            &secret.fingerprint,
            Arc::new(UnexpectedRuntimeSigningProvider),
        );
        assert!(matches!(
            non_p256_result,
            Err(PgpError::SigningFailed { .. })
        ));

        let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
        let cert = openpgp::Cert::from_bytes(&material.public_cert).expect("candidate parses");
        let key_agreement_fingerprint = cert
            .keys()
            .subkeys()
            .next()
            .expect("candidate has key-agreement subkey")
            .key()
            .fingerprint()
            .to_hex()
            .to_lowercase();
        let wrong_role_result = sign::sign_cleartext_with_external_p256_signer(
            b"wrong role input",
            &material.public_cert,
            &key_agreement_fingerprint,
            Arc::new(UnexpectedRuntimeSigningProvider),
        );
        assert!(matches!(
            wrong_role_result,
            Err(PgpError::SigningFailed { .. })
        ));
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
        let mut signer =
            ExternalP256Signer::new(material.signing_public_key, move |hash, digest| {
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
        let mut signer = ExternalP256Signer::new(
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
}
