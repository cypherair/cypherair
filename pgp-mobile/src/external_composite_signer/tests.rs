use std::sync::{Arc, Mutex};

use sequoia_openpgp as openpgp;

use openpgp::cert::{CertBuilder, CipherSuite};
use openpgp::crypto::{mpi, Signer};
use openpgp::packet::key::SecretKeyMaterial;
use openpgp::packet::{key, Key};
use openpgp::types::HashAlgorithm;

use super::core::MLDSA65_SIGNATURE_LENGTH;
use super::{ExternalCompositeSigner, ExternalCompositeSignerError, ExternalMlDsa65SignatureBytes};

struct CompositeFixture {
    public_key: Key<key::PublicParts, key::UnspecifiedRole>,
    classical_eddsa_secret: Vec<u8>,
    keypair: Arc<Mutex<openpgp::crypto::KeyPair>>,
}

fn composite_fixture() -> CompositeFixture {
    let (cert, _rev) = CertBuilder::new()
        .set_cipher_suite(CipherSuite::MLDSA65_Ed25519)
        .set_profile(openpgp::Profile::RFC9580)
        .expect("set RFC 9580 profile")
        .add_userid("Composite Signer Unit <composite-signer@unit.test>")
        .generate()
        .expect("generate software composite cert");
    let primary = cert.primary_key().key().clone();
    let public_key = primary.parts_as_public().role_as_unspecified().clone();
    let classical_eddsa_secret = match primary.optional_secret() {
        Some(SecretKeyMaterial::Unencrypted(secret)) => secret.map(|mpis| match mpis {
            mpi::SecretKeyMaterial::MLDSA65_Ed25519 { eddsa, .. } => eddsa.to_vec(),
            _ => panic!("expected composite secret material"),
        }),
        _ => panic!("expected unencrypted secret material"),
    };
    let keypair = Arc::new(Mutex::new(
        primary
            .parts_into_secret()
            .expect("secret parts")
            .role_into_unspecified()
            .into_keypair()
            .expect("keypair"),
    ));
    CompositeFixture {
        public_key,
        classical_eddsa_secret,
        keypair,
    }
}

/// Sign with the full software composite keypair and return only the ML-DSA
/// half — exactly the Secure Enclave primitive shape.
fn oracle_mldsa_half(
    keypair: &Arc<Mutex<openpgp::crypto::KeyPair>>,
    digest: &[u8],
) -> ExternalMlDsa65SignatureBytes {
    let mut keypair = keypair.lock().expect("keypair lock");
    match keypair
        .sign(HashAlgorithm::SHA512, digest)
        .expect("oracle sign")
    {
        mpi::Signature::MLDSA65_Ed25519 { mldsa, .. } => {
            ExternalMlDsa65SignatureBytes::new(mldsa.to_vec())
        }
        _ => panic!("expected composite signature"),
    }
}

fn sha512_digest() -> Vec<u8> {
    vec![0x42u8; 64]
}

#[test]
fn signs_and_self_verifies_composite_signature() {
    let fixture = composite_fixture();
    let keypair = fixture.keypair.clone();
    let mut signer = ExternalCompositeSigner::new(
        fixture.public_key.clone(),
        &fixture.classical_eddsa_secret,
        move |digest| Ok(oracle_mldsa_half(&keypair, digest)),
    )
    .expect("signer builds");

    let digest = sha512_digest();
    let signature = signer
        .sign(HashAlgorithm::SHA512, &digest)
        .expect("composite sign");
    fixture
        .public_key
        .verify(&signature, HashAlgorithm::SHA512, &digest)
        .expect("independent verify");
}

#[test]
fn rejects_non_composite_public_key() {
    let key: Key<key::SecretParts, key::PrimaryRole> =
        key::Key6::generate_ecc(true, openpgp::types::Curve::NistP256)
            .expect("p256 key")
            .into();
    let public_key = key.parts_as_public().role_as_unspecified().clone();
    let result = ExternalCompositeSigner::new(public_key, &[7u8; 32], |_digest| {
        panic!("must not be called")
    });
    assert!(result.is_err());
}

#[test]
fn rejects_classical_component_not_matching_certificate() {
    let fixture = composite_fixture();
    let error = ExternalCompositeSigner::new(fixture.public_key.clone(), &[7u8; 32], |_digest| {
        panic!("must not be called")
    })
    .err()
    .expect("mismatched classical component must fail");
    assert!(error.to_string().contains("does not match the certificate"));
}

#[test]
fn rejects_invalid_digest_length_before_calling_out() {
    let fixture = composite_fixture();
    let mut signer = ExternalCompositeSigner::new(
        fixture.public_key,
        &fixture.classical_eddsa_secret,
        |_digest| -> Result<ExternalMlDsa65SignatureBytes, ExternalCompositeSignerError> {
            panic!("must not be called")
        },
    )
    .expect("signer builds");
    let error = signer
        .sign(HashAlgorithm::SHA512, &[0u8; 32])
        .expect_err("length mismatch must fail");
    assert!(error.to_string().contains("invalid digest length"));
}

#[test]
fn rejects_malformed_external_signature_shapes() {
    let fixture = composite_fixture();

    let mut short_signer = ExternalCompositeSigner::new(
        fixture.public_key.clone(),
        &fixture.classical_eddsa_secret,
        |_digest| Ok(ExternalMlDsa65SignatureBytes::new(vec![1u8; 100])),
    )
    .expect("signer builds");
    let error = short_signer
        .sign(HashAlgorithm::SHA512, &sha512_digest())
        .expect_err("short signature must fail");
    assert!(error.to_string().contains("invalid signature shape"));

    let mut zero_signer = ExternalCompositeSigner::new(
        fixture.public_key.clone(),
        &fixture.classical_eddsa_secret,
        |_digest| {
            Ok(ExternalMlDsa65SignatureBytes::new(vec![
                0u8;
                MLDSA65_SIGNATURE_LENGTH
            ]))
        },
    )
    .expect("signer builds");
    let error = zero_signer
        .sign(HashAlgorithm::SHA512, &sha512_digest())
        .expect_err("all-zero signature must fail");
    assert!(error.to_string().contains("all-zero signature"));
}

#[test]
fn rejects_corrupted_external_signature_via_self_verify() {
    let fixture = composite_fixture();
    let keypair = fixture.keypair.clone();
    let mut signer = ExternalCompositeSigner::new(
        fixture.public_key,
        &fixture.classical_eddsa_secret,
        move |digest| {
            let mut signature = oracle_mldsa_half(&keypair, digest);
            signature.raw[17] ^= 0x01;
            Ok(signature)
        },
    )
    .expect("signer builds");
    let error = signer
        .sign(HashAlgorithm::SHA512, &sha512_digest())
        .expect_err("corrupted signature must fail");
    assert!(error.to_string().contains("unverified signature"));
}

#[test]
fn propagates_external_failure_and_cancellation() {
    let fixture = composite_fixture();

    let mut failing = ExternalCompositeSigner::new(
        fixture.public_key.clone(),
        &fixture.classical_eddsa_secret,
        |_digest| Err(ExternalCompositeSignerError::external_operation_failed()),
    )
    .expect("signer builds");
    let error = failing
        .sign(HashAlgorithm::SHA512, &sha512_digest())
        .expect_err("failure must propagate");
    assert!(error.chain().any(|cause| cause
        .downcast_ref::<ExternalCompositeSignerError>()
        .is_some()));

    let mut cancelled = ExternalCompositeSigner::new(
        fixture.public_key,
        &fixture.classical_eddsa_secret,
        |_digest| Err(ExternalCompositeSignerError::OperationCancelled),
    )
    .expect("signer builds");
    let error = cancelled
        .sign(HashAlgorithm::SHA512, &sha512_digest())
        .expect_err("cancellation must propagate");
    assert!(matches!(
        error
            .chain()
            .find_map(|cause| cause.downcast_ref::<ExternalCompositeSignerError>()),
        Some(ExternalCompositeSignerError::OperationCancelled)
    ));
}
