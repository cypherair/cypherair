use sequoia_openpgp as openpgp;

use openpgp::cert::{CertBuilder, CipherSuite};
use openpgp::crypto::{mpi, Decryptor};
use openpgp::packet::key::SecretKeyMaterial;
use openpgp::packet::{key, Key};

use super::core::{
    MLKEM1024_CIPHERTEXT_LENGTH, MLKEM1024_PUBLIC_KEY_LENGTH, MLKEM768_CIPHERTEXT_LENGTH,
    MLKEM768_PUBLIC_KEY_LENGTH,
};
use super::{
    ExternalCompositeDecryptor, ExternalCompositeDecryptorError, ExternalCompositeHighDecryptor,
    ExternalMlKem1024Share, ExternalMlKem768Share,
};

struct CompositeKaFixture {
    public_key: Key<key::PublicParts, key::UnspecifiedRole>,
    classical_ecdh_secret: Vec<u8>,
}

fn composite_ka_fixture() -> CompositeKaFixture {
    let (cert, _rev) = CertBuilder::new()
        .set_cipher_suite(CipherSuite::MLDSA65_Ed25519)
        .set_profile(openpgp::Profile::RFC9580)
        .expect("set RFC 9580 profile")
        .add_userid("Composite Decryptor Unit <composite-decryptor@unit.test>")
        .add_transport_encryption_subkey()
        .generate()
        .expect("generate software composite cert");
    let subkey = cert
        .keys()
        .subkeys()
        .next()
        .expect("encryption subkey")
        .key()
        .clone();
    let public_key = subkey.parts_as_public().role_as_unspecified().clone();
    let classical_ecdh_secret = match subkey.optional_secret() {
        Some(SecretKeyMaterial::Unencrypted(secret)) => secret.map(|mpis| match mpis {
            mpi::SecretKeyMaterial::MLKEM768_X25519 { ecdh, .. } => ecdh.to_vec(),
            _ => panic!("expected composite KA secret material"),
        }),
        _ => panic!("expected unencrypted secret material"),
    };
    CompositeKaFixture {
        public_key,
        classical_ecdh_secret,
    }
}

fn non_composite_ciphertext() -> mpi::Ciphertext {
    mpi::Ciphertext::ECDH {
        e: mpi::MPI::new(&[0x04u8; 65]),
        key: vec![0u8; 48].into_boxed_slice(),
    }
}

fn composite_ciphertext() -> mpi::Ciphertext {
    mpi::Ciphertext::MLKEM768_X25519 {
        ecdh: Box::new([9u8; 32]),
        mlkem: Box::new([7u8; MLKEM768_CIPHERTEXT_LENGTH]),
        esk: vec![0u8; 40].into_boxed_slice(),
    }
}

#[test]
fn rejects_non_composite_public_key() {
    let key: Key<key::SecretParts, key::SubordinateRole> =
        key::Key6::generate_ecc(false, openpgp::types::Curve::NistP256)
            .expect("p256 key")
            .into();
    let public_key = key.parts_as_public().role_as_unspecified().clone();
    let result = ExternalCompositeDecryptor::new(public_key, &[7u8; 32], |_request| {
        panic!("must not be called")
    });
    assert!(result.is_err());
}

#[test]
fn rejects_classical_component_not_matching_certificate() {
    let fixture = composite_ka_fixture();
    let error = ExternalCompositeDecryptor::new(fixture.public_key, &[7u8; 32], |_request| {
        panic!("must not be called")
    })
    .err()
    .expect("mismatched classical component must fail");
    assert!(error.to_string().contains("does not match the certificate"));
}

#[test]
fn non_composite_ciphertext_records_skippable_invalid_request() {
    let fixture = composite_ka_fixture();
    let mut decryptor = ExternalCompositeDecryptor::new(
        fixture.public_key,
        &fixture.classical_ecdh_secret,
        |_request| -> Result<ExternalMlKem768Share, ExternalCompositeDecryptorError> {
            panic!("must not be called")
        },
    )
    .expect("decryptor builds");

    assert!(decryptor
        .decrypt(&non_composite_ciphertext(), None)
        .is_err());
    let error = decryptor.take_last_error().expect("error recorded");
    assert!(matches!(
        error,
        ExternalCompositeDecryptorError::InvalidRequest(_)
    ));
    assert!(!error.hard_aborts_anonymous_recipient());
}

#[test]
fn request_carries_recipient_mlkem_public_and_ciphertext() {
    let fixture = composite_ka_fixture();
    let expected_mlkem_public = match fixture.public_key.mpis() {
        mpi::PublicKey::MLKEM768_X25519 { mlkem, .. } => mlkem.to_vec(),
        _ => panic!("expected composite public key"),
    };
    let mut decryptor = ExternalCompositeDecryptor::new(
        fixture.public_key.clone(),
        &fixture.classical_ecdh_secret,
        move |request| {
            assert_eq!(
                request.recipient_mlkem_public_key.len(),
                MLKEM768_PUBLIC_KEY_LENGTH
            );
            assert_eq!(request.recipient_mlkem_public_key, expected_mlkem_public);
            assert_eq!(
                request.mlkem_ciphertext,
                vec![7u8; MLKEM768_CIPHERTEXT_LENGTH]
            );
            Err(ExternalCompositeDecryptorError::OperationCancelled)
        },
    )
    .expect("decryptor builds");

    assert!(decryptor.decrypt(&composite_ciphertext(), None).is_err());
    let error = decryptor.take_last_error().expect("error recorded");
    assert!(matches!(
        error,
        ExternalCompositeDecryptorError::OperationCancelled
    ));
    assert!(error.hard_aborts_anonymous_recipient());
}

#[test]
fn malformed_key_shares_record_hard_failures() {
    let fixture = composite_ka_fixture();

    let mut short_share = ExternalCompositeDecryptor::new(
        fixture.public_key.clone(),
        &fixture.classical_ecdh_secret,
        |_request| Ok(ExternalMlKem768Share::new(vec![1u8; 16])),
    )
    .expect("decryptor builds");
    assert!(short_share.decrypt(&composite_ciphertext(), None).is_err());
    let error = short_share.take_last_error().expect("error recorded");
    assert!(matches!(
        error,
        ExternalCompositeDecryptorError::InvalidResponse(_)
    ));
    assert!(error.hard_aborts_anonymous_recipient());

    let mut zero_share = ExternalCompositeDecryptor::new(
        fixture.public_key.clone(),
        &fixture.classical_ecdh_secret,
        |_request| Ok(ExternalMlKem768Share::new(vec![0u8; 32])),
    )
    .expect("decryptor builds");
    assert!(zero_share.decrypt(&composite_ciphertext(), None).is_err());
    let error = zero_share.take_last_error().expect("error recorded");
    assert!(matches!(
        error,
        ExternalCompositeDecryptorError::InvalidResponse(_)
    ));
}

#[test]
fn wrong_but_valid_shape_share_fails_session_key_unwrap_without_recording() {
    let fixture = composite_ka_fixture();
    let mut decryptor = ExternalCompositeDecryptor::new(
        fixture.public_key,
        &fixture.classical_ecdh_secret,
        |_request| Ok(ExternalMlKem768Share::new(vec![0xA5u8; 32])),
    )
    .expect("decryptor builds");

    // A well-formed but wrong key share must fail closed at AES key unwrap.
    // Combiner/unwrap failures are returned raw (native parity), so nothing
    // is recorded for the helper loop.
    assert!(decryptor.decrypt(&composite_ciphertext(), None).is_err());
    assert!(decryptor.take_last_error().is_none());
}

#[test]
fn classical_component_failure_is_skippable_for_anonymous_recipient() {
    // A crafted all-zero / low-order X25519 peer ephemeral makes the classical
    // key agreement fail before the external ML-KEM decapsulation runs. For a
    // wildcard / hidden-recipient PKESK this failure is attacker-inducible and
    // must be a skippable non-match, not a hard abort that would deny an
    // otherwise-decryptable multi-recipient message.
    let fixture = composite_ka_fixture();
    let mut decryptor = ExternalCompositeDecryptor::new(
        fixture.public_key,
        &fixture.classical_ecdh_secret,
        |_request| -> Result<ExternalMlKem768Share, ExternalCompositeDecryptorError> {
            panic!("must not reach external decapsulation when the classical half fails")
        },
    )
    .expect("decryptor builds");

    let ciphertext = mpi::Ciphertext::MLKEM768_X25519 {
        ecdh: Box::new([0u8; 32]),
        mlkem: Box::new([7u8; MLKEM768_CIPHERTEXT_LENGTH]),
        esk: vec![0u8; 40].into_boxed_slice(),
    };
    assert!(decryptor.decrypt(&ciphertext, None).is_err());
    let error = decryptor.take_last_error().expect("error recorded");
    assert!(matches!(
        error,
        ExternalCompositeDecryptorError::ClassicalComponentFailure(_)
    ));
    assert!(!error.hard_aborts_anonymous_recipient());
}

// ── Device-Bound Post-Quantum · High (ML-KEM-1024 + X448) decryptor ──
// Same fail-closed coverage as the 65/768 decryptor above, for the High tier.

fn composite_high_ka_fixture() -> CompositeKaFixture {
    let (cert, _rev) = CertBuilder::new()
        .set_cipher_suite(CipherSuite::MLDSA87_Ed448)
        .set_profile(openpgp::Profile::RFC9580)
        .expect("set RFC 9580 profile")
        .add_userid("Composite High Decryptor Unit <composite-high-decryptor@unit.test>")
        .add_transport_encryption_subkey()
        .generate()
        .expect("generate software composite high cert");
    let subkey = cert
        .keys()
        .subkeys()
        .next()
        .expect("encryption subkey")
        .key()
        .clone();
    let public_key = subkey.parts_as_public().role_as_unspecified().clone();
    let classical_ecdh_secret = match subkey.optional_secret() {
        Some(SecretKeyMaterial::Unencrypted(secret)) => secret.map(|mpis| match mpis {
            mpi::SecretKeyMaterial::MLKEM1024_X448 { ecdh, .. } => ecdh.to_vec(),
            _ => panic!("expected composite high KA secret material"),
        }),
        _ => panic!("expected unencrypted secret material"),
    };
    CompositeKaFixture {
        public_key,
        classical_ecdh_secret,
    }
}

fn composite_high_ciphertext() -> mpi::Ciphertext {
    mpi::Ciphertext::MLKEM1024_X448 {
        ecdh: Box::new([9u8; 56]),
        mlkem: Box::new([7u8; MLKEM1024_CIPHERTEXT_LENGTH]),
        esk: vec![0u8; 40].into_boxed_slice(),
    }
}

#[test]
fn high_rejects_non_composite_public_key() {
    let key: Key<key::SecretParts, key::SubordinateRole> =
        key::Key6::generate_ecc(false, openpgp::types::Curve::NistP256)
            .expect("p256 key")
            .into();
    let public_key = key.parts_as_public().role_as_unspecified().clone();
    let result = ExternalCompositeHighDecryptor::new(public_key, &[7u8; 56], |_request| {
        panic!("must not be called")
    });
    assert!(result.is_err());
}

#[test]
fn high_rejects_classical_component_not_matching_certificate() {
    let fixture = composite_high_ka_fixture();
    let error = ExternalCompositeHighDecryptor::new(fixture.public_key, &[7u8; 56], |_request| {
        panic!("must not be called")
    })
    .err()
    .expect("mismatched classical component must fail");
    assert!(error.to_string().contains("does not match the certificate"));
}

#[test]
fn high_non_composite_ciphertext_records_skippable_invalid_request() {
    let fixture = composite_high_ka_fixture();
    let mut decryptor = ExternalCompositeHighDecryptor::new(
        fixture.public_key,
        &fixture.classical_ecdh_secret,
        |_request| -> Result<ExternalMlKem1024Share, ExternalCompositeDecryptorError> {
            panic!("must not be called")
        },
    )
    .expect("decryptor builds");

    assert!(decryptor
        .decrypt(&non_composite_ciphertext(), None)
        .is_err());
    let error = decryptor.take_last_error().expect("error recorded");
    assert!(matches!(
        error,
        ExternalCompositeDecryptorError::InvalidRequest(_)
    ));
    assert!(!error.hard_aborts_anonymous_recipient());
}

#[test]
fn high_request_carries_recipient_mlkem_public_and_ciphertext() {
    let fixture = composite_high_ka_fixture();
    let expected_mlkem_public = match fixture.public_key.mpis() {
        mpi::PublicKey::MLKEM1024_X448 { mlkem, .. } => mlkem.to_vec(),
        _ => panic!("expected composite high public key"),
    };
    let mut decryptor = ExternalCompositeHighDecryptor::new(
        fixture.public_key.clone(),
        &fixture.classical_ecdh_secret,
        move |request| {
            assert_eq!(
                request.recipient_mlkem_public_key.len(),
                MLKEM1024_PUBLIC_KEY_LENGTH
            );
            assert_eq!(request.recipient_mlkem_public_key, expected_mlkem_public);
            assert_eq!(
                request.mlkem_ciphertext,
                vec![7u8; MLKEM1024_CIPHERTEXT_LENGTH]
            );
            Err(ExternalCompositeDecryptorError::OperationCancelled)
        },
    )
    .expect("decryptor builds");

    assert!(decryptor
        .decrypt(&composite_high_ciphertext(), None)
        .is_err());
    let error = decryptor.take_last_error().expect("error recorded");
    assert!(matches!(
        error,
        ExternalCompositeDecryptorError::OperationCancelled
    ));
    assert!(error.hard_aborts_anonymous_recipient());
}

#[test]
fn high_malformed_key_shares_record_hard_failures() {
    let fixture = composite_high_ka_fixture();

    let mut short_share = ExternalCompositeHighDecryptor::new(
        fixture.public_key.clone(),
        &fixture.classical_ecdh_secret,
        |_request| Ok(ExternalMlKem1024Share::new(vec![1u8; 16])),
    )
    .expect("decryptor builds");
    assert!(short_share
        .decrypt(&composite_high_ciphertext(), None)
        .is_err());
    let error = short_share.take_last_error().expect("error recorded");
    assert!(matches!(
        error,
        ExternalCompositeDecryptorError::InvalidResponse(_)
    ));
    assert!(error.hard_aborts_anonymous_recipient());

    let mut zero_share = ExternalCompositeHighDecryptor::new(
        fixture.public_key.clone(),
        &fixture.classical_ecdh_secret,
        |_request| Ok(ExternalMlKem1024Share::new(vec![0u8; 32])),
    )
    .expect("decryptor builds");
    assert!(zero_share
        .decrypt(&composite_high_ciphertext(), None)
        .is_err());
    let error = zero_share.take_last_error().expect("error recorded");
    assert!(matches!(
        error,
        ExternalCompositeDecryptorError::InvalidResponse(_)
    ));
}

#[test]
fn high_wrong_but_valid_shape_share_fails_session_key_unwrap_without_recording() {
    let fixture = composite_high_ka_fixture();
    let mut decryptor = ExternalCompositeHighDecryptor::new(
        fixture.public_key,
        &fixture.classical_ecdh_secret,
        |_request| Ok(ExternalMlKem1024Share::new(vec![0xA5u8; 32])),
    )
    .expect("decryptor builds");

    // A well-formed but wrong key share must fail closed at AES key unwrap;
    // combiner/unwrap failures are returned raw, so nothing is recorded.
    assert!(decryptor
        .decrypt(&composite_high_ciphertext(), None)
        .is_err());
    assert!(decryptor.take_last_error().is_none());
}

#[test]
fn high_classical_component_failure_is_skippable_for_anonymous_recipient() {
    // · High analog of the 768-tier anonymous-recipient classical-failure guard:
    // an all-zero / low-order X448 peer ephemeral fails the
    // classical half and must be a skippable non-match for a wildcard PKESK.
    let fixture = composite_high_ka_fixture();
    let mut decryptor = ExternalCompositeHighDecryptor::new(
        fixture.public_key,
        &fixture.classical_ecdh_secret,
        |_request| -> Result<ExternalMlKem1024Share, ExternalCompositeDecryptorError> {
            panic!("must not reach external decapsulation when the classical half fails")
        },
    )
    .expect("decryptor builds");

    let ciphertext = mpi::Ciphertext::MLKEM1024_X448 {
        ecdh: Box::new([0u8; 56]),
        mlkem: Box::new([7u8; MLKEM1024_CIPHERTEXT_LENGTH]),
        esk: vec![0u8; 40].into_boxed_slice(),
    };
    assert!(decryptor.decrypt(&ciphertext, None).is_err());
    let error = decryptor.take_last_error().expect("error recorded");
    assert!(matches!(
        error,
        ExternalCompositeDecryptorError::ClassicalComponentFailure(_)
    ));
    assert!(!error.hard_aborts_anonymous_recipient());
}
