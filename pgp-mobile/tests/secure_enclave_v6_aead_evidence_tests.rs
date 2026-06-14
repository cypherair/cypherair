//! Secure Enclave custody v6 RFC 9580 / AEAD evidence (Phase 8, issue #501).
//!
//! Validates RFC 9580 / SEIPDv2 AEAD-OCB correctness for the device-bound *modern*
//! (v6) family through the PRODUCTION external key-agreement decrypt seam, driven by
//! the shared software-P256 stand-in. v6 carries no GnuPG interop gate (GnuPG does
//! not support v6 keys); the documented gpg-rejection and the third-party-AEAD
//! interop limitation are recorded in
//! docs/SECURE_ENCLAVE_CUSTODY.md §8. These tests need no gpg and run in
//! the default lane.

mod common;

use common::secure_enclave::SoftwareP256Material;
use pgp_mobile::keys::SecureEnclaveCertificateVersion;
use pgp_mobile::signature_details::SignatureVerificationState;
use pgp_mobile::{encrypt, PgpEngine};

/// Emit a sanitized one-line v6 evidence record (scenario label only) for harvesting
/// into the Phase 8 evidence matrix.
fn record_evidence(scenario: &str) {
    println!("SE-V6-AEAD-EVIDENCE scenario={scenario} version=v6 outcome=passed");
}

fn build_v6_material() -> SoftwareP256Material {
    SoftwareP256Material::generate(SecureEnclaveCertificateVersion::V6, Some(3600))
        .expect("software SE v6 material should build")
}

/// SEIPDv2 / AEAD-OCB round-trip: encrypt to the SE v6 certificate and decrypt
/// through the production key-agreement seam. Asserts the RFC 9580 packet shape
/// (PKESK v6 + SEIPDv2), not the v4 SEIPDv1 shape.
#[test]
fn test_se_v6_seipdv2_aead_roundtrip_through_production_seam() {
    let material = build_v6_material();
    let plaintext = b"Secure Enclave custody v6 RFC 9580 AEAD round-trip";

    let ciphertext =
        encrypt::encrypt_binary(plaintext, &[material.public_key_data.clone()], None, None)
            .expect("encryption to the SE v6 certificate should succeed");

    assert_eq!(
        common::detect_message_format(&ciphertext),
        (false, true),
        "the SE v6 message must be SEIPDv2/AEAD, not SEIPDv1"
    );
    assert_eq!(
        common::detect_pkesk_versions(&ciphertext),
        vec![6],
        "the SE v6 message must use a PKESK v6 packet"
    );

    let engine = PgpEngine::new();
    let result = engine
        .decrypt_detailed_with_external_p256_key_agreement(
            ciphertext,
            material.public_key_data.clone(),
            material.key_agreement_subkey_fingerprint.clone(),
            material.key_agreement_provider(),
            Vec::new(),
        )
        .expect("production SE custody boundary should decrypt the v6 message");
    assert_eq!(result.plaintext, plaintext);
    assert_eq!(result.summary_state, SignatureVerificationState::NotSigned);
    record_evidence("seipdv2AeadRoundtripThroughProductionSeam");
}

/// AEAD tamper hard-fail: a tampered SEIPDv2 ciphertext must fail closed in the
/// production seam, with no plaintext released.
#[test]
fn test_se_v6_aead_tamper_fails_closed_in_production_seam() {
    let material = build_v6_material();
    let plaintext = b"Secure Enclave custody v6 AEAD tamper case";

    let ciphertext =
        encrypt::encrypt_binary(plaintext, &[material.public_key_data.clone()], None, None)
            .expect("encryption to the SE v6 certificate should succeed");
    let tampered = common::tamper_near_payload_tail(&ciphertext);

    let engine = PgpEngine::new();
    let result = engine.decrypt_detailed_with_external_p256_key_agreement(
        tampered,
        material.public_key_data.clone(),
        material.key_agreement_subkey_fingerprint.clone(),
        material.key_agreement_provider(),
        Vec::new(),
    );
    assert!(
        result.is_err(),
        "a tampered v6 AEAD ciphertext must fail closed in the production seam"
    );
    record_evidence("aeadTamperFailsClosed");
}

/// A v6 signed+encrypted message decrypts AND verifies through the production seam
/// (the SE external signer signs the v6 message; the SE public certificate verifies).
#[test]
fn test_se_v6_signed_encrypted_decrypts_and_verifies_through_production_seam() {
    let material = build_v6_material();
    let plaintext = b"Secure Enclave custody v6 signed and encrypted";

    let ciphertext = encrypt::encrypt_with_external_p256_signer(
        plaintext,
        &[material.public_key_data.clone()],
        &material.public_key_data,
        &material.signing_key_fingerprint,
        material.signing_provider(),
        None,
    )
    .expect("SE v6 sign-plus-encrypt should succeed");
    assert_eq!(
        common::detect_message_format(&ciphertext),
        (false, true),
        "the SE v6 sign-plus-encrypt output must be SEIPDv2/AEAD"
    );

    let engine = PgpEngine::new();
    let result = engine
        .decrypt_detailed_with_external_p256_key_agreement(
            ciphertext,
            material.public_key_data.clone(),
            material.key_agreement_subkey_fingerprint.clone(),
            material.key_agreement_provider(),
            vec![material.public_key_data.clone()],
        )
        .expect("production SE custody boundary should decrypt the v6 signed message");
    assert_eq!(result.plaintext, plaintext);
    assert_eq!(
        result.summary_state,
        SignatureVerificationState::Verified,
        "the SE v6 signature should verify through the production boundary"
    );
    record_evidence("signedEncryptedDecryptsAndVerifies");
}
