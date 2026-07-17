//! Secure Enclave custody v4 GnuPG interop evidence.
//!
//! Drives the PRODUCTION Secure Enclave seams (certificate construction, external
//! signer, external key-agreement decrypt) with the shared software-P256 stand-in
//! and exercises real interop against the `gpg` binary for the device-bound
//! *compatible* (v4) family. Because the software lane holds both secret halves, it
//! imports a gpg-importable TSK so GnuPG can sign and decrypt as the SE certificate —
//! giving full bidirectional evidence in CI with no hardware.
//!
//! Skip behavior: these tests skip when `gpg` is absent, unless
//! `CYPHERAIR_REQUIRE_GPG=1` (the mandatory CI interop lane), in which case a missing
//! gpg fails the lane. See `common::gnupg::require_gpg_or_skip`.

mod common;

use common::gnupg::{
    assert_gpg_status_good_signature, gpg_cmd, gpg_import_key, require_gpg_or_skip, setup_gpg_home,
};
use common::secure_enclave::SoftwareP256Material;
use pgp_mobile::keys::SecureEnclaveCertificateVersion;
use pgp_mobile::signature_details::SignatureVerificationState;
use pgp_mobile::{armor, encrypt, sign, PgpEngine};
use tempfile::TempDir;

/// Emit a sanitized one-line interop evidence record (scenario label only — never
/// key material, plaintext, or fingerprints) for harvesting into the Secure Enclave
/// custody evidence matrix.
fn record_evidence(scenario: &str) {
    println!("SE-GNUPG-INTEROP-EVIDENCE scenario={scenario} version=v4 outcome=passed");
}

fn build_v4_material() -> SoftwareP256Material {
    SoftwareP256Material::generate(SecureEnclaveCertificateVersion::V4, Some(3600))
        .expect("software SE v4 material should build")
}

fn write(gnupghome: &TempDir, name: &str, data: &[u8]) -> std::path::PathBuf {
    let path = gnupghome.path().join(name);
    std::fs::write(&path, data).expect("temp file should write");
    path
}

/// gpg --encrypt (binary) to the SE certificate's primary fingerprint.
fn gpg_encrypt_to_se(
    gpg: &std::path::PathBuf,
    gnupghome: &TempDir,
    recipient_fingerprint: &str,
    plaintext: &[u8],
) -> Vec<u8> {
    let pt_file = write(gnupghome, "plaintext.txt", plaintext);
    let ct_file = gnupghome.path().join("ciphertext.gpg");
    let output = gpg_cmd(gpg, gnupghome)
        .arg("--encrypt")
        .arg("--recipient")
        .arg(recipient_fingerprint)
        .arg("--output")
        .arg(&ct_file)
        .arg(&pt_file)
        .output()
        .expect("gpg --encrypt should run");
    assert!(
        output.status.success(),
        "gpg --encrypt to the SE certificate should succeed.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    std::fs::read(&ct_file).expect("gpg ciphertext should read")
}

/// (1) GnuPG imports the SE custody public certificate as a P-256 ECDSA primary +
/// ECDH subkey.
#[test]
fn test_se_v4_gpg_imports_public_certificate() {
    let Some(gpg) = require_gpg_or_skip() else {
        return;
    };
    let material = build_v4_material();
    let gnupghome = setup_gpg_home();

    let armored = armor::armor_public_key(&material.public_key_data).expect("armor should succeed");
    gpg_import_key(&gpg, &gnupghome, &armored);

    let listing = gpg_cmd(&gpg, &gnupghome)
        .arg("--list-keys")
        .arg("--with-colons")
        .arg(&material.signing_key_fingerprint)
        .output()
        .expect("gpg --list-keys should run");
    assert!(listing.status.success());
    let colons = String::from_utf8_lossy(&listing.stdout);

    assert!(
        colons.contains("nistp256"),
        "imported SE certificate should be P-256.\n{colons}"
    );
    assert!(
        colons
            .to_lowercase()
            .contains(&material.signing_key_fingerprint),
        "the SE primary fingerprint should be listed"
    );
    // Public-key algorithm fields: 19 = ECDSA (primary), 18 = ECDH (subkey).
    assert!(
        colons.lines().any(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            fields.first() == Some(&"pub") && fields.get(3) == Some(&"19")
        }),
        "primary key must be ECDSA (algo 19).\n{colons}"
    );
    assert!(
        colons.lines().any(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            fields.first() == Some(&"sub") && fields.get(3) == Some(&"18")
        }),
        "key-agreement subkey must be ECDH (algo 18).\n{colons}"
    );
    record_evidence("gpgImportsSeCertificate");
}

/// (2) GnuPG verifies a signature produced through the production external signer.
#[test]
fn test_se_v4_gpg_verifies_se_generated_signature() {
    let Some(gpg) = require_gpg_or_skip() else {
        return;
    };
    let material = build_v4_material();
    let gnupghome = setup_gpg_home();
    let armored = armor::armor_public_key(&material.public_key_data).expect("armor should succeed");
    gpg_import_key(&gpg, &gnupghome, &armored);

    let message = b"Secure Enclave custody signature for GnuPG verification";
    let signed = sign::sign_cleartext_with_external_p256_signer(
        message,
        &material.public_key_data,
        &material.signing_key_fingerprint,
        material.signing_provider(),
    )
    .expect("SE cleartext signing should succeed");
    let signed_file = write(&gnupghome, "se_signed.asc", &signed);

    let output = gpg_cmd(&gpg, &gnupghome)
        .arg("--status-fd")
        .arg("2")
        .arg("--verify")
        .arg(&signed_file)
        .output()
        .expect("gpg --verify should run");
    assert!(
        output.status.success(),
        "gpg should verify the SE-generated signature.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert_gpg_status_good_signature(&output.stderr);
    record_evidence("gpgVerifiesSeSignature");
}

/// (3) GnuPG encrypts to the SE certificate; the production key-agreement seam
/// decrypts it. Asserts the GnuPG output is PKESK v3 ECDH + SEIPDv1/MDC, not AEAD.
#[test]
fn test_se_v4_gpg_encrypt_to_se_decrypts_through_production_seam() {
    let Some(gpg) = require_gpg_or_skip() else {
        return;
    };
    let material = build_v4_material();
    let gnupghome = setup_gpg_home();
    let armored = armor::armor_public_key(&material.public_key_data).expect("armor should succeed");
    gpg_import_key(&gpg, &gnupghome, &armored);

    let plaintext = b"GnuPG to Secure Enclave custody v4";
    let ciphertext = gpg_encrypt_to_se(
        &gpg,
        &gnupghome,
        &material.signing_key_fingerprint,
        plaintext,
    );

    // Packet shape: exactly one PKESK v3 (classic ECDH), SEIPDv1/MDC, never SEIPDv2/AEAD.
    assert_eq!(
        common::detect_pkesk_versions(&ciphertext),
        vec![3],
        "GnuPG must emit PKESK v3 ECDH for the SE-compatible v4 certificate"
    );
    assert_eq!(
        common::detect_message_format(&ciphertext),
        (true, false),
        "GnuPG must emit SEIPDv1/MDC, not an AEAD (SEIPDv2) packet shape"
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
        .expect("production SE custody boundary should decrypt the GnuPG message");
    assert_eq!(result.plaintext, plaintext);
    assert_eq!(result.summary_state, SignatureVerificationState::NotSigned);
    record_evidence("gpgEncryptToSe_productionSeamDecrypts_pkeskV3_seipdV1Mdc");
}

/// (4) A GnuPG-originated signed+encrypted message decrypts AND verifies through the
/// production SE custody boundary. GnuPG holds the SE secret (software TSK) so it can
/// sign as the SE primary and encrypt to the SE certificate.
#[test]
fn test_se_v4_gpg_signed_encrypted_decrypts_and_verifies_through_production_seam() {
    let Some(gpg) = require_gpg_or_skip() else {
        return;
    };
    let material = build_v4_material();
    let gnupghome = setup_gpg_home();
    let tsk = material
        .export_gpg_importable_tsk()
        .expect("gpg-importable TSK export should succeed");
    gpg_import_key(&gpg, &gnupghome, &tsk);

    let plaintext = b"GnuPG signed and encrypted to Secure Enclave custody v4";
    let pt_file = write(&gnupghome, "plaintext.txt", plaintext);
    let ct_file = gnupghome.path().join("signed_encrypted.gpg");
    let output = gpg_cmd(&gpg, &gnupghome)
        .arg("--sign")
        .arg("--encrypt")
        .arg("--local-user")
        .arg(&material.signing_key_fingerprint)
        .arg("--recipient")
        .arg(&material.signing_key_fingerprint)
        .arg("--output")
        .arg(&ct_file)
        .arg(&pt_file)
        .output()
        .expect("gpg --sign --encrypt should run");
    assert!(
        output.status.success(),
        "gpg --sign --encrypt should succeed.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let ciphertext = std::fs::read(&ct_file).expect("gpg ciphertext should read");

    let engine = PgpEngine::new();
    let result = engine
        .decrypt_detailed_with_external_p256_key_agreement(
            ciphertext,
            material.public_key_data.clone(),
            material.key_agreement_subkey_fingerprint.clone(),
            material.key_agreement_provider(),
            vec![material.public_key_data.clone()],
        )
        .expect("production SE custody boundary should decrypt the GnuPG-originated message");
    assert_eq!(result.plaintext, plaintext);
    assert_eq!(
        result.summary_state,
        SignatureVerificationState::Verified,
        "the GnuPG-originated signature should verify through the production boundary"
    );
    record_evidence("gpgSignedEncrypted_productionSeamDecryptsAndVerifies");
}

/// (5) Bidirectional sign+encrypt. Direction A: the SE external signer signs and
/// encrypts to the SE certificate; GnuPG decrypts and verifies the SE signature.
/// Direction B (GnuPG-originated → production decrypt+verify) is covered by
/// `test_se_v4_gpg_signed_encrypted_decrypts_and_verifies_through_production_seam`.
#[test]
fn test_se_v4_bidirectional_sign_plus_encrypt() {
    let Some(gpg) = require_gpg_or_skip() else {
        return;
    };
    let material = build_v4_material();
    let gnupghome = setup_gpg_home();
    let tsk = material
        .export_gpg_importable_tsk()
        .expect("gpg-importable TSK export should succeed");
    gpg_import_key(&gpg, &gnupghome, &tsk);

    let plaintext = b"Secure Enclave custody to GnuPG v4, signed and encrypted";
    let ciphertext = encrypt::encrypt_with_external_p256_signer(
        plaintext,
        &[material.public_key_data.clone()],
        &material.public_key_data,
        &material.signing_key_fingerprint,
        material.signing_provider(),
        None,
    )
    .expect("SE sign-plus-encrypt should succeed");
    assert_eq!(
        common::detect_message_format(&ciphertext),
        (true, false),
        "the SE v4 sign-plus-encrypt output should be SEIPDv1/MDC"
    );

    let ct_file = write(&gnupghome, "se_signed_encrypted.gpg", &ciphertext);
    let output = gpg_cmd(&gpg, &gnupghome)
        .arg("--status-fd")
        .arg("2")
        .arg("--decrypt")
        .arg(&ct_file)
        .output()
        .expect("gpg --decrypt should run");
    assert!(
        output.status.success(),
        "gpg should decrypt the SE-originated message.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(output.stdout, plaintext);
    assert_gpg_status_good_signature(&output.stderr);
    record_evidence("bidirectionalSignPlusEncrypt");
}

/// (6) A tampered GnuPG-originated ciphertext fails closed in the production seam,
/// with no plaintext released (the SEIPDv1/MDC hard-fail contract).
#[test]
fn test_se_v4_tampered_gpg_ciphertext_fails_closed_in_production_seam() {
    let Some(gpg) = require_gpg_or_skip() else {
        return;
    };
    let material = build_v4_material();
    let gnupghome = setup_gpg_home();
    let armored = armor::armor_public_key(&material.public_key_data).expect("armor should succeed");
    gpg_import_key(&gpg, &gnupghome, &armored);

    let plaintext = b"GnuPG to Secure Enclave custody v4 tamper case";
    let ciphertext = gpg_encrypt_to_se(
        &gpg,
        &gnupghome,
        &material.signing_key_fingerprint,
        plaintext,
    );
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
        "a tampered GnuPG ciphertext must fail closed in the production seam"
    );
    record_evidence("tamperedGpgCiphertextFailsClosed");
}
