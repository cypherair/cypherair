//! Rule E21 with GnuPG: `gpg` reads what the Legacy family writes, and the
//! engine reads what `gpg` writes. The fixture tests need no `gpg`; the live
//! ones skip without it unless `CYPHERAIR_REQUIRE_GPG=1`.

mod common;

use common::gnupg;
use common::keys::{self, PLAINTEXT};
use cypher_engine::{
    EngineError, KeyShape, PrivateKey, Signature, Verdict, decrypt, encrypt, inspect_certificate,
};
use openpgp::Cert;
use openpgp::parse::Parse;
use sequoia_openpgp as openpgp;

fn fixture_key() -> std::sync::Arc<PrivateKey> {
    keys::handle_of(&Cert::from_bytes(&common::load_fixture("gpg_secretkey.asc")).unwrap())
}

#[test]
fn e21_engine_reads_gnupg_fixtures() {
    let expected = common::load_fixture("gpg_plaintext.txt");
    for name in [
        "gpg_encrypted_message.asc",
        "gpg_encrypted_message.gpg",
        "gpg_encrypted_compressed_zlib.asc",
        "gpg_encrypted_compressed_deflate.asc",
    ] {
        let decrypted = decrypt(common::load_fixture(name), fixture_key(), vec![]).unwrap();
        assert_eq!(decrypted.plaintext, expected, "{name}");
        assert!(!decrypted.quantum_safe);
    }
    assert_eq!(
        decrypt(
            common::load_fixture("gpg_encrypted_tampered.gpg"),
            fixture_key(),
            vec![]
        )
        .unwrap_err(),
        EngineError::Tampered
    );

    let info = inspect_certificate(common::load_fixture("gpg_pubkey.asc")).unwrap();
    assert_eq!(info.shape, Some(KeyShape::V4Curve25519));
    assert_eq!(info.name.as_deref(), Some("GnuPG Test User"));
    assert_eq!(info.email.as_deref(), Some("gnupg-test@example.com"));
}

/// The engine encrypts to a key gpg made and signs with a Legacy key; gpg
/// decrypts and reports a good signature.
#[test]
fn e21_gnupg_reads_legacy_messages() {
    let Some(gpg) = gnupg::require_gpg_or_skip() else {
        return;
    };
    let home = gnupg::setup_gpg_home();
    let bob = gnupg::gpg_generate_key(&gpg, &home, "Bob <bob@example.org>", "ed25519", "cv25519");
    let alice = keys::new_key(KeyShape::V4Curve25519, "Alice");
    gnupg::gpg_import_key(&gpg, &home, &keys::armored_certificate(&alice.certificate));

    let message = encrypt(PLAINTEXT, vec![bob], Some(keys::handle(&alice))).unwrap();
    let message_path = home.path().join("message.asc");
    std::fs::write(&message_path, &message.message).unwrap();
    let output = gnupg::gpg_cmd(&gpg, &home)
        .args(["--status-fd", "2", "--decrypt"])
        .arg(&message_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "gpg --decrypt failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, PLAINTEXT);
    gnupg::assert_gpg_status_good_signature(&output.stderr);
}

/// gpg encrypts to a Legacy key and signs with its own key; the engine
/// decrypts and verifies.
#[test]
fn e21_engine_reads_gnupg_messages() {
    let Some(gpg) = gnupg::require_gpg_or_skip() else {
        return;
    };
    let home = gnupg::setup_gpg_home();
    let bob = gnupg::gpg_generate_key(&gpg, &home, "Bob <bob@example.org>", "ed25519", "cv25519");
    let alice = keys::new_key(KeyShape::V4Curve25519, "Alice");
    gnupg::gpg_import_key(&gpg, &home, &keys::armored_certificate(&alice.certificate));
    let alice_fingerprint = inspect_certificate(alice.certificate.clone())
        .unwrap()
        .fingerprint;
    let bob_fingerprint = inspect_certificate(bob.clone()).unwrap().fingerprint;

    let plaintext_path = home.path().join("plaintext.txt");
    std::fs::write(&plaintext_path, PLAINTEXT).unwrap();
    let output = gnupg::gpg_cmd(&gpg, &home)
        .args(["--armor", "--sign", "--encrypt"])
        .args([
            "--recipient",
            &alice_fingerprint,
            "--local-user",
            &bob_fingerprint,
        ])
        .arg("--output")
        .arg("-")
        .arg(&plaintext_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "gpg --encrypt failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let decrypted = decrypt(output.stdout, keys::handle(&alice), vec![bob]).unwrap();
    assert_eq!(decrypted.plaintext, PLAINTEXT);
    assert_eq!(
        decrypted.signature,
        Signature {
            verdict: Verdict::Verified,
            signer: Some(0)
        }
    );
}
