//! Rule E21 with `sq`: `sq` reads what the v6 and post-quantum families write,
//! and the engine reads what `sq` writes. The fixture tests need no `sq`; the
//! live ones skip without it unless `CYPHERAIR_REQUIRE_SQ=1`, which also
//! requires an `sq` that reads the final post-quantum encoding.

mod common;

use std::path::PathBuf;

use common::keys::{self, PLAINTEXT};
use common::sq;
use cypher_engine::{KeyShape, Signature, Verdict, decrypt, encrypt, inspect_certificate};
use openpgp::Cert;
use openpgp::parse::Parse;
use sequoia_openpgp as openpgp;

/// The fixture suites, the shape each certificate has, and whether a message to
/// it is quantum-safe.
const SUITES: [(&str, KeyShape, bool); 5] = [
    ("legacy", KeyShape::V4Curve25519, false),
    ("modern", KeyShape::V6Curve25519, false),
    ("modernhigh", KeyShape::V6Curve448, false),
    ("pq", KeyShape::V6MlDsa65, true),
    ("pqhigh", KeyShape::V6MlDsa87, true),
];

/// The families `sq` checks live, with the cipher suite `sq` names each by.
const LIVE: [(KeyShape, &str); 4] = [
    (KeyShape::V6Curve25519, "cv25519"),
    (KeyShape::V6Curve448, "cv448"),
    (KeyShape::V6MlDsa65, "mldsa65-ed25519"),
    (KeyShape::V6MlDsa87, "mldsa87-ed448"),
];

fn is_post_quantum(shape: KeyShape) -> bool {
    matches!(shape, KeyShape::V6MlDsa65 | KeyShape::V6MlDsa87)
}

fn require_sq(shape: KeyShape) -> Option<PathBuf> {
    if is_post_quantum(shape) {
        sq::require_pq_capable_sq_or_skip()
    } else {
        sq::require_sq_or_skip()
    }
}

#[test]
fn e21_engine_reads_sq_fixtures() {
    let expected = common::load_fixture("sq_plaintext.txt");
    for (suite, shape, quantum_safe) in SUITES {
        let secret =
            Cert::from_bytes(&common::load_fixture(&format!("sq_{suite}_secretkey.asc"))).unwrap();
        let message = common::load_fixture(&format!("sq_{suite}_encrypted.asc"));
        let decrypted = decrypt(message, keys::handle_of(&secret), vec![]).unwrap();
        assert_eq!(decrypted.plaintext, expected, "{suite}");
        assert_eq!(decrypted.quantum_safe, quantum_safe, "{suite}");

        let info =
            inspect_certificate(common::load_fixture(&format!("sq_{suite}_pubkey.asc"))).unwrap();
        assert_eq!(info.shape, Some(shape), "{suite}");
    }
}

/// The engine encrypts and signs with each v6 and post-quantum family; `sq`
/// decrypts and authenticates exactly one signature.
#[test]
fn e21_sq_reads_engine_messages() {
    for (shape, _) in LIVE {
        let Some(sq_path) = require_sq(shape) else {
            continue;
        };
        let home = sq::setup_sq_home();
        let alice = keys::new_key(shape, "Alice");
        let key_path = home.path().join("alice-secret.asc");
        let cert_path = home.path().join("alice.asc");
        let message_path = home.path().join("message.asc");
        let output_path = home.path().join("plaintext.txt");
        std::fs::write(&key_path, keys::tsk(&alice)).unwrap();
        std::fs::write(&cert_path, keys::armored_certificate(&alice.certificate)).unwrap();

        let message = encrypt(
            PLAINTEXT,
            vec![alice.certificate.clone()],
            Some(keys::handle(&alice)),
        )
        .unwrap();
        std::fs::write(&message_path, &message.message).unwrap();
        let mut decrypt_cmd = sq::sq_cmd(&sq_path, &home);
        decrypt_cmd
            .args(["decrypt", "--signatures", "1"])
            .arg("--recipient-file")
            .arg(&key_path)
            .arg("--signer-file")
            .arg(&cert_path)
            .arg("--output")
            .arg(&output_path)
            .arg(&message_path);
        sq::run_sq(decrypt_cmd, &format!("decrypt ({shape:?})"));
        assert_eq!(std::fs::read(&output_path).unwrap(), PLAINTEXT, "{shape:?}");
    }
}

/// `sq` makes a key in each family, encrypts to an engine key of that family
/// and signs; the engine decrypts and verifies.
#[test]
fn e21_engine_reads_sq_messages() {
    for (shape, cipher_suite) in LIVE {
        let Some(sq_path) = require_sq(shape) else {
            continue;
        };
        let home = sq::setup_sq_home();
        let alice = keys::new_key(shape, "Alice");
        let alice_path = home.path().join("alice.asc");
        let bob_path = home.path().join("bob.asc");
        let bob_secret_path = home.path().join("bob-secret.asc");
        let plaintext_path = home.path().join("plaintext.txt");
        let message_path = home.path().join("message.asc");
        std::fs::write(&alice_path, keys::armored_certificate(&alice.certificate)).unwrap();
        std::fs::write(&plaintext_path, PLAINTEXT).unwrap();

        let mut generate = sq::sq_cmd(&sq_path, &home);
        generate
            .args(["key", "generate", "--own-key", "--without-password"])
            .args(["--name", "Bob", "--email", "bob@example.org"])
            .args([
                "--cipher-suite",
                cipher_suite,
                "--profile",
                "rfc9580",
                "--expiration",
                "never",
            ])
            .arg("--output")
            .arg(&bob_secret_path)
            .arg("--rev-cert")
            .arg(home.path().join("bob-revocation.asc"));
        sq::run_sq(generate, "key generate");
        let bob = Cert::from_bytes(&std::fs::read(&bob_secret_path).unwrap()).unwrap();
        std::fs::write(&bob_path, keys::armored_certificate(&keys::split(&bob).0)).unwrap();

        let mut encrypt_cmd = sq::sq_cmd(&sq_path, &home);
        encrypt_cmd
            .arg("encrypt")
            .arg("--for-file")
            .arg(&alice_path)
            .arg("--signer-file")
            .arg(&bob_secret_path)
            .arg("--output")
            .arg(&message_path)
            .arg(&plaintext_path);
        sq::run_sq(encrypt_cmd, &format!("encrypt ({shape:?})"));

        let message = std::fs::read(&message_path).unwrap();
        let decrypted = decrypt(message, keys::handle(&alice), vec![keys::split(&bob).0]).unwrap();
        assert_eq!(decrypted.plaintext, PLAINTEXT, "{shape:?}");
        assert_eq!(
            decrypted.signature,
            Signature {
                verdict: Verdict::Verified,
                signer: Some(0)
            },
            "{shape:?}"
        );
        assert_eq!(decrypted.quantum_safe, is_post_quantum(shape), "{shape:?}");
    }
}
