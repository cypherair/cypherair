//! `sq` (sequoia-sq) cross-tool interoperability tests — fixture side.
//!
//! These tests consume pre-generated `sq` fixtures (see
//! `fixtures/generate_sq_fixtures.sh`; tool versions in `sq_version.txt`) and
//! run always-on: deterministic, offline, CI-safe (issue #567 closeout).
//!
//! Coverage per suite (legacy v4, modern v6, modernhigh v6, pq RFC 9980,
//! pqhigh RFC 9980):
//! - parse + family classification of the sq certificate;
//! - our engine encrypts to the sq certificate with the negotiated message
//!   format, and the sq secret key decrypts it through our engine;
//! - the sq-encrypted fixture decrypts through our engine (for the pq suites
//!   this is the RFC 9980 cross-implementation PKESK/SEIPD evidence);
//! - the sq inline-signed and detached-signature fixtures verify against the
//!   sq certificate;
//! - mixed-recipient sets exercise the SEIPDv1 floor (hard constraint #8).
//!
//! Format-selection nuance (TDD §1.4): selection is negotiated from the
//! recipient certificates' Features subpackets. sq advertises `SEIPDv1,
//! SEIPDv2` even on its default v4 profile, so every sq suite — including
//! `legacy` — correctly negotiates SEIPDv2. The SEIPDv1 floor for v4-only
//! holders (keys that do not advertise SEIPDv2, like GnuPG's or our Profile
//! A's) is asserted in the mixed-recipient test below with an engine
//! legacy key in the set.
//!
//! The pq/pqhigh suites additionally decrypt the sq-encrypted fixtures through
//! the split-custody external-decryptor path, which is the cross-implementation
//! proof for the vendored RFC 9980 §4.2.1 KEM combiner: sq encapsulated with
//! stock Sequoia, and the vendored combiner must recover the same session key.

use std::sync::Arc;

use openpgp::crypto::mpi;
use openpgp::packet::key::SecretKeyMaterial;
use openpgp::parse::Parse;
use openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp as openpgp;
use tempfile::NamedTempFile;

use pgp_mobile::armor;
use pgp_mobile::decrypt;
use pgp_mobile::encrypt;
use pgp_mobile::keys::{self, KeySuite};
use pgp_mobile::signature_details::SignatureVerificationState;
use pgp_mobile::streaming;
use pgp_mobile::verify;
use pgp_mobile::PgpEngine;

mod common;
use common::composite::{
    SoftwareMlKem1024DecapsulationProvider, SoftwareMlKem768DecapsulationProvider,
};
use common::format::detect_seipd_v2_cipher;
use common::{detect_message_format, load_fixture};

/// One sq-generated fixture suite and the family classification we expect.
struct SqSuite {
    name: &'static str,
    key_version: u8,
    profile: KeySuite,
}

const LEGACY: SqSuite = SqSuite {
    name: "legacy",
    key_version: 4,
    profile: KeySuite::Ed25519LegacyCurve25519Legacy,
};
const MODERN: SqSuite = SqSuite {
    name: "modern",
    key_version: 6,
    profile: KeySuite::Ed25519X25519,
};
const MODERN_HIGH: SqSuite = SqSuite {
    name: "modernhigh",
    key_version: 6,
    profile: KeySuite::Ed448X448,
};
const PQ: SqSuite = SqSuite {
    name: "pq",
    key_version: 6,
    profile: KeySuite::MlDsa65Ed25519MlKem768X25519,
};
const PQ_HIGH: SqSuite = SqSuite {
    name: "pqhigh",
    key_version: 6,
    profile: KeySuite::MlDsa87Ed448MlKem1024X448,
};

impl SqSuite {
    fn fixture(&self, kind: &str) -> Vec<u8> {
        load_fixture(&format!("sq_{}_{}.asc", self.name, kind))
    }

    fn pubkey(&self) -> Vec<u8> {
        self.fixture("pubkey")
    }

    fn secretkey(&self) -> Vec<u8> {
        self.fixture("secretkey")
    }

    fn is_post_quantum(&self) -> bool {
        matches!(
            self.profile,
            KeySuite::MlDsa65Ed25519MlKem768X25519 | KeySuite::MlDsa87Ed448MlKem1024X448
        )
    }
}

fn sq_plaintext() -> Vec<u8> {
    load_fixture("sq_plaintext.txt")
}

fn write_temp_data_file(data: &[u8]) -> NamedTempFile {
    let input = NamedTempFile::new().expect("temp input should be created");
    std::fs::write(input.path(), data).expect("temp input should be written");
    input
}

/// Dearmor an armored fixture so packet-level format inspection sees binary.
fn dearmor(data: &[u8]) -> Vec<u8> {
    let (binary, _kind) = armor::decode_armor(data).expect("fixture should dearmor");
    binary
}

// ── (a) Parse the sq certificate and classify its family ───────────────────

fn assert_sq_cert_classifies(suite: &SqSuite) {
    let pubkey = suite.pubkey();
    let info = keys::parse_key_info(&pubkey).expect("sq public cert should parse");

    assert_eq!(info.key_version, suite.key_version, "key version");
    assert_eq!(info.suite, suite.profile, "profile classification");
    assert!(info.has_encryption_subkey, "must have encryption subkey");
    assert!(!info.is_revoked);
    assert!(!info.is_expired);
    assert!(info.user_id.is_some(), "sq cert should carry a user ID");

    assert_eq!(
        keys::detect_suite(&pubkey).expect("detect_suite"),
        suite.profile
    );
}

#[test]
fn test_parse_sq_legacy_cert_classifies_legacy_v4() {
    assert_sq_cert_classifies(&LEGACY);
}

#[test]
fn test_parse_sq_modern_cert_classifies_modern_v6() {
    assert_sq_cert_classifies(&MODERN);
}

#[test]
fn test_parse_sq_modernhigh_cert_classifies_ed448x448_v6() {
    assert_sq_cert_classifies(&MODERN_HIGH);
}

#[test]
fn test_parse_sq_pq_cert_classifies_post_quantum_v6() {
    assert_sq_cert_classifies(&PQ);
}

#[test]
fn test_parse_sq_pqhigh_cert_classifies_post_quantum_high_v6() {
    assert_sq_cert_classifies(&PQ_HIGH);
}

// ── (b) Our engine encrypts to the sq certificate; the negotiated format
//        holds; the sq secret key decrypts through our engine ───────────────

fn assert_engine_encrypts_to_sq_cert(suite: &SqSuite) {
    let pubkey = suite.pubkey();
    let secretkey = suite.secretkey();
    let plaintext = b"From CypherAir to an sq-generated certificate.";

    // Negotiated format: every sq cert — the v4 `legacy` one included —
    // advertises the SEIPDv2 feature, so Sequoia selects SEIPDv2 for all
    // suites. The v4-only SEIPDv1 floor is covered by the mixed test below.
    let ciphertext_binary = encrypt::encrypt_binary(plaintext, &[pubkey.clone()], None, None)
        .expect("binary encryption to sq cert should succeed");
    let (has_v1, has_v2) = detect_message_format(&ciphertext_binary);
    assert!(
        has_v2,
        "encryption to an SEIPDv2-advertising sq cert must produce SEIPDv2"
    );
    assert!(!has_v1, "no SEIPDv1 fallback for an SEIPDv2-capable recipient");

    // Any PQ recipient additionally forces the AES-256 floor (RFC 9980).
    if suite.is_post_quantum() {
        let (cipher, _aead) = detect_seipd_v2_cipher(&ciphertext_binary)
            .expect("PQ recipient message must be SEIPDv2");
        assert_eq!(cipher, SymmetricAlgorithm::AES256, "AES-256 floor");
    }

    // Round trip: the sq secret key decrypts our armored message.
    let ciphertext = encrypt::encrypt(plaintext, &[pubkey.clone()], None, None)
        .expect("encryption to sq cert should succeed");
    let result = decrypt::decrypt_detailed(&ciphertext, &[secretkey], &[pubkey])
        .expect("sq secret key should decrypt our message");
    assert_eq!(result.plaintext, plaintext);
}

#[test]
fn test_engine_encrypt_to_sq_legacy_negotiates_seipdv2_and_roundtrips() {
    // sq's default v4 profile advertises `Features: SEIPDv1, SEIPDv2`, so the
    // negotiated format is SEIPDv2 even though the key is v4 — and sq itself
    // decrypts such messages (it announced the capability).
    assert_engine_encrypts_to_sq_cert(&LEGACY);
}

#[test]
fn test_engine_encrypt_to_sq_modern_uses_seipdv2_and_roundtrips() {
    assert_engine_encrypts_to_sq_cert(&MODERN);
}

#[test]
fn test_engine_encrypt_to_sq_modernhigh_uses_seipdv2_and_roundtrips() {
    assert_engine_encrypts_to_sq_cert(&MODERN_HIGH);
}

#[test]
fn test_engine_encrypt_to_sq_pq_uses_seipdv2_aes256_and_roundtrips() {
    assert_engine_encrypts_to_sq_cert(&PQ);
}

#[test]
fn test_engine_encrypt_to_sq_pqhigh_uses_seipdv2_aes256_and_roundtrips() {
    assert_engine_encrypts_to_sq_cert(&PQ_HIGH);
}

// ── (c) The sq-encrypted fixture decrypts through our engine ───────────────
// Proves we consume sq's PKESK/SEIPD output; for the pq suites this is the
// RFC 9980 cross-implementation evidence.

fn assert_sq_encrypted_fixture_decrypts(suite: &SqSuite) {
    let ciphertext = suite.fixture("encrypted");
    let secretkey = suite.secretkey();
    let pubkey = suite.pubkey();
    let expected = sq_plaintext();

    // sq's own output lands on the same negotiated format we produce:
    // SEIPDv2 for every suite, because even the v4 `legacy` cert advertises
    // the SEIPDv2 feature.
    let (has_v1, has_v2) = detect_message_format(&dearmor(&ciphertext));
    assert!(has_v2 && !has_v1, "sq fixture must be SEIPDv2");

    let result = decrypt::decrypt_detailed(&ciphertext, &[secretkey], &[pubkey])
        .expect("sq-encrypted fixture should decrypt through our engine");
    assert_eq!(result.plaintext, expected);
}

#[test]
fn test_decrypt_sq_encrypted_legacy_fixture() {
    assert_sq_encrypted_fixture_decrypts(&LEGACY);
}

#[test]
fn test_decrypt_sq_encrypted_modern_fixture() {
    assert_sq_encrypted_fixture_decrypts(&MODERN);
}

#[test]
fn test_decrypt_sq_encrypted_modernhigh_fixture() {
    assert_sq_encrypted_fixture_decrypts(&MODERN_HIGH);
}

#[test]
fn test_decrypt_sq_encrypted_pq_fixture() {
    assert_sq_encrypted_fixture_decrypts(&PQ);
}

#[test]
fn test_decrypt_sq_encrypted_pqhigh_fixture() {
    assert_sq_encrypted_fixture_decrypts(&PQ_HIGH);
}

// ── (d) sq signatures verify against the sq certificate ────────────────────

fn assert_sq_signatures_verify(suite: &SqSuite) {
    let pubkey = suite.pubkey();
    let data = sq_plaintext();

    // Inline-signed message (`sq sign --message`).
    let inline_signed = suite.fixture("inline_signed");
    let result = verify::verify_cleartext_detailed(&inline_signed, &[pubkey.clone()])
        .expect("sq inline-signed message should verify");
    assert_eq!(result.summary_state, SignatureVerificationState::Verified);
    let content = result.content.expect("inline message should carry content");
    assert_eq!(content, data, "inline-signed content must match plaintext");

    // Detached signature (`sq sign --signature-file`).
    let signature = suite.fixture("detached_sig");
    let input = write_temp_data_file(&data);
    let result = streaming::verify_detached_file_detailed(
        input.path().to_str().unwrap(),
        &signature,
        &[pubkey],
        None,
    )
    .expect("sq detached signature should verify");
    assert_eq!(result.summary_state, SignatureVerificationState::Verified);
}

#[test]
fn test_verify_sq_legacy_signatures() {
    assert_sq_signatures_verify(&LEGACY);
}

#[test]
fn test_verify_sq_modern_signatures() {
    assert_sq_signatures_verify(&MODERN);
}

#[test]
fn test_verify_sq_modernhigh_signatures() {
    assert_sq_signatures_verify(&MODERN_HIGH);
}

#[test]
fn test_verify_sq_pq_signatures() {
    assert_sq_signatures_verify(&PQ);
}

#[test]
fn test_verify_sq_pqhigh_signatures() {
    assert_sq_signatures_verify(&PQ_HIGH);
}

// ── (e) Mixed-recipient format rule with sq certificates in the set ────────

/// The SEIPDv1 floor (hard constraint #8): an engine Portable Legacy
/// key advertises only SEIPDv1, so mixing it with an sq v6 cert must floor
/// the whole message to SEIPDv1 — never SEIPDv2 when a v4-only holder is a
/// recipient — and both sides must decrypt. Mirrors the cross-profile GnuPG
/// assertions with a real sq cert in the set.
#[test]
fn test_mixed_engine_v4_only_and_sq_v6_recipients_floor_to_seipdv1() {
    let engine_key = keys::generate_key_with_suite(
        "Engine Legacy".to_string(),
        None,
        None,
        KeySuite::Ed25519LegacyCurve25519Legacy,
    )
    .expect("engine legacy key gen should succeed");
    let modern_pub = MODERN.pubkey();
    let plaintext = b"Mixed engine-v4-only + sq-v6 recipient set.";

    let recipients = [engine_key.public_key_data.clone(), modern_pub.clone()];
    let ciphertext_binary = encrypt::encrypt_binary(plaintext, &recipients, None, None)
        .expect("mixed-recipient encryption should succeed");
    let (has_v1, has_v2) = detect_message_format(&ciphertext_binary);
    assert!(has_v1, "a v4-only recipient must floor the set to SEIPDv1");
    assert!(!has_v2, "never SEIPDv2 when a v4-only holder is a recipient");

    let ciphertext = encrypt::encrypt(plaintext, &recipients, None, None)
        .expect("mixed-recipient encryption should succeed");

    let engine_result = decrypt::decrypt_detailed(&ciphertext, &[engine_key.cert_data], &[])
        .expect("engine v4-only recipient should decrypt");
    assert_eq!(engine_result.plaintext, plaintext);

    let modern_result = decrypt::decrypt_detailed(&ciphertext, &[MODERN.secretkey()], &[])
        .expect("sq v6 recipient should decrypt");
    assert_eq!(modern_result.plaintext, plaintext);
}

/// The capability-negotiation counterpart: sq's v4 `legacy` cert advertises
/// SEIPDv2, so the sq v4 + sq v6 set negotiates SEIPDv2 (no floor is needed —
/// every holder announced AEAD support) and both sq keys decrypt.
#[test]
fn test_mixed_sq_v4_and_v6_recipients_negotiate_seipdv2() {
    let legacy_pub = LEGACY.pubkey();
    let modern_pub = MODERN.pubkey();
    let plaintext = b"Mixed sq v4+v6 recipient set from CypherAir.";

    let recipients = [legacy_pub.clone(), modern_pub.clone()];
    let ciphertext_binary = encrypt::encrypt_binary(plaintext, &recipients, None, None)
        .expect("mixed-recipient encryption should succeed");
    let (has_v1, has_v2) = detect_message_format(&ciphertext_binary);
    assert!(
        has_v2 && !has_v1,
        "SEIPDv2-advertising v4+v6 sq recipients negotiate SEIPDv2"
    );

    let ciphertext = encrypt::encrypt(plaintext, &recipients, None, None)
        .expect("mixed-recipient encryption should succeed");

    let legacy_result = decrypt::decrypt_detailed(&ciphertext, &[LEGACY.secretkey()], &[])
        .expect("sq v4 recipient should decrypt");
    assert_eq!(legacy_result.plaintext, plaintext);

    let modern_result = decrypt::decrypt_detailed(&ciphertext, &[MODERN.secretkey()], &[])
        .expect("sq v6 recipient should decrypt");
    assert_eq!(modern_result.plaintext, plaintext);
}

// ── Split-custody consumption of sq PQ fixtures (vendored combiner) ────────
// The strongest cross-implementation evidence for the vendored RFC 9980
// §4.2.1 KEM combiner: sq encapsulated through stock Sequoia, and our
// split-custody path (in-Rust classical ECDH + external ML-KEM decapsulation
// + vendored combiner + AES-256 unwrap) must recover the identical session
// key from the committed fixture.

/// Extract the composite key-agreement halves from an sq TSK: the subkey
/// fingerprint, the classical ECDH secret scalar, and the ML-KEM secret seed.
fn extract_composite_key_agreement_halves(
    tsk_data: &[u8],
    expect_high_tier: bool,
) -> (String, Vec<u8>, Vec<u8>) {
    let cert = openpgp::Cert::from_bytes(tsk_data).expect("sq TSK should parse");
    for key in cert.keys().subkeys() {
        let is_composite_ka = matches!(
            (key.key().mpis(), expect_high_tier),
            (mpi::PublicKey::MLKEM768_X25519 { .. }, false)
                | (mpi::PublicKey::MLKEM1024_X448 { .. }, true)
        );
        if !is_composite_ka {
            continue;
        }
        let fingerprint = key.key().fingerprint().to_hex();
        let Some(SecretKeyMaterial::Unencrypted(secret)) = key.key().optional_secret() else {
            panic!("sq TSK key-agreement subkey should carry unencrypted secret material");
        };
        let (ecdh_secret, mlkem_seed) = secret.map(|mpis| match mpis {
            mpi::SecretKeyMaterial::MLKEM768_X25519 { ecdh, mlkem } => {
                (ecdh.to_vec(), mlkem.to_vec())
            }
            mpi::SecretKeyMaterial::MLKEM1024_X448 { ecdh, mlkem } => {
                (ecdh.to_vec(), mlkem.to_vec())
            }
            _ => panic!("expected composite key-agreement secret material"),
        });
        return (fingerprint, ecdh_secret, mlkem_seed);
    }
    panic!("sq TSK should contain a composite key-agreement subkey");
}

#[test]
fn test_sq_pq_fixture_decrypts_through_split_custody_vendored_combiner() {
    let (ka_fingerprint, ecdh_secret, mlkem_seed) =
        extract_composite_key_agreement_halves(&PQ.secretkey(), false);

    let result = PgpEngine::new()
        .decrypt_detailed_with_external_composite_key_agreement(
            PQ.fixture("encrypted"),
            PQ.pubkey(),
            ka_fingerprint,
            ecdh_secret,
            Arc::new(SoftwareMlKem768DecapsulationProvider::new(mlkem_seed)),
            vec![],
        )
        .expect("sq PQ fixture should decrypt through the split-custody path");
    assert_eq!(result.plaintext, sq_plaintext());
}

#[test]
fn test_sq_pqhigh_fixture_decrypts_through_split_custody_vendored_combiner() {
    let (ka_fingerprint, ecdh_secret, mlkem_seed) =
        extract_composite_key_agreement_halves(&PQ_HIGH.secretkey(), true);

    let result = PgpEngine::new()
        .decrypt_detailed_with_external_composite_high_key_agreement(
            PQ_HIGH.fixture("encrypted"),
            PQ_HIGH.pubkey(),
            ka_fingerprint,
            ecdh_secret,
            Arc::new(SoftwareMlKem1024DecapsulationProvider::new(mlkem_seed)),
            vec![],
        )
        .expect("sq PQ-high fixture should decrypt through the split-custody path");
    assert_eq!(result.plaintext, sq_plaintext());
}
