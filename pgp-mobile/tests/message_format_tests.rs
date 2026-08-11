//! The outgoing message format rule, held against the messages it describes.
//!
//! `message_format::decide_outgoing_message_format` states the container format
//! before a message exists. Every test here checks that statement against the
//! SEIP version byte of the ciphertext `encrypt` then produces from the same
//! recipients, so the two cannot drift apart.
//!
//! Certificates whose advertised features contradict their key version are
//! built deliberately. They are the cases a version-derived preview gets wrong,
//! and the reason the rule reads the Features subpacket: only certificates this
//! app generates are guaranteed to keep features and version in agreement
//! (`keys::generate_key_with_suite`), and an imported certificate is under no
//! such constraint.

mod common;
use common::detect_message_format;

use openpgp::cert::prelude::*;
use openpgp::serialize::Serialize;
use openpgp::types::Features;
use sequoia_openpgp as openpgp;

use pgp_mobile::encrypt;
use pgp_mobile::keys::{self, KeySuite};
use pgp_mobile::message_format::{decide_outgoing_message_format, OutgoingMessageFormat};

/// A v6 certificate whose valid self-signature does not advertise SEIPDv2 — the
/// direction that previews green and encrypts SEIPDv1.
fn v6_certificate_without_aead() -> Vec<u8> {
    forge_certificate(
        "V6 Without AEAD <v6-no-aead@example.test>",
        openpgp::Profile::RFC9580,
        Features::empty().set_seipdv1(),
    )
}

/// A v4 certificate that advertises SEIPDv2 — what stock Sequoia produces under
/// the RFC 4880 profile, and the direction that draws a false downgrade warning.
fn v4_certificate_with_aead() -> Vec<u8> {
    forge_certificate(
        "V4 With AEAD <v4-aead@example.test>",
        openpgp::Profile::RFC4880,
        Features::empty().set_seipdv1().set_seipdv2(),
    )
}

fn forge_certificate(user_id: &str, profile: openpgp::Profile, features: Features) -> Vec<u8> {
    let (cert, _) = CertBuilder::general_purpose(Some(user_id))
        .set_cipher_suite(CipherSuite::Cv25519)
        .set_profile(profile)
        .expect("Profile should be accepted")
        .set_features(features)
        .expect("Features should be accepted")
        .generate()
        .expect("Certificate generation should succeed");

    let mut public_key_data = Vec::new();
    cert.serialize(&mut public_key_data)
        .expect("Public certificate serialization should succeed");
    public_key_data
}

fn generated_certificate(name: &str, suite: KeySuite) -> Vec<u8> {
    keys::generate_key_with_suite(name.to_string(), None, None, suite)
        .expect("Key generation should succeed")
        .public_key_data
}

fn fingerprint(public_key_data: &[u8]) -> String {
    keys::parse_key_info(public_key_data)
        .expect("Key info should parse")
        .fingerprint
}

/// The format of the message `encrypt` actually produces for these recipients.
fn produced_format(
    recipients: &[Vec<u8>],
    encrypt_to_self: Option<&[u8]>,
) -> OutgoingMessageFormat {
    let ciphertext = encrypt::encrypt_binary(
        b"Message format drift check",
        recipients,
        None,
        encrypt_to_self,
    )
    .expect("Encryption should succeed");

    match detect_message_format(&ciphertext) {
        (true, false) => OutgoingMessageFormat::SeipdV1,
        (false, true) => OutgoingMessageFormat::SeipdV2,
        other => panic!("Ciphertext should carry exactly one SEIPD version, got {other:?}"),
    }
}

#[test]
fn the_forged_certificates_really_do_contradict_their_versions() {
    // The premise every divergence case below rests on. Were Sequoia to stop
    // honouring these Features overrides, the cases would quietly degrade into
    // ordinary v4/v6 certificates and prove nothing.
    let v6_without_aead = keys::parse_key_info(&v6_certificate_without_aead())
        .expect("Forged v6 certificate should parse");
    assert_eq!(v6_without_aead.key_version, 6);
    assert_eq!(
        decide_outgoing_message_format(&[v6_certificate_without_aead()], None)
            .expect("Decision should succeed")
            .format,
        OutgoingMessageFormat::SeipdV1,
        "A v6 certificate that does not advertise SEIPDv2 gets no AEAD"
    );

    let v4_with_aead = keys::parse_key_info(&v4_certificate_with_aead())
        .expect("Forged v4 certificate should parse");
    assert_eq!(v4_with_aead.key_version, 4);
    assert_eq!(
        decide_outgoing_message_format(&[v4_certificate_with_aead()], None)
            .expect("Decision should succeed")
            .format,
        OutgoingMessageFormat::SeipdV2,
        "A v4 certificate that advertises SEIPDv2 does get AEAD"
    );
}

#[test]
fn the_decision_matches_the_format_encrypt_produces() {
    let legacy = generated_certificate("Legacy", KeySuite::Ed25519LegacyCurve25519Legacy);
    let modern = generated_certificate("Modern", KeySuite::Ed25519X25519);
    let v6_without_aead = v6_certificate_without_aead();
    let v4_with_aead = v4_certificate_with_aead();

    let cases: [(&str, Vec<Vec<u8>>); 7] = [
        ("modern only", vec![modern.clone()]),
        ("legacy only", vec![legacy.clone()]),
        ("modern and legacy", vec![modern.clone(), legacy.clone()]),
        // The four a version-derived preview answers backwards.
        ("v6 without AEAD alone", vec![v6_without_aead.clone()]),
        (
            "v6 without AEAD beside a modern recipient",
            vec![v6_without_aead.clone(), modern.clone()],
        ),
        ("v4 with AEAD alone", vec![v4_with_aead.clone()]),
        (
            "v4 with AEAD beside a modern recipient",
            vec![v4_with_aead.clone(), modern.clone()],
        ),
    ];

    for (label, recipients) in cases {
        let decision =
            decide_outgoing_message_format(&recipients, None).expect("Decision should succeed");

        assert_eq!(
            decision.format,
            produced_format(&recipients, None),
            "Decision and produced message disagree for {label}"
        );
    }
}

#[test]
fn the_key_holding_the_message_at_seipd_v1_is_the_one_named() {
    let modern = generated_certificate("Modern", KeySuite::Ed25519X25519);
    let v6_without_aead = v6_certificate_without_aead();
    let recipients = vec![modern.clone(), v6_without_aead.clone()];

    let decision =
        decide_outgoing_message_format(&recipients, None).expect("Decision should succeed");

    assert_eq!(decision.format, produced_format(&recipients, None));
    assert!(decision.withholds_aead);
    assert_eq!(
        decision.seipd_v1_forcing_fingerprints,
        vec![fingerprint(&v6_without_aead)],
        "The recipient that does not advertise SEIPDv2 is what costs the other its AEAD"
    );
}

#[test]
fn the_encrypt_to_self_copy_decides_the_format_like_any_recipient() {
    let modern = generated_certificate("Modern", KeySuite::Ed25519X25519);
    let legacy = generated_certificate("Legacy", KeySuite::Ed25519LegacyCurve25519Legacy);

    let decision = decide_outgoing_message_format(&[modern.clone()], Some(&legacy))
        .expect("Decision should succeed");

    assert_eq!(
        decision.format,
        produced_format(&[modern], Some(&legacy)),
        "A self copy is a recipient and moves the format like any other"
    );
    assert!(decision.withholds_aead);
    assert_eq!(
        decision.seipd_v1_forcing_fingerprints,
        vec![fingerprint(&legacy)],
        "A self key with no row of its own is still named as the cause"
    );
}

#[test]
fn a_set_that_could_never_have_had_aead_gives_up_nothing() {
    let legacy = generated_certificate("Legacy", KeySuite::Ed25519LegacyCurve25519Legacy);
    let other_legacy =
        generated_certificate("Other Legacy", KeySuite::Ed25519LegacyCurve25519Legacy);
    let recipients = vec![legacy, other_legacy];

    let decision =
        decide_outgoing_message_format(&recipients, None).expect("Decision should succeed");

    assert_eq!(decision.format, OutgoingMessageFormat::SeipdV1);
    assert_eq!(decision.format, produced_format(&recipients, None));
    assert!(
        !decision.withholds_aead,
        "SEIPDv1 is what these keys support — nothing is being given up"
    );
    assert!(decision.seipd_v1_forcing_fingerprints.is_empty());
}

#[test]
fn a_recipient_set_encrypt_would_refuse_has_no_format_to_report() {
    assert!(
        decide_outgoing_message_format(&[], None).is_err(),
        "No recipients is not a message"
    );
    assert!(
        encrypt::encrypt_binary(b"No recipients", &[], None, None).is_err(),
        "…and the encrypt path refuses it the same way"
    );

    assert!(
        decide_outgoing_message_format(&[b"not a certificate".to_vec()], None).is_err(),
        "Unparseable recipient material is refused, not silently skipped"
    );
}

#[test]
fn a_certificate_counted_twice_is_still_one_recipient() {
    let legacy = generated_certificate("Legacy", KeySuite::Ed25519LegacyCurve25519Legacy);
    let modern = generated_certificate("Modern", KeySuite::Ed25519X25519);

    // Encrypt to self with a key already chosen as a recipient: the engine
    // deduplicates, so the same key must not be named twice as the cause.
    let decision = decide_outgoing_message_format(&[modern, legacy.clone()], Some(&legacy))
        .expect("Decision should succeed");

    assert_eq!(
        decision.seipd_v1_forcing_fingerprints,
        vec![fingerprint(&legacy)]
    );
}
