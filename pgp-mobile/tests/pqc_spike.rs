//! RFC 9980 post-quantum feasibility spike (issue #567, Phase 0).
//!
//! Exercises the real pgp-mobile pipeline with a composite
//! ML-DSA-65+Ed25519 (algo 30) primary key and ML-KEM-768+X25519
//! (algo 35) encryption subkey on a v6 certificate, and records
//! artifact sizes. Spike-only evidence; not part of the product
//! test matrix.

use pgp_mobile::PgpEngine;
use sequoia_openpgp as openpgp;

use openpgp::cert::{CertBuilder, CipherSuite};
use openpgp::parse::{PacketParser, PacketParserResult, Parse};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::{Serialize, SerializeInto};
use openpgp::types::PublicKeyAlgorithm;
use openpgp::Packet;

/// Generate a Portable Post-Quantum candidate cert: v6,
/// MLDSA65+Ed25519 primary, MLKEM768+X25519 encryption subkey.
fn generate_pq() -> (openpgp::Cert, Vec<u8>, Vec<u8>) {
    let (cert, _rev) = CertBuilder::general_purpose(Some("PQ Spike <pq@spike.example>"))
        .set_cipher_suite(CipherSuite::MLDSA65_Ed25519)
        .set_profile(openpgp::Profile::RFC9580)
        .expect("set RFC 9580 profile")
        .generate()
        .expect("generate PQ cert");

    let mut tsk = Vec::new();
    cert.as_tsk().serialize(&mut tsk).expect("serialize TSK");
    let pub_armored = cert.armored().to_vec().expect("armor public cert");
    (cert, tsk, pub_armored)
}

/// Generate a Legacy-equivalent classical cert (v4, Cv25519,
/// RFC 4880) the same way the engine's Universal profile does.
fn generate_classical_v4() -> (Vec<u8>, Vec<u8>) {
    let (cert, _rev) = CertBuilder::general_purpose(Some("Classic Spike <classic@spike.example>"))
        .set_cipher_suite(CipherSuite::Cv25519)
        .set_profile(openpgp::Profile::RFC4880)
        .expect("set RFC 4880 profile")
        // Match the engine's Legacy exactly: advertise SEIPDv1 only
        // (see keys/generation.rs — GnuPG compatibility).
        .set_features(openpgp::types::Features::empty().set_seipdv1())
        .expect("set Legacy features")
        .generate()
        .expect("generate classical cert");
    let mut tsk = Vec::new();
    cert.as_tsk().serialize(&mut tsk).expect("serialize TSK");
    let pub_armored = cert.armored().to_vec().expect("armor public cert");
    (tsk, pub_armored)
}

/// Walk the OpenPGP packets of a message and describe the
/// recipient-relevant framing: PKESK algorithms and SEIPD version.
fn describe_message(ct: &[u8]) -> (Vec<PublicKeyAlgorithm>, Option<u8>) {
    let mut pkesk_algos = Vec::new();
    let mut seipd_version = None;

    let mut ppr = PacketParser::from_bytes(ct).expect("parse message");
    while let PacketParserResult::Some(pp) = ppr {
        match &pp.packet {
            Packet::PKESK(openpgp::packet::PKESK::V3(p)) => pkesk_algos.push(p.pk_algo()),
            Packet::PKESK(openpgp::packet::PKESK::V6(p)) => pkesk_algos.push(p.pk_algo()),
            Packet::SEIP(openpgp::packet::SEIP::V1(_)) => seipd_version = Some(1),
            Packet::SEIP(openpgp::packet::SEIP::V2(_)) => seipd_version = Some(2),
            _ => {}
        }
        if seipd_version.is_some() {
            // Do not descend into the encrypted container.
            break;
        }
        let (_packet, next) = pp.next().expect("advance parser");
        ppr = next;
    }
    (pkesk_algos, seipd_version)
}

#[test]
fn pq_cert_shape_and_sizes() {
    let (cert, tsk, pub_armored) = generate_pq();
    let policy = &StandardPolicy::new();

    assert_eq!(cert.primary_key().key().version(), 6, "PQ cert must be v6");
    assert_eq!(
        cert.primary_key().key().pk_algo(),
        PublicKeyAlgorithm::MLDSA65_Ed25519,
        "primary must be composite ML-DSA-65+Ed25519 (algo 30)"
    );

    let enc_keys: Vec<_> = cert
        .keys()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .collect();
    assert_eq!(enc_keys.len(), 1, "exactly one encryption subkey");
    assert_eq!(
        enc_keys[0].key().pk_algo(),
        PublicKeyAlgorithm::MLKEM768_X25519,
        "encryption subkey must be composite ML-KEM-768+X25519 (algo 35)"
    );

    println!(
        "SPIKE-SIZES pq_pub_armored_bytes={} pq_tsk_binary_bytes={}",
        pub_armored.len(),
        tsk.len()
    );
    println!(
        "SPIKE-QR single_qr_binary_capacity=2953 pq_pub_fits_single_qr={}",
        pub_armored.len() <= 2953
    );
}

#[test]
fn pq_engine_encrypt_decrypt_roundtrip() {
    let engine = PgpEngine::new();
    let (_cert, tsk, pub_armored) = generate_pq();
    let msg = b"post-quantum spike message".to_vec();

    let ct = engine
        .encrypt(msg.clone(), vec![pub_armored.clone()], None, None)
        .expect("engine encrypt to PQ recipient");
    println!("SPIKE-SIZES pq_message_armored_bytes={}", ct.len());

    let (pkesk_algos, seipd) = describe_message(&ct);
    println!("SPIKE-FORMAT pq_only pkesks={pkesk_algos:?} seipd_version={seipd:?}");
    assert!(
        pkesk_algos.contains(&PublicKeyAlgorithm::MLKEM768_X25519),
        "PKESK must target the ML-KEM composite subkey"
    );

    let out = engine
        .decrypt_detailed(ct, vec![tsk], vec![])
        .expect("engine decrypt with PQ secret key");
    assert_eq!(out.plaintext, msg, "round-trip plaintext must match");
}

#[test]
fn pq_engine_sign_verify_roundtrip() {
    let engine = PgpEngine::new();
    let (_cert, tsk, pub_armored) = generate_pq();
    let text = b"post-quantum spike signed text".to_vec();

    let signed = engine
        .sign_cleartext(text, tsk)
        .expect("engine cleartext sign with PQ key");
    println!("SPIKE-SIZES pq_cleartext_signature_bytes={}", signed.len());

    let result = engine
        .verify_cleartext_detailed(signed, vec![pub_armored])
        .expect("engine verify PQ cleartext signature");
    assert!(
        !result.signatures.is_empty(),
        "verification must surface the PQ signature"
    );
    println!(
        "SPIKE-VERIFY summary_state={:?} signatures={}",
        result.summary_state,
        result.signatures.len()
    );
}

#[test]
fn pq_mixed_recipients_with_v4_classical() {
    let engine = PgpEngine::new();
    let (_cert, pq_tsk, pq_pub) = generate_pq();
    let (classical_tsk, classical_pub) = generate_classical_v4();
    let msg = b"mixed post-quantum and classical recipients".to_vec();

    let ct = engine
        .encrypt(msg.clone(), vec![pq_pub, classical_pub], None, None)
        .expect("engine encrypt to mixed recipients");

    let (pkesk_algos, seipd) = describe_message(&ct);
    println!("SPIKE-FORMAT mixed_pq_v4 pkesks={pkesk_algos:?} seipd_version={seipd:?}");
    assert_eq!(pkesk_algos.len(), 2, "one PKESK per recipient");
    assert!(pkesk_algos.contains(&PublicKeyAlgorithm::MLKEM768_X25519));

    let via_pq = engine
        .decrypt_detailed(ct.clone(), vec![pq_tsk], vec![])
        .expect("PQ recipient decrypts mixed message");
    assert_eq!(via_pq.plaintext, msg);

    let via_classical = engine
        .decrypt_detailed(ct, vec![classical_tsk], vec![])
        .expect("classical recipient decrypts mixed message");
    assert_eq!(via_classical.plaintext, msg);
}

#[test]
fn pq_recipients_surface_in_parse_recipients() {
    let engine = PgpEngine::new();
    let (_cert, _tsk, pub_armored) = generate_pq();

    let ct = engine
        .encrypt(b"recipient listing".to_vec(), vec![pub_armored], None, None)
        .expect("encrypt");
    let recipients = engine
        .parse_recipients(ct)
        .expect("parse_recipients on a PQ message");
    assert_eq!(recipients.len(), 1);
    println!("SPIKE-RECIPIENTS {recipients:?}");
}
