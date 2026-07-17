//! Portable Post-Quantum message tests (RFC 9980).
//! Covers the recipient matrix (PQ-only, PQ+v4, PQ+v6, PQ+PQ), the
//! AES-256 format floor, and signing round-trips —
//! all through the engine's public module functions.

mod common;

use common::detect_message_format;
use common::format::{detect_pkesk_algorithms, detect_seipd_v2_cipher};

use openpgp::crypto::SessionKey;
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper,
};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::types::{PublicKeyAlgorithm, SymmetricAlgorithm};
use pgp_mobile::keys::{self, KeyProfile};
use pgp_mobile::signature_details::SignatureVerificationState;
use pgp_mobile::{decrypt, encrypt, sign, verify};
use sequoia_openpgp as openpgp;

const PLAINTEXT: &[u8] = b"portable post-quantum message";

fn gen(profile: KeyProfile, name: &str) -> keys::GeneratedKey {
    keys::generate_key_with_profile(name.to_string(), None, None, profile)
        .expect("key gen should succeed")
}

/// Capture the negotiated symmetric algorithm at decrypt time. SEIPDv1
/// carries the cipher inside the encrypted session-key payload, so the
/// AES-256 floor there is only observable by actually decrypting.
struct SymAlgoCapture {
    cert: openpgp::Cert,
    algo: Option<SymmetricAlgorithm>,
}

impl VerificationHelper for SymAlgoCapture {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(vec![])
    }
    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        Ok(())
    }
}

impl DecryptionHelper for SymAlgoCapture {
    fn decrypt(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<openpgp::Cert>> {
        let policy = &StandardPolicy::new();
        for pkesk in pkesks {
            for ka in self
                .cert
                .keys()
                .with_policy(policy, None)
                .supported()
                .secret()
                .for_transport_encryption()
            {
                let mut keypair = ka.key().clone().into_keypair()?;
                if let Some((algo, session_key)) = pkesk.decrypt(&mut keypair, sym_algo) {
                    if decrypt(algo, &session_key) {
                        self.algo = algo.or(sym_algo);
                        return Ok(None);
                    }
                }
            }
        }
        Err(openpgp::anyhow::anyhow!("no matching key"))
    }
}

/// Decrypt with Sequoia directly to observe the negotiated cipher.
fn negotiated_cipher(ciphertext: &[u8], tsk_data: &[u8]) -> SymmetricAlgorithm {
    let cert = openpgp::Cert::from_bytes(tsk_data).expect("parse TSK");
    let policy = &StandardPolicy::new();
    let helper = SymAlgoCapture { cert, algo: None };
    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)
        .expect("builder")
        .with_policy(policy, None, helper)
        .expect("decrypt setup");
    let mut sink = Vec::new();
    std::io::copy(&mut decryptor, &mut sink).expect("decrypt stream");
    assert_eq!(sink, PLAINTEXT, "plaintext must round-trip");
    decryptor
        .helper_ref()
        .algo
        .expect("cipher must be observable at decrypt time")
}

#[test]
fn test_pq_only_message_uses_seipdv2_aes256() {
    let pq = gen(KeyProfile::PostQuantum, "PQ");
    let ct = encrypt::encrypt(PLAINTEXT, &[pq.public_key_data.clone()], None, None)
        .expect("encrypt to PQ recipient");

    let algos = detect_pkesk_algorithms(&ct);
    assert_eq!(algos, vec![PublicKeyAlgorithm::MLKEM768_X25519]);

    let (v1, v2) = detect_message_format(&ct);
    assert!(!v1 && v2, "PQ-only message must be SEIPDv2");

    let (cipher, _aead) = detect_seipd_v2_cipher(&ct).expect("v2 header");
    assert_eq!(
        cipher,
        SymmetricAlgorithm::AES256,
        "AES-256 floor for PQ recipients (RFC 9980)"
    );

    let out = decrypt::decrypt_detailed(&ct, &[pq.cert_data.clone()], &[]).expect("decrypt");
    assert_eq!(out.plaintext, PLAINTEXT);
}

#[test]
fn test_pq_plus_v4_mixed_uses_seipdv1_with_aes256_floor() {
    let pq = gen(KeyProfile::PostQuantum, "PQ");
    let v4 = gen(KeyProfile::Universal, "Classic");
    let ct = encrypt::encrypt(
        PLAINTEXT,
        &[pq.public_key_data.clone(), v4.public_key_data.clone()],
        None,
        None,
    )
    .expect("encrypt to mixed recipients");

    let algos = detect_pkesk_algorithms(&ct);
    assert_eq!(algos.len(), 2);
    assert!(algos.contains(&PublicKeyAlgorithm::MLKEM768_X25519));

    let (v1, v2) = detect_message_format(&ct);
    assert!(v1 && !v2, "mixed PQ + Legacy must fall back to SEIPDv1");

    // Both recipients decrypt through the engine.
    let via_pq = decrypt::decrypt_detailed(&ct, &[pq.cert_data.clone()], &[]).expect("pq");
    assert_eq!(via_pq.plaintext, PLAINTEXT);
    let via_v4 = decrypt::decrypt_detailed(&ct, &[v4.cert_data.clone()], &[]).expect("v4");
    assert_eq!(via_v4.plaintext, PLAINTEXT);

    // AES-256 floor holds even inside the SEIPDv1 container.
    assert_eq!(
        negotiated_cipher(&ct, &pq.cert_data),
        SymmetricAlgorithm::AES256,
        "AES-256 floor must hold for mixed PQ + v4 messages"
    );
}

#[test]
fn test_pq_plus_advanced_v6_uses_seipdv2_aes256() {
    let pq = gen(KeyProfile::PostQuantum, "PQ");
    let v6 = gen(KeyProfile::Advanced, "Modern");
    let ct = encrypt::encrypt(
        PLAINTEXT,
        &[pq.public_key_data.clone(), v6.public_key_data.clone()],
        None,
        None,
    )
    .expect("encrypt to PQ + Advanced");

    let (v1, v2) = detect_message_format(&ct);
    assert!(!v1 && v2, "all-v6 recipients must produce SEIPDv2");

    let (cipher, _aead) = detect_seipd_v2_cipher(&ct).expect("v2 header");
    assert_eq!(cipher, SymmetricAlgorithm::AES256);

    let via_pq = decrypt::decrypt_detailed(&ct, &[pq.cert_data.clone()], &[]).expect("pq");
    assert_eq!(via_pq.plaintext, PLAINTEXT);
    let via_v6 = decrypt::decrypt_detailed(&ct, &[v6.cert_data.clone()], &[]).expect("v6");
    assert_eq!(via_v6.plaintext, PLAINTEXT);
}

#[test]
fn test_pq_to_pq_message() {
    let alice = gen(KeyProfile::PostQuantum, "Alice PQ");
    let bob = gen(KeyProfile::PostQuantum, "Bob PQ");
    let ct = encrypt::encrypt(
        PLAINTEXT,
        &[alice.public_key_data.clone(), bob.public_key_data.clone()],
        None,
        None,
    )
    .expect("encrypt PQ to PQ");

    let algos = detect_pkesk_algorithms(&ct);
    assert_eq!(
        algos,
        vec![
            PublicKeyAlgorithm::MLKEM768_X25519,
            PublicKeyAlgorithm::MLKEM768_X25519
        ]
    );
    let (v1, v2) = detect_message_format(&ct);
    assert!(!v1 && v2);

    for key in [&alice, &bob] {
        let out = decrypt::decrypt_detailed(&ct, &[key.cert_data.clone()], &[]).expect("decrypt");
        assert_eq!(out.plaintext, PLAINTEXT);
    }
}

#[test]
fn test_pq_signed_and_encrypted_roundtrip() {
    let signer = gen(KeyProfile::PostQuantum, "PQ Signer");
    let recipient = gen(KeyProfile::PostQuantum, "PQ Recipient");

    let ct = encrypt::encrypt(
        PLAINTEXT,
        &[recipient.public_key_data.clone()],
        Some(&signer.cert_data),
        None,
    )
    .expect("sign+encrypt with PQ keys");

    let out = decrypt::decrypt_detailed(
        &ct,
        &[recipient.cert_data.clone()],
        &[signer.public_key_data.clone()],
    )
    .expect("decrypt+verify");
    assert_eq!(out.plaintext, PLAINTEXT);
    assert_eq!(out.summary_state, SignatureVerificationState::Verified);
}

#[test]
fn test_message_quantum_safety_classifies_by_pkesk_algorithms() {
    use pgp_mobile::decrypt::MessageQuantumSafety;

    let pq = gen(KeyProfile::PostQuantum, "PQ");
    let v4 = gen(KeyProfile::Universal, "Classic");

    let pq_only =
        encrypt::encrypt(PLAINTEXT, &[pq.public_key_data.clone()], None, None).expect("pq only");
    assert_eq!(
        decrypt::message_quantum_safety(&pq_only).expect("classify"),
        MessageQuantumSafety::FullyPostQuantum
    );

    let mixed = encrypt::encrypt(
        PLAINTEXT,
        &[pq.public_key_data.clone(), v4.public_key_data.clone()],
        None,
        None,
    )
    .expect("mixed");
    assert_eq!(
        decrypt::message_quantum_safety(&mixed).expect("classify"),
        MessageQuantumSafety::Mixed
    );

    let classical =
        encrypt::encrypt(PLAINTEXT, &[v4.public_key_data.clone()], None, None).expect("classical");
    assert_eq!(
        decrypt::message_quantum_safety(&classical).expect("classify"),
        MessageQuantumSafety::NonePostQuantum
    );

    // A truncated binary prefix (a streamed file's head) classifies
    // identically: parsing stops at the encrypted container, after the
    // PKESKs. The composite PKESK is ~1.2 KB, so 8 KiB safely covers all.
    let mixed_binary = encrypt::encrypt_binary(
        PLAINTEXT,
        &[pq.public_key_data.clone(), v4.public_key_data.clone()],
        None,
        None,
    )
    .expect("mixed binary");
    let prefix_len = mixed_binary.len().min(8192);
    assert_eq!(
        decrypt::message_quantum_safety(&mixed_binary[..prefix_len]).expect("prefix"),
        MessageQuantumSafety::Mixed
    );

    // A prefix truncated BEFORE the encrypted container — only the leading
    // session-key packets survive — must fail closed rather than return a
    // verdict computed from an unknown-completeness set of PKESKs. Re-serialize
    // just the PKESK packets (dropping the SEIP container) to build exactly
    // that input.
    let mut pkesks_only: Vec<u8> = Vec::new();
    let mut ppr =
        openpgp::parse::PacketParser::from_bytes(&mixed_binary).expect("reparse mixed binary");
    while let openpgp::parse::PacketParserResult::Some(pp) = ppr {
        if matches!(pp.packet, openpgp::Packet::SEIP(_)) {
            break;
        }
        if matches!(pp.packet, openpgp::Packet::PKESK(_)) {
            use openpgp::serialize::Serialize;
            pp.packet
                .serialize(&mut pkesks_only)
                .expect("serialize pkesk");
        }
        let (_, next) = pp.recurse().expect("recurse");
        ppr = next;
    }
    assert!(
        !pkesks_only.is_empty(),
        "expected at least one leading PKESK packet"
    );
    assert!(
        decrypt::message_quantum_safety(&pkesks_only).is_err(),
        "a container-less PKESK prefix must fail closed"
    );
}

#[test]
fn test_pq_cleartext_sign_verify_roundtrip() {
    let signer = gen(KeyProfile::PostQuantum, "PQ Signer");
    let text = b"post-quantum cleartext".to_vec();

    let signed = sign::sign_cleartext(&text, &signer.cert_data).expect("cleartext sign");
    let result = verify::verify_cleartext_detailed(&signed, &[signer.public_key_data.clone()])
        .expect("verify");
    assert_eq!(result.summary_state, SignatureVerificationState::Verified);
    assert!(!result.signatures.is_empty());
}
