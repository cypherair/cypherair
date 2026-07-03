//! Message format inspection helpers for integration tests.

use openpgp::parse::Parse;
use sequoia_openpgp as openpgp;

/// Detect whether binary ciphertext uses SEIPDv1 or SEIPDv2.
/// Uses PacketParser to inspect packet headers without fully decrypting.
/// Returns (has_seipd_v1, has_seipd_v2).
#[allow(dead_code)]
pub fn detect_message_format(ciphertext: &[u8]) -> (bool, bool) {
    let mut has_v1 = false;
    let mut has_v2 = false;
    let mut ppr =
        openpgp::parse::PacketParser::from_bytes(ciphertext).expect("Should parse ciphertext");
    while let openpgp::parse::PacketParserResult::Some(pp) = ppr {
        match &pp.packet {
            openpgp::Packet::SEIP(seip) => {
                if seip.version() == 1 {
                    has_v1 = true;
                } else if seip.version() == 2 {
                    has_v2 = true;
                }
            }
            _ => {}
        }
        let (_, next) = pp.next().expect("Should advance");
        ppr = next;
    }
    (has_v1, has_v2)
}

/// Collect the versions of every PKESK (public-key encrypted session key) packet.
/// v3 is the classic ECDH shape GnuPG emits for the SE-compatible v4 certificate;
/// v6 is the RFC 9580 shape. Inspects packet headers without decrypting.
#[allow(dead_code)]
pub fn detect_pkesk_versions(ciphertext: &[u8]) -> Vec<u8> {
    let mut versions = Vec::new();
    let mut ppr =
        openpgp::parse::PacketParser::from_bytes(ciphertext).expect("Should parse ciphertext");
    while let openpgp::parse::PacketParserResult::Some(pp) = ppr {
        if let openpgp::Packet::PKESK(pkesk) = &pp.packet {
            versions.push(pkesk.version());
        }
        let (_, next) = pp.next().expect("Should advance");
        ppr = next;
    }
    versions
}

/// Collect the public-key algorithm of every PKESK packet.
/// Distinguishes composite RFC 9980 recipients (MLKEM768_X25519) from
/// classical ECDH/X25519 recipients without decrypting.
#[allow(dead_code)]
pub fn detect_pkesk_algorithms(ciphertext: &[u8]) -> Vec<openpgp::types::PublicKeyAlgorithm> {
    let mut algorithms = Vec::new();
    let mut ppr =
        openpgp::parse::PacketParser::from_bytes(ciphertext).expect("Should parse ciphertext");
    while let openpgp::parse::PacketParserResult::Some(pp) = ppr {
        match &pp.packet {
            openpgp::Packet::PKESK(openpgp::packet::PKESK::V3(p)) => algorithms.push(p.pk_algo()),
            openpgp::Packet::PKESK(openpgp::packet::PKESK::V6(p)) => algorithms.push(p.pk_algo()),
            _ => {}
        }
        let (_, next) = pp.next().expect("Should advance");
        ppr = next;
    }
    algorithms
}

/// Read the cleartext cipher/AEAD declaration of a SEIPDv2 container.
/// Returns None for SEIPDv1 messages (v1 carries the cipher inside the
/// encrypted session-key payload, not in a packet header).
#[allow(dead_code)]
pub fn detect_seipd_v2_cipher(
    ciphertext: &[u8],
) -> Option<(
    openpgp::types::SymmetricAlgorithm,
    openpgp::types::AEADAlgorithm,
)> {
    let mut ppr =
        openpgp::parse::PacketParser::from_bytes(ciphertext).expect("Should parse ciphertext");
    while let openpgp::parse::PacketParserResult::Some(pp) = ppr {
        if let openpgp::Packet::SEIP(openpgp::packet::SEIP::V2(seip)) = &pp.packet {
            return Some((seip.symmetric_algo(), seip.aead()));
        }
        let (_, next) = pp.next().expect("Should advance");
        ppr = next;
    }
    None
}
