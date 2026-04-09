//! Shared test utilities for pgp-mobile integration tests.

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

/// Flip a bit near the very end of the encrypted payload to target the auth/integrity trailer.
///
/// This is more stable than a midpoint bit-flip for tests that want to exercise
/// AEAD/MDC failure paths without corrupting packet headers or session-key packets.
#[allow(dead_code)]
pub fn tamper_near_payload_tail(ciphertext: &[u8]) -> Vec<u8> {
    let mut tampered = ciphertext.to_vec();
    let tamper_pos = tampered.len().saturating_sub(8);
    tampered[tamper_pos] ^= 0x01;
    tampered
}
