//! Messages built with Sequoia directly, for the cases the engine never
//! writes: crafted contents inside a valid container, hidden recipients, keys
//! that are expired now.

use std::io::{Read, Write};
use std::time::SystemTime;

use openpgp::cert::prelude::*;
use openpgp::crypto::{KeyPair, SessionKey};
use openpgp::packet::{PKESK, SKESK};
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, MessageLayer, MessageStructure, VerificationHelper,
};
use openpgp::parse::{PacketParser, PacketParserResult, Parse};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::SerializeInto;
use openpgp::serialize::stream::{
    Compressor, Encryptor, LiteralWriter, Message, Recipient, Signer,
};
use openpgp::types::{AEADAlgorithm, CompressionAlgorithm, SymmetricAlgorithm};
use openpgp::{Cert, KeyHandle, Packet};
use sequoia_openpgp as openpgp;

static POLICY: StandardPolicy = StandardPolicy::new();

/// Binary from armored or binary.
pub fn binary(message: &[u8]) -> Vec<u8> {
    let mut reader =
        openpgp::armor::Reader::from_bytes(message, openpgp::armor::ReaderMode::Tolerant(None));
    let mut binary = Vec::new();
    reader.read_to_end(&mut binary).unwrap();
    binary
}

/// Where the encrypted container starts: the length of the session-key packets
/// before it, as Sequoia writes them.
pub fn container_offset(binary: &[u8]) -> usize {
    let mut offset = 0;
    let mut ppr = PacketParser::from_bytes(binary).unwrap();
    while let PacketParserResult::Some(pp) = ppr {
        if matches!(pp.packet, Packet::SEIP(_)) {
            return offset;
        }
        let (packet, next) = pp.next().unwrap();
        offset += packet.to_vec().unwrap().len();
        ppr = next;
    }
    panic!("no encrypted container")
}

/// Where each session-key packet ends, as Sequoia writes them.
pub fn session_key_packet_ends(binary: &[u8]) -> Vec<usize> {
    let mut ends = Vec::new();
    let mut offset = 0;
    let mut ppr = PacketParser::from_bytes(binary).unwrap();
    while let PacketParserResult::Some(pp) = ppr {
        if matches!(pp.packet, Packet::SEIP(_)) {
            return ends;
        }
        let (packet, next) = pp.next().unwrap();
        offset += packet.to_vec().unwrap().len();
        ends.push(offset);
        ppr = next;
    }
    panic!("no encrypted container")
}

/// A literal data packet holding `text`.
pub fn literal(text: &[u8]) -> Vec<u8> {
    let mut sink = Vec::new();
    let mut writer = LiteralWriter::new(Message::new(&mut sink)).build().unwrap();
    writer.write_all(text).unwrap();
    writer.finalize().unwrap();
    sink
}

/// A compressed data packet holding `inner`.
pub fn compressed(inner: &[u8]) -> Vec<u8> {
    let mut sink = Vec::new();
    let mut writer = Compressor::new(Message::new(&mut sink))
        .algo(CompressionAlgorithm::Zip)
        .build()
        .unwrap();
    writer.write_all(inner).unwrap();
    writer.finalize().unwrap();
    sink
}

/// A padding packet of `length` zero bytes.
pub fn padding(length: u32) -> Vec<u8> {
    let mut packet = vec![0xC0 | 21, 0xFF];
    packet.extend_from_slice(&length.to_be_bytes());
    packet.resize(packet.len() + length as usize, 0);
    packet
}

/// A message signed by each of `signers` around a literal packet of `text`,
/// unencrypted.
pub fn signed(text: &[u8], signers: Vec<KeyPair>) -> Vec<u8> {
    let mut sink = Vec::new();
    let mut signers = signers.into_iter();
    let mut signer = Signer::new(Message::new(&mut sink), signers.next().unwrap()).unwrap();
    for other in signers {
        signer = signer.add_signer(other).unwrap();
    }
    let mut writer = LiteralWriter::new(signer.build().unwrap()).build().unwrap();
    writer.write_all(text).unwrap();
    writer.finalize().unwrap();
    sink
}

/// A message signed by `signer` around a literal packet of `text`,
/// unencrypted, with the signature dated `created` and valid for `validity`.
pub fn signed_at(
    text: &[u8],
    signer: KeyPair,
    created: SystemTime,
    validity: Option<std::time::Duration>,
) -> Vec<u8> {
    let mut template =
        openpgp::packet::signature::SignatureBuilder::new(openpgp::types::SignatureType::Binary);
    if let Some(validity) = validity {
        template = template.set_signature_validity_period(validity).unwrap();
    }
    let mut sink = Vec::new();
    let signer = Signer::with_template(Message::new(&mut sink), signer, template)
        .unwrap()
        .creation_time(created)
        .build()
        .unwrap();
    let mut writer = LiteralWriter::new(signer).build().unwrap();
    writer.write_all(text).unwrap();
    writer.finalize().unwrap();
    sink
}

/// `signed` with the signature value of `issuer`'s signature corrupted.
pub fn corrupt_signature(signed: &[u8], issuer: &Cert) -> Vec<u8> {
    let pile = openpgp::PacketPile::from_bytes(signed).unwrap();
    let mut corrupted = Vec::new();
    for packet in pile.into_children() {
        let mut bytes = packet.to_vec().unwrap();
        if let Packet::Signature(signature) = &packet {
            let by_issuer = signature.get_issuers().iter().any(|handle| {
                issuer
                    .keys()
                    .any(|key| handle.aliases(key.key().key_handle()))
            });
            if by_issuer {
                let position = bytes.len() - 10;
                bytes[position] ^= 0x01;
            }
        }
        corrupted.extend_from_slice(&bytes);
    }
    corrupted
}

/// A signing key pair of a certificate with secrets, as it was at `at`.
pub fn signing_pair(cert: &Cert, at: SystemTime) -> KeyPair {
    cert.keys()
        .with_policy(&POLICY, at)
        .secret()
        .for_signing()
        .next()
        .unwrap()
        .key()
        .clone()
        .into_keypair()
        .unwrap()
}

/// A binary message whose container holds `inner`, encrypted to the
/// certificates' encryption keys as they were at `at`; with `hidden`, the
/// session-key packets name no recipient.
pub fn encrypted_raw(recipients: &[&Cert], inner: &[u8], at: SystemTime, hidden: bool) -> Vec<u8> {
    let recipients: Vec<_> = recipients.iter().map(|cert| (*cert, hidden)).collect();
    encrypted_mixed(&recipients, inner, at)
}

/// `encrypted_raw` with a choice per recipient whose packet is hidden, in the
/// order given.
pub fn encrypted_mixed(recipients: &[(&Cert, bool)], inner: &[u8], at: SystemTime) -> Vec<u8> {
    let valid: Vec<_> = recipients
        .iter()
        .map(|(cert, hidden)| (cert.with_policy(&POLICY, at).unwrap(), *hidden))
        .collect();
    let mut keys = Vec::new();
    for (valid, hidden) in &valid {
        for key in valid.keys().for_transport_encryption() {
            let features = valid.features();
            keys.push(if *hidden {
                Recipient::new(features, None::<KeyHandle>, key.key())
            } else {
                Recipient::from(key)
            });
        }
    }
    let mut sink = Vec::new();
    let mut message = Encryptor::for_recipients(Message::new(&mut sink), keys)
        .build()
        .unwrap();
    message.write_all(inner).unwrap();
    message.finalize().unwrap();
    sink
}

/// What a message is, read by Sequoia with the recipient's secret keys.
#[derive(Debug, PartialEq, Eq)]
pub struct Layers {
    pub compressed: bool,
    pub cipher: SymmetricAlgorithm,
    pub aead: Option<AEADAlgorithm>,
}

pub fn layers(message: &[u8], recipient: &Cert) -> Layers {
    struct Helper<'a> {
        recipient: &'a Cert,
        layers: Option<Layers>,
    }
    impl VerificationHelper for Helper<'_> {
        fn get_certs(&mut self, _: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
            Ok(Vec::new())
        }
        fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
            let mut layers = Layers {
                compressed: false,
                cipher: SymmetricAlgorithm::Unencrypted,
                aead: None,
            };
            for layer in structure.into_iter() {
                match layer {
                    MessageLayer::Compression { .. } => layers.compressed = true,
                    MessageLayer::Encryption {
                        sym_algo,
                        aead_algo,
                    } => {
                        layers.cipher = sym_algo;
                        layers.aead = aead_algo;
                    }
                    MessageLayer::SignatureGroup { .. } => {}
                }
            }
            self.layers = Some(layers);
            Ok(())
        }
    }
    impl DecryptionHelper for Helper<'_> {
        fn decrypt(
            &mut self,
            pkesks: &[PKESK],
            _: &[SKESK],
            sym_algo: Option<SymmetricAlgorithm>,
            decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
        ) -> openpgp::Result<Option<Cert>> {
            for key in self.recipient.keys().secret() {
                let mut pair = key.key().clone().into_keypair()?;
                for pkesk in pkesks {
                    if let Some((algo, session_key)) = pkesk.decrypt(&mut pair, sym_algo)
                        && decrypt(algo, &session_key)
                    {
                        return Ok(None);
                    }
                }
            }
            Err(openpgp::anyhow::anyhow!("no key"))
        }
    }

    let helper = Helper {
        recipient,
        layers: None,
    };
    let mut decryptor = DecryptorBuilder::from_bytes(message)
        .unwrap()
        .with_policy(&POLICY, None, helper)
        .unwrap();
    std::io::copy(&mut decryptor, &mut std::io::sink()).unwrap();
    decryptor.into_helper().layers.unwrap()
}
