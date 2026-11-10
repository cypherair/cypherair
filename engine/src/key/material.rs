//! Key material: the bounds every certificate, secret key and revocation is
//! read under, the engine's format for a portable secret, and armor.
//!
//! Sequoia parses key material without limits of its own beyond 1 MiB per
//! packet, and checks self-signatures as it goes. Every input here is first
//! held to a size and a packet count. A real certificate is a handful of
//! packets and a few kilobytes; a post-quantum one with several subkeys stays
//! under 100 KiB.
//!
//! The app has no web of trust. So certifications of a User ID by other keys
//! are dropped as a certificate is read: they are not counted, never reach
//! Sequoia's certificate code, and are not kept or passed on.

use openpgp::cert::prelude::*;
use openpgp::packet::Tag;
use openpgp::packet::key::{SecretParts, UnspecifiedRole};
use openpgp::parse::{Dearmor, PacketParserBuilder, PacketParserResult, Parse as _};
use openpgp::serialize::{Serialize as _, SerializeInto as _};
use openpgp::types::SignatureType;
use openpgp::{Packet, armor};
use sequoia_openpgp as openpgp;
use zeroize::Zeroizing;

use crate::error::contained;
use crate::{ArmorKind, EngineError};

/// The most bytes of key material, armored or binary, the engine reads.
const MAX_BYTES: usize = 1024 * 1024;
/// The most packets one piece of key material may hold.
const MAX_PACKETS: usize = 1024;

pub(crate) type SecretKey = openpgp::packet::Key<SecretParts, UnspecifiedRole>;

/// Read one certificate, public or with secrets.
///
/// Data that is not OpenPGP is `Malformed`; OpenPGP that is not one
/// certificate (a message, a signature, a keyring) is `WrongKind`; a key of a
/// version Sequoia does not read is `Unsupported`.
pub(crate) fn certificate(bytes: &[u8]) -> Result<Cert, EngineError> {
    let packets = packets(bytes, Certifications::OwnOnly)?;
    match packets.first() {
        Some(Packet::PublicKey(_) | Packet::SecretKey(_)) => {}
        Some(packet) if is_primary_key(packet.tag()) => return Err(EngineError::Unsupported),
        Some(_) => return Err(EngineError::WrongKind),
        None => return Err(EngineError::Malformed),
    }
    if packets[1..]
        .iter()
        .any(|packet| is_primary_key(packet.tag()))
    {
        return Err(EngineError::WrongKind);
    }
    Cert::from_packets(packets.into_iter()).map_err(|_| EngineError::Malformed)
}

/// Read a portable secret: the primary key's secret key packet, then one
/// secret subkey packet per subkey that has a secret, all unencrypted. The
/// engine writes this format and nothing else reads it, so any other shape is
/// `Malformed`.
pub(crate) fn secret_keys(bytes: &[u8]) -> Result<Vec<SecretKey>, EngineError> {
    let mut keys = Vec::new();
    for (index, packet) in packets(bytes, Certifications::All)?.into_iter().enumerate() {
        let key = match packet {
            Packet::SecretKey(key) if index == 0 => key.role_into_unspecified(),
            Packet::SecretSubkey(key) if index > 0 => key.role_into_unspecified(),
            _ => return Err(EngineError::Malformed),
        };
        if !key.has_unencrypted_secret() {
            return Err(EngineError::Malformed);
        }
        keys.push(key);
    }
    if keys.is_empty() {
        return Err(EngineError::Malformed);
    }
    Ok(keys)
}

/// Write the portable secret of a certificate that holds its secret keys. The
/// buffer gets its exact size first, so that it never reallocates and leaves
/// a copy of the secret behind.
pub(crate) fn write_secret_keys(cert: &Cert) -> Result<Zeroizing<Vec<u8>>, EngineError> {
    let packets: Vec<Packet> = cert
        .keys()
        .secret()
        .map(|key| {
            if key.primary() {
                Packet::SecretKey(key.key().clone().role_into_primary())
            } else {
                Packet::SecretSubkey(key.key().clone().role_into_subordinate())
            }
        })
        .collect();
    let size = packets.iter().map(|packet| packet.serialized_len()).sum();
    let mut secret = Zeroizing::new(Vec::with_capacity(size));
    for packet in &packets {
        packet
            .serialize(&mut *secret)
            .map_err(EngineError::internal)?;
    }
    debug_assert_eq!(secret.capacity(), size);
    Ok(secret)
}

/// Read a revocation: one signature that revokes a certificate.
pub(crate) fn revocation(bytes: &[u8]) -> Result<openpgp::packet::Signature, EngineError> {
    let mut packets = packets(bytes, Certifications::All)?;
    match (packets.pop(), packets.is_empty()) {
        (Some(Packet::Signature(signature)), true)
            if signature.typ() == SignatureType::KeyRevocation =>
        {
            Ok(signature)
        }
        (None, _) => Err(EngineError::Malformed),
        _ => Err(EngineError::WrongKind),
    }
}

/// Armor a certificate or a revocation.
///
/// A certificate is armored without any secret key material it may carry. A
/// revocation is armored as a public key block, as GnuPG writes one.
#[uniffi::export]
pub fn armor(kind: ArmorKind, data: Vec<u8>) -> Result<String, EngineError> {
    contained(|| {
        let armored = match kind {
            ArmorKind::Certificate => certificate(&data)?
                .strip_secret_key_material()
                .armored()
                .to_vec()
                .map_err(EngineError::internal)?,
            ArmorKind::Revocation => {
                let packet = Packet::from(revocation(&data)?);
                let mut armored = Vec::new();
                let mut writer = armor::Writer::new(&mut armored, armor::Kind::PublicKey)
                    .map_err(|_| EngineError::Internal)?;
                packet
                    .serialize(&mut writer)
                    .map_err(EngineError::internal)?;
                writer.finalize().map_err(|_| EngineError::Internal)?;
                armored
            }
        };
        String::from_utf8(armored).map_err(|_| EngineError::Internal)
    })
}

fn is_primary_key(tag: Tag) -> bool {
    matches!(tag, Tag::PublicKey | Tag::SecretKey)
}

/// Which certifications of a User ID a read keeps.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Certifications {
    All,
    /// Those that name no issuer or name the first packet's key; a
    /// certificate keeps no certification by another key.
    OwnOnly,
}

/// Read the packets of one piece of key material, within the bounds. The
/// parser does not descend into containers, which key material never holds.
/// A dropped certification costs one pass of the parser and is not counted.
fn packets(bytes: &[u8], certifications: Certifications) -> Result<Vec<Packet>, EngineError> {
    if bytes.len() > MAX_BYTES {
        return Err(EngineError::LimitsExceeded);
    }
    let mut ppr = PacketParserBuilder::from_bytes(bytes)
        .map_err(|_| EngineError::Malformed)?
        .dearmor(Dearmor::Auto(Default::default()))
        .max_recursion_depth(0)
        .build()
        .map_err(|_| EngineError::Malformed)?;
    let mut packets: Vec<Packet> = Vec::new();
    while let PacketParserResult::Some(pp) = ppr {
        let (packet, next) = pp.next().map_err(|_| EngineError::Malformed)?;
        ppr = next;
        if certifications == Certifications::OwnOnly
            && packets
                .first()
                .is_some_and(|first| certified_by_another(&packet, first))
        {
            continue;
        }
        if packets.len() == MAX_PACKETS {
            return Err(EngineError::LimitsExceeded);
        }
        packets.push(packet);
    }
    Ok(packets)
}

/// A certification of a User ID that names an issuer, none of them `first`'s
/// key. A signature without an issuer stays: Sequoia may find it to be a
/// self-signature.
fn certified_by_another(packet: &Packet, first: &Packet) -> bool {
    let Packet::Signature(signature) = packet else {
        return false;
    };
    let primary = match first {
        Packet::PublicKey(key) => key.key_handle(),
        Packet::SecretKey(key) => key.key_handle(),
        _ => return false,
    };
    let issuers = signature.get_issuers();
    matches!(
        signature.typ(),
        SignatureType::GenericCertification
            | SignatureType::PersonaCertification
            | SignatureType::CasualCertification
            | SignatureType::PositiveCertification
    ) && !issuers.is_empty()
        && !issuers.iter().any(|issuer| issuer.aliases(&primary))
}
