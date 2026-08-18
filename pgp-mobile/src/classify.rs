//! What a blob of OpenPGP bytes actually is.
//!
//! A file arriving from outside the app carries a name its producer chose and
//! bytes that may say something else entirely — a revocation certificate is
//! armored as `PUBLIC KEY BLOCK`, a `.sig` may hold anything, and `.asc` is
//! only a claim that the content is armored. Deciding the kind therefore means
//! reading the packets, which is this crate's job rather than the app's: the
//! answer comes from the same parser every other route uses, not from a second
//! OpenPGP reader written in Swift.
//!
//! The walk reads packet *headers* and stops at the first packet that settles
//! the question, so it never reads a payload and never decrypts. It descends at
//! most one container, because a compressed message is the only legitimate
//! wrapper around the packet that decides.

use openpgp::packet::Signature;
use openpgp::parse::{Dearmor, PacketParserBuilder, PacketParserResult, Parse as _};
use openpgp::types::SignatureType;
use sequoia_openpgp as openpgp;

use crate::error::PgpError;

/// The OpenPGP object a blob holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum OpenPgpDataKind {
    /// A transferable public key: a certificate, and the only kind a contact
    /// import accepts.
    PublicCertificate,
    /// A transferable secret key, whatever protection its secrets carry.
    SecretKey,
    /// An encrypted message, addressed to certificates or to a password.
    Ciphertext,
    /// A signed message that carries the data it signs — the cleartext
    /// signature framework, or a one-pass-signed message — so verifying it
    /// needs nothing else.
    SignedMessage,
    /// A bare signature over data held somewhere else.
    DetachedSignature,
    /// A bare revocation signature, produced to retire a key rather than to
    /// attest to a message.
    RevocationCertificate,
}

/// Packets the walk may read before one of them settles the kind.
///
/// Only markers and padding are walked past, and a producer emits neither more
/// than once. The allowance exists so that a file made entirely of them ends as
/// a refusal instead of a scan of its whole length.
const MAX_INDECISIVE_PACKETS: u32 = 8;

/// Containers the walk may open.
///
/// A compressed message may wrap the signature or literal packets that decide,
/// and nothing legitimate wraps that in turn.
const MAX_RECURSION_DEPTH: u8 = 1;

/// The header that opens the cleartext signature framework.
const CLEARTEXT_FRAMEWORK_HEADER: &[u8] = b"-----BEGIN PGP SIGNED MESSAGE-----";

/// Decide what `data` is from its packets.
///
/// Fails when the bytes are not OpenPGP at all, or hold something no route in
/// the app can act on: the caller has an opened file to answer for either way,
/// and an error is the answer.
pub fn classify_openpgp_data(data: &[u8]) -> Result<OpenPgpDataKind, PgpError> {
    // Checked before parsing, and by shape rather than by the parser: Sequoia's
    // armor reader walks the cleartext framework's plaintext to reach the
    // trailing signature block, which would present a signed message as the
    // detached signature that is only part of it.
    if begins_cleartext_framework(data) {
        return Ok(OpenPgpDataKind::SignedMessage);
    }

    let mut ppr = PacketParserBuilder::from_bytes(data)
        .and_then(|builder| {
            builder
                // Armored and binary input both arrive here.
                .dearmor(Dearmor::Auto(Default::default()))
                .max_recursion_depth(MAX_RECURSION_DEPTH)
                .build()
        })
        .map_err(unrecognized)?;

    let mut walked: u32 = 0;
    while let PacketParserResult::Some(packet_parser) = ppr {
        match &packet_parser.packet {
            openpgp::Packet::PublicKey(_) => return Ok(OpenPgpDataKind::PublicCertificate),
            openpgp::Packet::SecretKey(_) => return Ok(OpenPgpDataKind::SecretKey),
            openpgp::Packet::PKESK(_) | openpgp::Packet::SKESK(_) | openpgp::Packet::SEIP(_) => {
                return Ok(OpenPgpDataKind::Ciphertext)
            }
            openpgp::Packet::OnePassSig(_) => return Ok(OpenPgpDataKind::SignedMessage),
            openpgp::Packet::Signature(signature) => return Ok(bare_signature_kind(signature)),
            // Ignorable by RFC 9580, and a compressed container is opened
            // rather than answered: what it wraps is what the file is.
            openpgp::Packet::Marker(_)
            | openpgp::Packet::Padding(_)
            | openpgp::Packet::CompressedData(_) => {}
            // Literal data, a stray subkey, an unknown packet: OpenPGP the
            // parser could read, and nothing the app opens files to do.
            _ => break,
        }

        walked += 1;
        if walked >= MAX_INDECISIVE_PACKETS {
            return Err(PgpError::MessageLimitsExceeded {
                reason: format!(
                    "File carries more than {MAX_INDECISIVE_PACKETS} packets \
                     before anything that identifies it"
                ),
            });
        }

        // `recurse` rather than `next`: descending into a compressed container
        // reads its header, while stepping over it would inflate the whole
        // body to find where it ends.
        let (_, next) = packet_parser.recurse().map_err(unrecognized)?;
        ppr = next;
    }

    Err(PgpError::CorruptData {
        reason: "File holds no OpenPGP certificate, message or signature".to_string(),
    })
}

/// What a signature standing on its own is for.
///
/// A revocation retires a key and is the one bare signature that means
/// something without other data; every other kind attests to data held
/// elsewhere, which is what makes it detached.
fn bare_signature_kind(signature: &Signature) -> OpenPgpDataKind {
    match signature.typ() {
        SignatureType::KeyRevocation
        | SignatureType::SubkeyRevocation
        | SignatureType::CertificationRevocation => OpenPgpDataKind::RevocationCertificate,
        _ => OpenPgpDataKind::DetachedSignature,
    }
}

fn begins_cleartext_framework(data: &[u8]) -> bool {
    let data = data.strip_prefix("\u{FEFF}".as_bytes()).unwrap_or(data);
    let start = data
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(data.len());
    data[start..].starts_with(CLEARTEXT_FRAMEWORK_HEADER)
}

fn unrecognized(error: openpgp::anyhow::Error) -> PgpError {
    PgpError::CorruptData {
        reason: format!("File is not readable OpenPGP data: {error}"),
    }
}
