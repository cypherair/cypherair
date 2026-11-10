//! Consumption bounds for the packet walks that read received input.
//!
//! Two walks read a message before anything about it has been authenticated:
//! the header walk the engine runs to learn a message's recipients and its
//! container; and the walk Sequoia runs inside `DecryptorBuilder::with_policy`
//! to reach the literal data. Sequoia installs a decompressor the moment it
//! parses a `CompressedData` header, so both walks read a stream that expands
//! up to 1032:1 per nested layer. An output-side ceiling cannot bound either
//! one: input that never yields a literal packet produces no output to count.
//!
//! So the bounds live here, on the consumption side, and each one is charged
//! before the walk reads *past* the packet it is charged for, which is what
//! makes them bounds rather than post-mortems. Sequoia produces an ordinary
//! packet by parsing its body, so one such body is always already read when its
//! charge is refused; that body is bounded by the parser's own
//! `max_packet_size`, 1 MiB by default. Total consumption is therefore the
//! budget plus that one packet, and everything a walk goes *on* to read
//! (container bodies, and the bodies of packets it skips) is bounded outright.
//! A bound that fires is `EngineError::LimitsExceeded`.

use std::fmt;

use openpgp::crypto::SessionKey;
use openpgp::packet::Tag;
use openpgp::packet::header::BodyLength;
use openpgp::parse::stream::{DecryptionHelper, MessageStructure, VerificationHelper};
use openpgp::parse::{Dearmor, PacketParser, PacketParserBuilder, PacketParserResult, Parse as _};
use openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp as openpgp;

use crate::EngineError;

/// Packets the header walk may consume.
///
/// This walk reads the session-key packets and stops. A message addressed to
/// more than a thousand recipients is not a message anybody composed, and this
/// is the bound that decides that question: the header walk runs first, so it
/// is the one a recipient meets.
const MAX_PREFIX_WALK_PACKETS: u32 = 1024;

/// Packets Sequoia's setup walk may consume.
///
/// Twice the header allowance, so that the two walks cannot split a verdict on
/// the same message. They count different packets: the header walk sees only
/// the session-key prefix, while this walk also sees the one-pass-signature,
/// signature, marker and padding packets around the literal data. Equal
/// allowances would make this the effective ceiling on recipients, and a lower
/// one would refuse messages the header walk had just accepted.
const MAX_SETUP_WALK_PACKETS: u32 = 2 * MAX_PREFIX_WALK_PACKETS;

/// Bytes the header walk may consume.
///
/// The walk stops at the encrypted container, so this covers the session-key
/// packets alone; the largest one is a v6 PKESK carrying an ML-KEM-1024
/// ciphertext, under 2 KiB. 4 MiB is well past `MAX_PREFIX_WALK_PACKETS` of
/// those. The bound is absolute because this walk stops before any payload: a
/// large input does not entitle a message to a larger header.
const MAX_PREFIX_WALK_BYTES: u64 = 4 * 1024 * 1024;

/// How deep the header walk may descend.
///
/// Session-key packets sit at the top level of an encrypted message. A
/// compressed message may hold one (`Compressed Message` is an `OpenPGP
/// Message` in RFC 9580's grammar), which is the single legitimate reason to
/// descend at all; deeper nesting is the decompression-bomb shape.
const MAX_PREFIX_WALK_DEPTH: u8 = 1;

/// How deep Sequoia's setup walk may descend.
///
/// The deepest shape a real producer emits is
/// `Compressed( PKESK, SEIP( Compressed( OPS, Literal, Sig ) ) )`, which
/// verifies at depth 3, one layer inside this bound. Each further layer below
/// the encryption container multiplies the expansion an attacker gets per byte
/// of input, so raising it buys nothing.
const MAX_SETUP_WALK_DEPTH: isize = 4;

/// Bytes Sequoia's setup walk may consume per byte of input, and the floor
/// below which the ratio stops applying.
///
/// This walk descends through decompression, so its bound is input-relative:
/// what it reads is the message's own framing, expanded. Every legitimate case
/// stays at or below the input size, so a factor of four is headroom. The floor
/// keeps a small input from being judged by a ratio of too little to carry any
/// framing.
///
/// That reasoning holds because every packet class `charge` counts is
/// incompressible in practice: key-exchange packets and signatures are
/// ciphertext, and Sequoia fills padding with random bytes. Adding a
/// compressible packet class to what `charge` counts would break it silently.
const MAX_SETUP_WALK_RATIO: u64 = 4;
const MIN_SETUP_WALK_BYTES: u64 = 1024 * 1024;

/// Plaintext Sequoia may buffer while building a decryptor.
///
/// Sequoia's default is 25 MiB: it decrypts and holds that much during
/// `with_policy`, while no output ceiling exists yet. No path of the engine
/// releases plaintext before the end, so the buffer buys nothing.
pub(crate) const SETUP_BUFFER_BYTES: usize = 64 * 1024;

/// A consumption bound fired. Its own type, so that it can be recognised after
/// the trip through Sequoia's error channel.
#[derive(Debug)]
struct Bound;

impl fmt::Display for Bound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a consumption bound fired")
    }
}

impl std::error::Error for Bound {}

impl Bound {
    /// Hand the bound to Sequoia as an `io::Error`.
    ///
    /// Sequoia returns a bound raised in `inspect` by one of two routes: as
    /// itself, when the walk runs under `with_policy`, or through
    /// `Decryptor::read`, which passes an inner `io::Error` on unchanged and
    /// boxes anything else into a wrapper that downcasts to nothing reachable.
    /// Wrapping here makes both routes deliver one shape: an `io::Error` whose
    /// `get_ref()` is a `Bound`.
    ///
    /// `ErrorKind::Other`, never `Interrupted`: readers in the stack retry that
    /// one, and a bound must not be retried.
    fn into_sequoia_error(self) -> openpgp::anyhow::Error {
        std::io::Error::other(self).into()
    }
}

/// Whether a Sequoia error chain carries a bound that fired.
///
/// It reaches through `get_ref()` rather than following `source()`, because an
/// `io::Error`'s `source()` skips the error it wraps.
pub(crate) fn is_bound(error: &openpgp::anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .and_then(|io_error| io_error.get_ref())
            .is_some_and(|inner| inner.is::<Bound>())
    })
}

/// What a walk may still consume. Both walks share it: they differ in how much
/// they may read and how deep they may go, never in what counts.
struct WalkBudget {
    packets: u32,
    bytes: u64,
    max_depth: isize,
}

impl WalkBudget {
    fn message_prefix() -> Self {
        Self {
            packets: MAX_PREFIX_WALK_PACKETS,
            bytes: MAX_PREFIX_WALK_BYTES,
            max_depth: isize::from(MAX_PREFIX_WALK_DEPTH),
        }
    }

    fn message_setup(input_bytes: u64) -> Self {
        Self {
            packets: MAX_SETUP_WALK_PACKETS,
            bytes: input_bytes
                .saturating_mul(MAX_SETUP_WALK_RATIO)
                .max(MIN_SETUP_WALK_BYTES),
            max_depth: MAX_SETUP_WALK_DEPTH,
        }
    }

    /// Charge one packet, before the walk reads past it.
    fn charge(&mut self, pp: &PacketParser) -> Result<(), Bound> {
        if pp.recursion_depth() > self.max_depth {
            return Err(Bound);
        }
        self.packets = self.packets.checked_sub(1).ok_or(Bound)?;

        if is_streamed(&pp.packet) {
            // A container the walk descends into is accounted for by the
            // packets inside it, and the literal data the walk stops at by the
            // output ceilings. Charging either here would double-count.
            return Ok(());
        }

        // Every other packet is one the walk skips over, and skipping means
        // reading the whole body, through the decompressor when the packet sits
        // inside a compressed container. A body that is not definitely sized
        // runs to the end of its level, so there is nothing to charge: RFC 9580
        // permits partial and indeterminate lengths only on the data packets
        // handled above.
        let BodyLength::Full(length) = pp.header().length() else {
            return Err(Bound);
        };
        self.bytes = self.bytes.checked_sub(u64::from(*length)).ok_or(Bound)?;
        Ok(())
    }
}

fn is_streamed(packet: &openpgp::Packet) -> bool {
    matches!(
        packet,
        openpgp::Packet::CompressedData(_) | openpgp::Packet::SEIP(_) | openpgp::Packet::Literal(_)
    )
}

// ── The header walk ─────────────────────────────────────────────────────

/// Where a header walk stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrefixEnd {
    /// The encrypted container was reached, so every session-key packet in the
    /// message has been seen.
    Container,
    /// A packet that cannot belong to an encrypted message's prefix: this is
    /// where a signed message or a certificate lands.
    Other,
    /// The input ran out first.
    End,
}

/// Walk the session-key packets of a message held in memory, up to and
/// including the encrypted container. `visit` sees each session-key packet and
/// the SEIP packet.
///
/// A container without authentication (the old tag-9 packet), or one this
/// engine cannot open (the withdrawn tag-20 AEAD packet, or an unknown SEIP
/// version), is `Unsupported`; so is a session-key packet of a version Sequoia
/// does not parse, because its decryptor cannot read past one.
pub(crate) fn walk_message_prefix<V>(message: &[u8], mut visit: V) -> Result<PrefixEnd, EngineError>
where
    V: FnMut(&openpgp::Packet),
{
    let mut ppr = PacketParserBuilder::from_bytes(message)
        .map_err(|_| EngineError::Malformed)?
        .dearmor(Dearmor::Auto(Default::default()))
        // The parser is told the depth the walk descends to, so that no later
        // edit to the loop can make it inflate a container by recursing.
        .max_recursion_depth(MAX_PREFIX_WALK_DEPTH)
        .build()
        .map_err(|_| EngineError::Malformed)?;
    let mut budget = WalkBudget::message_prefix();

    while let PacketParserResult::Some(pp) = ppr {
        match &pp.packet {
            openpgp::Packet::Unknown(packet) if matches!(packet.tag(), Tag::PKESK | Tag::SKESK) => {
                return Err(EngineError::Unsupported);
            }
            packet if matches!(packet.tag(), Tag::PKESK | Tag::SKESK) => {
                budget
                    .charge(&pp)
                    .map_err(|_| EngineError::LimitsExceeded)?;
                visit(&pp.packet);
            }
            // Ignorable by RFC 9580, and never the container: neither may stand
            // in for the proof that every session-key packet has been seen.
            openpgp::Packet::Marker(_) | openpgp::Packet::Padding(_) => {
                budget
                    .charge(&pp)
                    .map_err(|_| EngineError::LimitsExceeded)?;
            }
            openpgp::Packet::SEIP(_) => {
                visit(&pp.packet);
                return Ok(PrefixEnd::Container);
            }
            openpgp::Packet::CompressedData(_)
                if pp.recursion_depth() < isize::from(MAX_PREFIX_WALK_DEPTH) =>
            {
                budget
                    .charge(&pp)
                    .map_err(|_| EngineError::LimitsExceeded)?;
            }
            // A container this walk will not open. That is a bound firing, not
            // an absence of session-key packets.
            openpgp::Packet::CompressedData(_) => return Err(EngineError::LimitsExceeded),
            packet if matches!(packet.tag(), Tag::SED | Tag::AED | Tag::SEIP) => {
                return Err(EngineError::Unsupported);
            }
            // Returning here drops the parser without reading the packet.
            _ => return Ok(PrefixEnd::Other),
        }

        let (_, next) = pp.recurse().map_err(|_| EngineError::Malformed)?;
        ppr = next;
    }

    Ok(PrefixEnd::End)
}

// ── Sequoia's walk to the literal data ──────────────────────────────────

/// Charges Sequoia's own packet walk against a consumption budget.
///
/// `VerificationHelper::inspect` is called for every packet that walk parses,
/// before it reads past the packet, which makes it the one place the walk can
/// be bounded from outside Sequoia: `DecryptorBuilder` exposes no recursion or
/// consumption settings of its own.
pub(crate) struct BoundedHelper<H> {
    inner: H,
    budget: WalkBudget,
}

impl<H> BoundedHelper<H> {
    /// Bound the walk Sequoia will run over `input_bytes` of received input.
    pub(crate) fn new(inner: H, input_bytes: u64) -> Self {
        Self {
            inner,
            budget: WalkBudget::message_setup(input_bytes),
        }
    }

    pub(crate) fn into_inner(self) -> H {
        self.inner
    }
}

impl<H: VerificationHelper> VerificationHelper for BoundedHelper<H> {
    fn inspect(&mut self, pp: &PacketParser) -> openpgp::Result<()> {
        self.budget.charge(pp).map_err(Bound::into_sequoia_error)?;
        self.inner.inspect(pp)
    }

    fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        self.inner.get_certs(ids)
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        self.inner.check(structure)
    }
}

impl<H: DecryptionHelper> DecryptionHelper for BoundedHelper<H> {
    fn decrypt(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<openpgp::Cert>> {
        self.inner.decrypt(pkesks, skesks, sym_algo, decrypt)
    }
}
