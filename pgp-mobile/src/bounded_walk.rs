//! Consumption bounds for the packet walks that read received input.
//!
//! Two walks read a message before anything about it has been authenticated:
//! the phase-1 header walk the app runs to learn a message's recipients, its
//! quantum safety, or its password packets; and the walk Sequoia runs inside
//! `DecryptorBuilder::with_policy` / `VerifierBuilder::with_policy` to reach the
//! literal data. Sequoia installs a decompressor the moment it parses a
//! `CompressedData` header, so both walks read a stream that expands up to
//! 1032:1 per nested layer. An output-side ceiling cannot bound either one:
//! input that never yields a literal packet produces no output bytes to count.
//!
//! So the bounds live here, on the consumption side, and each one is charged
//! *before* the bytes it guards are read. Exceeding one fails closed with
//! `PgpError::MessageLimitsExceeded`.

use std::fmt;
use std::io::Read;

use openpgp::crypto::SessionKey;
use openpgp::packet::header::BodyLength;
use openpgp::parse::stream::{DecryptionHelper, MessageStructure, VerificationHelper};
use openpgp::parse::{Dearmor, PacketParser, PacketParserBuilder, PacketParserResult, Parse as _};
use openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp as openpgp;

use crate::error::PgpError;

/// Packets a walk over unauthenticated input may consume.
///
/// The walks bounded here read a message's framing, never its payload: the
/// session-key packets, the one-pass-signature and signature packets around the
/// literal data, and the ignorable marker and padding packets. A message that
/// needs more than a thousand of those is not a message anybody composed.
const MAX_WALK_PACKETS: u32 = 1024;

/// Bytes a phase-1 header walk may consume.
///
/// The walk stops at the encrypted container, so this covers the session-key
/// packets alone; the largest one we can receive is a v6 PKESK carrying an
/// ML-KEM-1024 ciphertext, under 2 KiB. 4 MiB is well past `MAX_WALK_PACKETS`
/// of those and still bounds the read a crafted file can provoke. The bound is
/// absolute rather than input-relative because this walk stops before any
/// payload: a large input does not entitle a message to a larger header.
const MAX_PREFIX_WALK_BYTES: u64 = 4 * 1024 * 1024;

/// How deep the phase-1 header walk may descend.
///
/// Session-key packets sit at the top level of an encrypted message. A
/// compressed message may in turn hold one (`Compressed Message` is an
/// `OpenPGP Message` in RFC 9580's grammar), which is the single legitimate
/// reason to descend at all; deeper nesting is the decompression-bomb shape
/// rather than a message, so the walk stops there instead of inflating it.
const MAX_PREFIX_WALK_DEPTH: u8 = 1;

/// How deep Sequoia's setup walk may descend before we refuse the message.
///
/// Producers nest two containers at most — an encryption container over a
/// compression container — putting the literal data at depth 2. Each further
/// layer multiplies the expansion an attacker gets per input byte, so the
/// headroom here is deliberately small.
const MAX_SETUP_WALK_DEPTH: isize = 4;

/// Bytes Sequoia's setup walk may consume per byte of input, and the floor
/// below which the ratio stops applying.
///
/// This walk *does* descend through decompression, so its bound is honestly
/// input-relative: what it reads is the message's own framing, expanded. Every
/// legitimate case stays at or below the input size — the framing of an
/// encrypted message is a fraction of its ciphertext, a detached signature file
/// is framing throughout, and Padmé padding adds at most 12% — so a factor of
/// four is headroom rather than a guess. The floor keeps a small input from
/// being judged by a ratio of something too small to carry framing at all.
const MAX_SETUP_WALK_RATIO: u64 = 4;
const MIN_SETUP_WALK_BYTES: u64 = 1024 * 1024;

/// Plaintext Sequoia may buffer while building a decryptor or verifier.
///
/// Sequoia's default is 25 MiB: it decrypts and holds that much of the payload
/// during `with_policy`, so that a short message is fully verified before any
/// of it is released. Neither of our paths releases plaintext incrementally —
/// the in-memory path returns a fully-read buffer, the file path renames a temp
/// file only after a complete decrypt — so all that buffer buys us is a 25 MiB
/// allocation and 25 MiB of decompression performed while no output ceiling
/// exists yet.
pub(crate) const SETUP_BUFFER_BYTES: usize = 64 * 1024;

/// A consumption bound fired. Its own type so that it survives the trip through
/// Sequoia's `anyhow` error channel, which is how the setup walk reports.
#[derive(Debug)]
pub(crate) struct WalkBoundExceeded {
    reason: String,
}

impl fmt::Display for WalkBoundExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for WalkBoundExceeded {}

impl From<WalkBoundExceeded> for PgpError {
    fn from(exceeded: WalkBoundExceeded) -> Self {
        PgpError::MessageLimitsExceeded {
            reason: exceeded.reason,
        }
    }
}

/// Recover a consumption bound from a Sequoia error chain.
///
/// The setup walk reports through `VerificationHelper::inspect`, so the bound
/// comes back wrapped in `anyhow` — and, when that walk runs from `Decryptor`'s
/// `Read` impl rather than from `with_policy`, inside an `io::Error` as well.
/// An `io::Error`'s `source()` skips the error it wraps, so the chain walk
/// steps through `get_ref()` explicitly.
pub(crate) fn walk_bound_error(error: &openpgp::anyhow::Error) -> Option<PgpError> {
    error
        .chain()
        .find_map(bound_in_error_chain)
        .map(|exceeded| PgpError::MessageLimitsExceeded {
            reason: exceeded.reason.clone(),
        })
}

fn bound_in_error_chain<'e>(
    error: &'e (dyn std::error::Error + 'static),
) -> Option<&'e WalkBoundExceeded> {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(exceeded) = error.downcast_ref::<WalkBoundExceeded>() {
            return Some(exceeded);
        }
        current = match error
            .downcast_ref::<std::io::Error>()
            .and_then(|io_error| io_error.get_ref())
        {
            Some(inner) => Some(inner as &(dyn std::error::Error + 'static)),
            None => error.source(),
        };
    }
    None
}

/// What a walk may still consume.
///
/// One accounting primitive for both walks: they differ in how much they are
/// allowed and how deep they may go, never in what counts.
struct WalkBudget {
    packets: u32,
    bytes: u64,
    max_depth: isize,
}

impl WalkBudget {
    /// The budget for a phase-1 header walk.
    fn message_prefix() -> Self {
        Self {
            packets: MAX_WALK_PACKETS,
            bytes: MAX_PREFIX_WALK_BYTES,
            max_depth: isize::from(MAX_PREFIX_WALK_DEPTH),
        }
    }

    /// The budget for Sequoia's walk to the literal data, over `input_bytes` of
    /// received input.
    fn message_setup(input_bytes: u64) -> Self {
        Self {
            packets: MAX_WALK_PACKETS,
            bytes: input_bytes
                .saturating_mul(MAX_SETUP_WALK_RATIO)
                .max(MIN_SETUP_WALK_BYTES),
            max_depth: MAX_SETUP_WALK_DEPTH,
        }
    }

    /// Charge one packet, before the walk reads past it.
    fn charge(&mut self, pp: &PacketParser) -> Result<(), WalkBoundExceeded> {
        let depth = pp.recursion_depth();
        if depth > self.max_depth {
            return Err(WalkBoundExceeded {
                reason: format!(
                    "Message nests packets {depth} containers deep, past the maximum of {}",
                    self.max_depth
                ),
            });
        }

        self.packets = self.packets.checked_sub(1).ok_or_else(|| WalkBoundExceeded {
            reason: format!(
                "Message carries more than {MAX_WALK_PACKETS} packets before its payload"
            ),
        })?;

        if is_streamed(&pp.packet) {
            // A container the walk descends into is accounted for by the
            // packets inside it, and the literal data the walk stops at is
            // accounted for by the output ceilings. Charging either here would
            // double-count.
            return Ok(());
        }

        // Every other packet is one the walk skips over, and skipping means
        // reading the whole body — through the decompressor, when the packet
        // sits inside a compressed container. A body that is not definitely
        // sized runs to the end of its level, so there is nothing to charge and
        // no reason to indulge it: RFC 9580 permits partial and indeterminate
        // lengths only on the data packets handled above.
        let BodyLength::Full(length) = pp.header().length() else {
            return Err(WalkBoundExceeded {
                reason: format!(
                    "Message declares an unbounded {} packet outside its payload",
                    pp.packet.tag()
                ),
            });
        };

        self.bytes = self
            .bytes
            .checked_sub(u64::from(*length))
            .ok_or_else(|| WalkBoundExceeded {
                reason: "Message consumes more than the maximum expansion for its size".to_string(),
            })?;

        Ok(())
    }
}

/// Whether a packet's body is streamed by the walk rather than skipped over.
fn is_streamed(packet: &openpgp::Packet) -> bool {
    matches!(
        packet,
        openpgp::Packet::CompressedData(_) | openpgp::Packet::SEIP(_) | openpgp::Packet::Literal(_)
    )
}

// ── Phase 1: the header walk ───────────────────────────────────────────

/// Where a header walk stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrefixEnd {
    /// The encrypted container was reached, so every session-key packet in the
    /// message has been seen.
    Container,
    /// The walk ended without reaching a container: the input ran out, or a
    /// packet that cannot belong to a session-key sequence closed it.
    NoContainer,
}

/// Walk the session-key packets of a message held in memory.
pub(crate) fn walk_message_prefix_bytes<V>(
    ciphertext: &[u8],
    visit: V,
) -> Result<PrefixEnd, PgpError>
where
    V: FnMut(&openpgp::Packet) -> Result<(), PgpError>,
{
    let builder = PacketParserBuilder::from_bytes(ciphertext).map_err(parse_failure)?;
    walk_message_prefix(build_prefix_parser(builder)?, visit)
}

/// Walk the session-key packets of a message read from a file.
pub(crate) fn walk_message_prefix_reader<'a, R, V>(
    reader: R,
    visit: V,
) -> Result<PrefixEnd, PgpError>
where
    R: Read + Send + Sync + 'a,
    V: FnMut(&openpgp::Packet) -> Result<(), PgpError>,
{
    let builder = PacketParserBuilder::from_reader(reader).map_err(parse_failure)?;
    walk_message_prefix(build_prefix_parser(builder)?, visit)
}

fn parse_failure(error: openpgp::anyhow::Error) -> PgpError {
    PgpError::CorruptData {
        reason: format!("Failed to parse message: {error}"),
    }
}

fn build_prefix_parser(builder: PacketParserBuilder<'_>) -> Result<PacketParserResult<'_>, PgpError> {
    builder
        // Both binary and ASCII-armored input reach these routes.
        .dearmor(Dearmor::Auto(Default::default()))
        // The walk descends no further than it needs to, and the parser is told
        // the same, so no later edit to the loop can make it inflate a
        // container by recursing.
        .max_recursion_depth(MAX_PREFIX_WALK_DEPTH)
        .build()
        .map_err(parse_failure)
}

fn walk_message_prefix<V>(
    mut ppr: PacketParserResult<'_>,
    mut visit: V,
) -> Result<PrefixEnd, PgpError>
where
    V: FnMut(&openpgp::Packet) -> Result<(), PgpError>,
{
    let mut budget = WalkBudget::message_prefix();

    while let PacketParserResult::Some(pp) = ppr {
        match &pp.packet {
            openpgp::Packet::PKESK(_) | openpgp::Packet::SKESK(_) => {
                budget.charge(&pp)?;
                visit(&pp.packet)?;
            }
            // Ignorable by RFC 9580, and deliberately not treated as the
            // container: neither may stand in for the proof that every
            // session-key packet has been seen.
            openpgp::Packet::Marker(_) | openpgp::Packet::Padding(_) => {
                budget.charge(&pp)?;
            }
            // The encrypted container follows every session-key packet, so
            // reaching it ends the walk with the sequence complete.
            openpgp::Packet::SEIP(_) => {
                visit(&pp.packet)?;
                return Ok(PrefixEnd::Container);
            }
            openpgp::Packet::CompressedData(_)
                if pp.recursion_depth() < isize::from(MAX_PREFIX_WALK_DEPTH) =>
            {
                budget.charge(&pp)?;
            }
            // Anything else ends the session-key sequence. Returning here drops
            // the parser without reading the packet — the whole point of
            // stopping is to leave a container uninflated.
            _ => return Ok(PrefixEnd::NoContainer),
        }

        let (_, next) = pp.recurse().map_err(parse_failure)?;
        ppr = next;
    }

    Ok(PrefixEnd::NoContainer)
}

// ── Phase 2: Sequoia's walk to the literal data ────────────────────────

/// Charges Sequoia's own packet walk against a consumption budget.
///
/// `VerificationHelper::inspect` is called for every packet that walk parses,
/// before it reads past the packet, which makes this the one place the walk can
/// be bounded from outside Sequoia: `DecryptorBuilder` and `VerifierBuilder`
/// expose no recursion or consumption settings of their own.
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
        self.budget.charge(pp)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_budget_uses_the_floor_for_small_inputs() {
        assert_eq!(WalkBudget::message_setup(0).bytes, MIN_SETUP_WALK_BYTES);
        assert_eq!(WalkBudget::message_setup(1024).bytes, MIN_SETUP_WALK_BYTES);
    }

    #[test]
    fn setup_budget_scales_with_large_inputs() {
        let input = 64 * 1024 * 1024;
        assert_eq!(
            WalkBudget::message_setup(input).bytes,
            input * MAX_SETUP_WALK_RATIO
        );
    }

    #[test]
    fn setup_budget_saturates_instead_of_overflowing() {
        assert_eq!(WalkBudget::message_setup(u64::MAX).bytes, u64::MAX);
    }
}
