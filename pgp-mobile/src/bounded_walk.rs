//! Consumption bounds for the packet walks that read received input.
//!
//! Three walks read input before anything about it has been authenticated: the
//! phase-1 header walk the app runs to learn a message's recipients, its quantum
//! safety, or its password packets; the walk Sequoia runs inside
//! `DecryptorBuilder::with_policy` / `VerifierBuilder::with_policy` to reach the
//! literal data; and the walk `crate::classify` runs to decide what an opened
//! file holds. Sequoia installs a decompressor the moment it parses a
//! `CompressedData` header, so all three read a stream that expands up to
//! 1032:1 per nested layer. An output-side ceiling cannot bound any of them:
//! input that never yields a literal packet produces no output bytes to count.
//!
//! A depth limit alone does not bound one either — it relocates the cost.
//! `PacketParser::recurse` recurses only while the parser's own limit allows,
//! and at that limit it does what `next` does instead: finish the current packet
//! and move on, which for a compressed container means inflating the whole thing
//! to find where it ends. A walk that stops descending must therefore *refuse*
//! the container it stopped at, never step over it.
//!
//! So the bounds live here, on the consumption side, and each one is charged
//! before the walk reads *past* the packet it is charged for — which is what
//! makes them bounds rather than post-mortems. Sequoia produces an ordinary
//! packet by parsing its body, so one such body is always already read when its
//! charge is refused; that body is bounded by the parser's own
//! `max_packet_size`, 1 MiB by default. Total consumption is therefore the
//! budget plus that one packet, and everything a walk goes *on* to read —
//! container bodies, and the bodies of packets it skips — is bounded outright.
//! Exceeding a bound fails closed with `PgpError::MessageLimitsExceeded`.

use std::fmt;
use std::io::Read;

use openpgp::crypto::SessionKey;
use openpgp::packet::header::BodyLength;
use openpgp::parse::stream::{DecryptionHelper, MessageStructure, VerificationHelper};
use openpgp::parse::{Dearmor, PacketParser, PacketParserBuilder, PacketParserResult, Parse as _};
use openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp as openpgp;

use crate::error::PgpError;

/// Packets a phase-1 header walk may consume.
///
/// This walk reads the session-key packets and stops. A message addressed to
/// more than a thousand recipients is not a message anybody composed, and this
/// is the bound that decides that question — phase 1 runs first, so it is the
/// one a recipient meets.
const MAX_PREFIX_WALK_PACKETS: u32 = 1024;

/// Packets Sequoia's setup walk may consume.
///
/// Twice the phase-1 allowance, so that the two walks cannot split a verdict on
/// the same message — which would show a recipient a key for a message that
/// then refuses to open. They count different packets: phase 1 sees only the
/// session-key prefix, while this walk also sees the one-pass-signature,
/// signature, marker and padding packets around the literal data. Equal
/// allowances would therefore make this the effective ceiling on recipients,
/// and a lower one here would refuse messages phase 1 had just accepted. The
/// doubling is slack for framing, not tolerance for more of it: a message
/// carrying a thousand packets of framing around its payload is already past
/// anything a producer emits.
const MAX_SETUP_WALK_PACKETS: u32 = 2 * MAX_PREFIX_WALK_PACKETS;

/// Bytes a phase-1 header walk may consume.
///
/// The walk stops at the encrypted container, so this covers the session-key
/// packets alone; the largest one we can receive is a v6 PKESK carrying an
/// ML-KEM-1024 ciphertext, under 2 KiB. 4 MiB is well past
/// `MAX_PREFIX_WALK_PACKETS` of those and still bounds the read a crafted file
/// can provoke. The bound is absolute rather than input-relative because this
/// walk stops before any payload: a large input does not entitle a message to a
/// larger header.
const MAX_PREFIX_WALK_BYTES: u64 = 4 * 1024 * 1024;

/// How deep the phase-1 header walk may descend.
///
/// Session-key packets sit at the top level of an encrypted message. A
/// compressed message may in turn hold one (`Compressed Message` is an
/// `OpenPGP Message` in RFC 9580's grammar), which is the single legitimate
/// reason to descend at all; deeper nesting is the decompression-bomb shape
/// rather than a message, so the walk stops there instead of inflating it.
const MAX_PREFIX_WALK_DEPTH: u8 = 1;

/// Packets a content-classification walk may consume.
///
/// That walk stops at the first packet that says what its input is, and the only
/// things that can legitimately precede one are a compressed container and the
/// marker and padding packets RFC 9580 lets a producer ignore — none of which
/// anything emits more than once. The allowance is generous against that shape
/// and still turns a file made entirely of them into a refusal rather than a
/// scan of its whole length.
const MAX_CLASSIFICATION_WALK_PACKETS: u32 = 16;

/// Bytes a content-classification walk may consume.
///
/// Charged against the packets it steps over, which are framing rather than
/// payload. Nothing spends a megabyte of framing ahead of the packet that
/// identifies a file, and the bound is absolute rather than input-relative for
/// the reason phase 1's is: the walk stops before any payload, so a large input
/// does not entitle it to a larger header.
const MAX_CLASSIFICATION_WALK_BYTES: u64 = 1024 * 1024;

/// How deep a content-classification walk may descend.
///
/// One, for the same reason phase 1 descends one: a compressed message may hold
/// the packet that decides what a file is, and nothing legitimate wraps that in
/// turn.
const MAX_CLASSIFICATION_WALK_DEPTH: u8 = 1;

/// How deep Sequoia's setup walk may descend before we refuse the message.
///
/// Four, and it should stay four. The deepest shape a real producer can emit is
/// a compressed message holding an encrypted one holding a compressed, signed
/// one — `Compressed( PKESK, SEIP( Compressed( OPS, Literal, Sig ) ) )` — which
/// verifies at depth 3, one layer inside this bound. Raising it buys nothing:
/// the phase-1 depth rule below is the earlier and tighter gate, so the only
/// inputs this constant decides are ones nesting *below* the encryption
/// container, which is exactly where each further layer multiplies the
/// expansion an attacker gets per byte of input.
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
///
/// What holds that reasoning up is that every packet class `charge` counts is
/// incompressible in practice: key-exchange packets and signatures are
/// ciphertext, and Sequoia fills a padding packet with CSPRNG bytes
/// (`packet/padding.rs`). None of them can be charged at a size the input did
/// not pay for. Adding a compressible packet class to what `charge` counts
/// would break that silently, and the ratio would have to be revisited.
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

impl WalkBoundExceeded {
    /// Hand the bound to Sequoia as an `io::Error`.
    ///
    /// Sequoia returns a bound raised in `inspect` by one of two routes: as
    /// itself, when the walk runs under `with_policy`, or through
    /// `Decryptor::read`, which passes an inner `io::Error` on unchanged and
    /// boxes anything else. Only the `io::Error` survives that second route
    /// intact — `anyhow`'s box is its own wrapper type, which downcasts to
    /// neither the value inside it nor anything reachable from `source()`, so a
    /// bound handed over bare comes back unrecognizable and gets classified as
    /// a damaged message. Wrapping here makes both routes deliver one shape:
    /// an `io::Error` whose `get_ref()` is this value.
    ///
    /// `ErrorKind::Other` deliberately, never `Interrupted`: readers in the
    /// stack retry that one, and a bound must not be retried.
    fn into_sequoia_error(self) -> openpgp::anyhow::Error {
        std::io::Error::new(std::io::ErrorKind::Other, self).into()
    }
}

/// Recover a consumption bound from a Sequoia error chain.
///
/// Both routes out of `inspect` carry the bound as the inner error of an
/// `io::Error` (see `into_sequoia_error`), so one shape is all this looks for.
/// It has to reach through `get_ref()` rather than follow `source()`, because
/// an `io::Error`'s `source()` is the source *of* the error it wraps and skips
/// that error itself.
pub(crate) fn walk_bound_error(error: &openpgp::anyhow::Error) -> Option<PgpError> {
    error
        .chain()
        .find_map(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .and_then(|io_error| io_error.get_ref())
                .and_then(|inner| inner.downcast_ref::<WalkBoundExceeded>())
        })
        .map(|exceeded| PgpError::MessageLimitsExceeded {
            reason: exceeded.reason.clone(),
        })
}

/// What a walk may still consume.
///
/// One accounting primitive for every walk here: they differ in how much they
/// are allowed and how deep they may go, never in what counts.
pub(crate) struct WalkBudget {
    packets: u32,
    packet_limit: u32,
    bytes: u64,
    max_depth: isize,
}

impl WalkBudget {
    /// The budget for a phase-1 header walk.
    fn message_prefix() -> Self {
        Self {
            packets: MAX_PREFIX_WALK_PACKETS,
            packet_limit: MAX_PREFIX_WALK_PACKETS,
            bytes: MAX_PREFIX_WALK_BYTES,
            max_depth: isize::from(MAX_PREFIX_WALK_DEPTH),
        }
    }

    /// The budget for Sequoia's walk to the literal data, over `input_bytes` of
    /// received input.
    fn message_setup(input_bytes: u64) -> Self {
        Self {
            packets: MAX_SETUP_WALK_PACKETS,
            packet_limit: MAX_SETUP_WALK_PACKETS,
            bytes: input_bytes
                .saturating_mul(MAX_SETUP_WALK_RATIO)
                .max(MIN_SETUP_WALK_BYTES),
            max_depth: MAX_SETUP_WALK_DEPTH,
        }
    }

    /// The budget for a walk that reads packet headers until one identifies the
    /// input.
    pub(crate) fn content_classification() -> Self {
        Self {
            packets: MAX_CLASSIFICATION_WALK_PACKETS,
            packet_limit: MAX_CLASSIFICATION_WALK_PACKETS,
            bytes: MAX_CLASSIFICATION_WALK_BYTES,
            max_depth: isize::from(MAX_CLASSIFICATION_WALK_DEPTH),
        }
    }

    /// The recursion depth to build the parser with.
    ///
    /// One past what the walk will descend, and that is the point. At the
    /// parser's *own* limit `recurse` stops recursing and behaves like `next`,
    /// and `next` over a compressed container skips it by inflating the whole
    /// thing — so a walk whose parser limit equals its own turns a missing depth
    /// guard into a decompression bomb rather than a refusal. Given a level of
    /// slack the parser descends instead, cheaply, and `charge` refuses the
    /// packet it lands on for being past `max_depth`. The guard below is still
    /// what bounds the walk; this only decides which way a mistake fails.
    pub(crate) fn parser_recursion_depth(&self) -> u8 {
        u8::try_from(self.max_depth.saturating_add(1)).unwrap_or(u8::MAX)
    }

    /// Whether the walk may open the container it is looking at.
    pub(crate) fn may_descend(&self, pp: &PacketParser) -> bool {
        pp.recursion_depth() < self.max_depth
    }

    /// A container the walk will not open.
    ///
    /// Refusing it is a bound firing, not an absence of whatever the walk was
    /// looking for, and it says so: left to a caller's "nothing found" path it
    /// would reach the reader as "the data appears damaged, ask the sender to
    /// resend", which is the misleading advice this error exists to avoid.
    pub(crate) fn undescendable_container(&self) -> WalkBoundExceeded {
        WalkBoundExceeded {
            reason: format!(
                "Message nests compressed data more than {} container deep",
                self.max_depth
            ),
        }
    }

    /// Charge one packet, before the walk reads past it.
    pub(crate) fn charge(&mut self, pp: &PacketParser) -> Result<(), WalkBoundExceeded> {
        let depth = pp.recursion_depth();
        if depth > self.max_depth {
            return Err(WalkBoundExceeded {
                reason: format!(
                    "Message nests packets {depth} containers deep, past the maximum of {}",
                    self.max_depth
                ),
            });
        }

        self.packets = self
            .packets
            .checked_sub(1)
            .ok_or_else(|| WalkBoundExceeded {
                reason: format!(
                    "Message carries more than {} packets before its payload",
                    self.packet_limit
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

        self.bytes =
            self.bytes
                .checked_sub(u64::from(*length))
                .ok_or_else(|| WalkBoundExceeded {
                    reason: "Message consumes more than the maximum expansion for its size"
                        .to_string(),
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
pub(crate) fn walk_message_prefix_reader<R, V>(reader: R, visit: V) -> Result<PrefixEnd, PgpError>
where
    R: Read + Send + Sync,
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

fn build_prefix_parser(
    builder: PacketParserBuilder<'_>,
) -> Result<PacketParserResult<'_>, PgpError> {
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
            openpgp::Packet::CompressedData(_) if budget.may_descend(&pp) => {
                budget.charge(&pp)?;
            }
            openpgp::Packet::CompressedData(_) => {
                return Err(budget.undescendable_container().into())
            }
            // Anything else ends the session-key sequence, and ends it as an
            // absence rather than a refusal: this is where a signed-only
            // message or a certificate file lands. Returning here drops the
            // parser without reading the packet.
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
        if let Err(exceeded) = self.budget.charge(pp) {
            return Err(exceeded.into_sequoia_error());
        }
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
