//! The unlock passphrase stretch: Argon2id under the caller's fixed profile.
//!
//! The output becomes the vault wrapping key's application password on the
//! Swift side. The salt is public metadata; the parameters are bounded here so
//! that a misbehaving caller cannot request an absurd allocation.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::Zeroizing;

use crate::EngineError;
use crate::error::contained;

const OUTPUT_LENGTH: usize = 32;
const MIN_SALT_LENGTH: usize = 16;
const MEMORY_KIB: std::ops::RangeInclusive<u32> = 8_192..=1_048_576;
const ITERATIONS: std::ops::RangeInclusive<u32> = 1..=16;
const PARALLELISM: std::ops::RangeInclusive<u32> = 1..=8;
/// Stack overwritten once a derivation returns; it has to exceed the depth
/// argon2 and its BLAKE2b hashing reach below `derive`.
const STACK_SCRUB_BYTES: usize = 64 * 1024;

/// Stretch the unlock passphrase into 32 bytes.
///
/// An empty passphrase, a salt shorter than 16 bytes, or a parameter outside
/// its range is `KdfOutOfRange`.
#[uniffi::export]
pub fn stretch_unlock_passphrase(
    passphrase: &[u8],
    salt: Vec<u8>,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Vec<u8>, EngineError> {
    contained(|| {
        if passphrase.is_empty()
            || salt.len() < MIN_SALT_LENGTH
            || !MEMORY_KIB.contains(&memory_kib)
            || !ITERATIONS.contains(&iterations)
            || !PARALLELISM.contains(&parallelism)
        {
            return Err(EngineError::KdfOutOfRange);
        }
        let params = Params::new(memory_kib, iterations, parallelism, Some(OUTPUT_LENGTH))
            .map_err(|_| EngineError::KdfOutOfRange)?;
        let mut blocks = Zeroizing::new(vec![Block::new(); params.block_count()]);
        let mut output = Zeroizing::new(vec![0u8; OUTPUT_LENGTH]);
        let derived = derive(passphrase, &salt, params, &mut blocks, &mut output);
        zeroize::zeroize_stack::<STACK_SCRUB_BYTES>();
        derived.map_err(|_| EngineError::Internal)?;
        Ok(std::mem::take(&mut *output))
    })
}

/// Out of line so that argon2's frames lie below the caller's, where the stack
/// scrub reaches them.
#[inline(never)]
fn derive(
    passphrase: &[u8],
    salt: &[u8],
    params: Params,
    blocks: &mut [Block],
    output: &mut [u8],
) -> argon2::Result<()> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(passphrase, salt, output, blocks)
}
