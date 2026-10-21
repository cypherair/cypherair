//! The unlock passphrase stretch: Argon2id under the caller's fixed profile.
//!
//! The output becomes the vault wrapping key's application password on the
//! Swift side. The salt is public metadata; the parameters are bounded here so
//! a misbehaving caller cannot request an absurd allocation.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::Zeroizing;

use crate::error::PgpError;

pub const OUTPUT_LENGTH: usize = 32;
const MIN_SALT_LENGTH: usize = 16;
const MEMORY_KIB: std::ops::RangeInclusive<u32> = 8_192..=1_048_576;
const ITERATIONS: std::ops::RangeInclusive<u32> = 1..=16;
const PARALLELISM: std::ops::RangeInclusive<u32> = 1..=8;
/// Stack overwritten once a derivation returns; it has to exceed the depth
/// argon2 and its BLAKE2b hashing reach below `derive`.
const STACK_SCRUB_BYTES: usize = 64 * 1024;

pub(crate) fn derive_unlock_secret(
    passphrase: Vec<u8>,
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Vec<u8>, PgpError> {
    let passphrase = Zeroizing::new(passphrase);
    let refuse = |reason: &str| PgpError::UnlockStretchFailed {
        reason: reason.to_string(),
    };
    if passphrase.is_empty() {
        return Err(refuse("empty passphrase"));
    }
    if salt.len() < MIN_SALT_LENGTH {
        return Err(refuse("salt too short"));
    }
    if !MEMORY_KIB.contains(&memory_kib)
        || !ITERATIONS.contains(&iterations)
        || !PARALLELISM.contains(&parallelism)
    {
        return Err(refuse("parameters out of range"));
    }
    let params = Params::new(memory_kib, iterations, parallelism, Some(OUTPUT_LENGTH))
        .map_err(|error| refuse(&error.to_string()))?;
    let mut blocks = Zeroizing::new(vec![Block::new(); params.block_count()]);
    let mut output = vec![0u8; OUTPUT_LENGTH];
    let derived = derive(&passphrase, salt, params, &mut blocks, &mut output);
    zeroize::zeroize_stack::<STACK_SCRUB_BYTES>();
    derived.map_err(|error| refuse(&error.to_string()))?;
    Ok(output)
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

#[cfg(test)]
mod tests {
    use super::*;

    const PASSPHRASE: &[u8] = b"correct horse battery staple";
    const SALT: [u8; 16] = [0x01; 16];

    #[test]
    fn known_answer_pins_the_profile() {
        let started = std::time::Instant::now();
        let output = derive_unlock_secret(PASSPHRASE.to_vec(), &SALT, 65_536, 3, 1).unwrap();
        eprintln!("unlock stretch took {:?}", started.elapsed());
        let hex: String = output.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "2059d35e11f775944efac46541cfcd82013946a4ce55030871f5891aacf73b07");
    }

    #[test]
    fn refuses_bad_inputs() {
        assert!(derive_unlock_secret(Vec::new(), &SALT, 65_536, 3, 1).is_err());
        assert!(derive_unlock_secret(PASSPHRASE.to_vec(), &SALT[..8], 65_536, 3, 1).is_err());
        assert!(derive_unlock_secret(PASSPHRASE.to_vec(), &SALT, 1_024, 3, 1).is_err());
        assert!(derive_unlock_secret(PASSPHRASE.to_vec(), &SALT, 65_536, 0, 1).is_err());
        assert!(derive_unlock_secret(PASSPHRASE.to_vec(), &SALT, 65_536, 3, 0).is_err());
    }

    #[test]
    fn salt_and_passphrase_both_matter() {
        let base = derive_unlock_secret(PASSPHRASE.to_vec(), &SALT, 8_192, 1, 1).unwrap();
        assert_ne!(base, derive_unlock_secret(b"other".to_vec(), &SALT, 8_192, 1, 1).unwrap());
        assert_ne!(base, derive_unlock_secret(PASSPHRASE.to_vec(), &[0x02; 16], 8_192, 1, 1).unwrap());
        assert_eq!(base, derive_unlock_secret(PASSPHRASE.to_vec(), &SALT, 8_192, 1, 1).unwrap());
    }
}
