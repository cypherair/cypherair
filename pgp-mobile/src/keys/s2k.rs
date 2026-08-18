use super::*;

/// The Argon2id parameters every v6 export derives under: RFC 9106 §4's first
/// recommended option — 2 GiB of memory, one pass, four lanes. Staying exactly
/// on the RFC keeps the external-standard anchor, and the high memory cost is
/// what makes a stolen backup expensive to attack offline. Each secret-key
/// packet carries its own S2K, so an export of a v6 certificate runs the
/// derivation three times — sequentially, leaving 2 GiB the peak and tripling
/// only the wall-clock cost (SECURITY.md §7).
///
/// RFC 9580 encodes the memory cost as `2^m` KiB, so 2 GiB is `m = 21`.
/// `export_s2k_params` publishes the resulting requirement to the app's memory
/// guard and `export_argon2_s2k` builds the specifier the packets carry, so the
/// number the guard checks and the number the KDF runs under are the same one.
const EXPORT_ARGON2_MEMORY_ENCODED_M: u8 = 21;
const EXPORT_ARGON2_PASSES: u8 = 1;
const EXPORT_ARGON2_LANES: u8 = 4;

/// Maximum Argon2 time cost (passes) accepted on the passphrase key-import
/// path. The import KDF runs before the wrong-passphrase check and is
/// uninterruptible, so an attacker-supplied key with a very high pass count
/// could make a single import attempt run arbitrarily long. Our own export uses
/// one pass, so 16 leaves ample headroom while rejecting the abuse range.
pub(crate) const MAX_IMPORT_ARGON2_PASSES: u8 = 16;

/// Maximum Argon2 memory cost accepted on the passphrase key-import path.
/// RFC 9580 caps the encoded memory parameter at 31, so 2^31 KiB is the largest
/// figure a well-formed key can ask for and anything beyond it is malformed or
/// hostile. This is the format bound and belongs with the pass bound; the much
/// narrower question of what *this device* can afford is platform knowledge and
/// stays in the app's memory guard.
pub(crate) const MAX_IMPORT_ARGON2_MEMORY_KIB: u64 = 1 << 31;

/// RFC 9580 encodes Argon2's memory cost as `2^m` KiB. The shift is guarded so a
/// malformed `m >= 64` saturates instead of overflowing.
pub(crate) fn argon2_memory_kib(encoded_m: u8) -> u64 {
    1u64.checked_shl(u32::from(encoded_m)).unwrap_or(u64::MAX)
}

/// Whether exporting `suite` protects the secret material with Argon2id.
///
/// The v4 suites carry the GnuPG-compatibility story, so their exports keep
/// RFC 4880 Iterated+Salted S2K; every v6 suite uses Argon2id.
pub(crate) fn export_uses_argon2id(suite: KeySuite) -> bool {
    suite.key_version() == 6
}

/// The Argon2id specifier an export writes into its secret-key packets.
pub(crate) fn export_argon2_s2k(salt: [u8; 16]) -> openpgp::crypto::S2K {
    openpgp::crypto::S2K::Argon2 {
        salt,
        t: EXPORT_ARGON2_PASSES,
        p: EXPORT_ARGON2_LANES,
        m: EXPORT_ARGON2_MEMORY_ENCODED_M,
    }
}

/// Reject a cert whose encrypted secret key material uses Argon2 parameters
/// outside the accepted range, before any KDF runs during import.
pub(crate) fn reject_excessive_import_argon2_parameters(
    cert: &openpgp::Cert,
) -> Result<(), PgpError> {
    let check =
        |secret: Option<&openpgp::packet::key::SecretKeyMaterial>| -> Result<(), PgpError> {
            if let Some(openpgp::packet::key::SecretKeyMaterial::Encrypted(encrypted)) = secret {
                if let openpgp::crypto::S2K::Argon2 { m, t, .. } = encrypted.s2k() {
                    if *t > MAX_IMPORT_ARGON2_PASSES {
                        return Err(PgpError::InvalidKeyData {
                            reason: format!(
                                "Argon2 time cost {t} passes exceeds the maximum of {MAX_IMPORT_ARGON2_PASSES}"
                            ),
                        });
                    }
                    let memory_kib = argon2_memory_kib(*m);
                    if memory_kib > MAX_IMPORT_ARGON2_MEMORY_KIB {
                        return Err(PgpError::Argon2idMemoryExceeded {
                            required_mb: memory_kib / 1024,
                        });
                    }
                }
            }
            Ok(())
        };
    check(cert.primary_key().key().optional_secret())?;
    for ka in cert.keys().subkeys() {
        check(ka.key().optional_secret())?;
    }
    Ok(())
}

/// How a passphrase-protected key derives its unlock key.
///
/// A real enum rather than a string: the app reads this to decide whether the
/// memory guard applies at all, and a rename on either side has to stop
/// compiling rather than silently disable the guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum S2kType {
    /// RFC 9580 Argon2id — memory-hard, and the only kind with a memory cost.
    Argon2id,
    /// RFC 4880 iterated-and-salted, as used by Portable Legacy.
    IteratedSalted,
    /// Any other S2K a certificate may carry.
    Unknown,
}

/// S2K (String-to-Key) parameters of a passphrase-protected key. The app reads
/// these to check the device's memory headroom before any derivation runs — as
/// declared by an incoming key file (`parse_s2k_params`) or as an outgoing
/// export will use them (`export_s2k_params`).
///
/// `memory_kib` is the cost of a single derivation, which is also the peak: a
/// certificate protects each of its secret-key packets under its own S2K, so an
/// export or import derives once per packet, one after another (SECURITY.md §7).
#[derive(Debug, uniffi::Record)]
pub struct S2kInfo {
    pub s2k_type: S2kType,
    /// For Argon2id: memory requirement in KiB (2^encoded_m). 0 otherwise.
    pub memory_kib: u64,
}

/// The S2K an export of `suite` will derive under, without exporting anything.
///
/// Export is as memory-hard as import and carries the same risk of being
/// terminated mid-derivation, so the app checks this before it unwraps any
/// secret material. Answering from the suite alone keeps the check ahead of
/// both the authentication prompt and the private key leaving the enclave.
pub fn export_s2k_params(suite: KeySuite) -> S2kInfo {
    if export_uses_argon2id(suite) {
        S2kInfo {
            s2k_type: S2kType::Argon2id,
            memory_kib: argon2_memory_kib(EXPORT_ARGON2_MEMORY_ENCODED_M),
        }
    } else {
        S2kInfo {
            s2k_type: S2kType::IteratedSalted,
            memory_kib: 0,
        }
    }
}

/// Parse S2K parameters from a passphrase-protected key file.
/// This allows the Swift side to check the memory requirement an incoming key
/// declares before calling `import_secret_key`, preventing iOS Jetsam kills.
///
/// Inspects the primary key and all subkeys, returning the S2K info with the
/// highest memory requirement. This handles keys where the primary key and
/// subkeys may use different S2K parameters (e.g., imported from external tools).
pub fn parse_s2k_params(armored_data: &[u8]) -> Result<S2kInfo, PgpError> {
    let cert = openpgp::Cert::from_bytes(armored_data).map_err(|e| PgpError::InvalidKeyData {
        reason: e.to_string(),
    })?;

    // Iterate primary key + all subkeys, extract S2K info from each encrypted key.
    let mut best: Option<S2kInfo> = None;
    let mut has_unencrypted = false;

    // Helper closure to extract S2K info from secret key material
    let mut check_secret = |secret: Option<&openpgp::packet::key::SecretKeyMaterial>| match secret {
        Some(openpgp::packet::key::SecretKeyMaterial::Encrypted(encrypted)) => {
            let info = match encrypted.s2k() {
                openpgp::crypto::S2K::Argon2 { m, .. } => S2kInfo {
                    s2k_type: S2kType::Argon2id,
                    memory_kib: argon2_memory_kib(*m),
                },
                openpgp::crypto::S2K::Iterated { .. } => S2kInfo {
                    s2k_type: S2kType::IteratedSalted,
                    memory_kib: 0,
                },
                _ => S2kInfo {
                    s2k_type: S2kType::Unknown,
                    memory_kib: 0,
                },
            };
            if best
                .as_ref()
                .map_or(true, |b| info.memory_kib > b.memory_kib)
            {
                best = Some(info);
            }
        }
        Some(openpgp::packet::key::SecretKeyMaterial::Unencrypted(_)) => {
            has_unencrypted = true;
        }
        None => {}
    };

    // Check primary key
    check_secret(cert.primary_key().key().optional_secret());
    // Check all subkeys
    for ka in cert.keys().subkeys() {
        check_secret(ka.key().optional_secret());
    }

    if let Some(info) = best {
        // `best` holds the largest memory cost in the certificate, so checking
        // it here bounds every key in the file.
        if info.memory_kib > MAX_IMPORT_ARGON2_MEMORY_KIB {
            return Err(PgpError::Argon2idMemoryExceeded {
                required_mb: info.memory_kib / 1024,
            });
        }
        Ok(info)
    } else if has_unencrypted {
        Err(PgpError::InvalidKeyData {
            reason: "Key is not passphrase-protected (unencrypted secret key)".to_string(),
        })
    } else {
        Err(PgpError::InvalidKeyData {
            reason: "No secret key material found (public key only)".to_string(),
        })
    }
}
