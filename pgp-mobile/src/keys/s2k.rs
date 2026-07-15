use super::*;

/// Maximum Argon2 time cost (passes) accepted on the passphrase key-import
/// path. The import KDF runs before the wrong-passphrase check and is
/// uninterruptible, so an attacker-supplied key with a very high pass count
/// could make a single import attempt run arbitrarily long. Memory is bounded
/// separately by the Swift-side `Argon2idMemoryGuard` via `parse_s2k_params`;
/// our own export uses 3 passes, so 16 leaves ample headroom while rejecting
/// the abuse range.
pub(crate) const MAX_IMPORT_ARGON2_PASSES: u8 = 16;

/// Reject a cert whose encrypted secret key material uses an Argon2 S2K with an
/// implausible time cost, before any KDF runs during import.
pub(crate) fn reject_excessive_import_argon2_passes(
    cert: &openpgp::Cert,
) -> Result<(), PgpError> {
    let check =
        |secret: Option<&openpgp::packet::key::SecretKeyMaterial>| -> Result<(), PgpError> {
            if let Some(openpgp::packet::key::SecretKeyMaterial::Encrypted(encrypted)) = secret {
                if let openpgp::crypto::S2K::Argon2 { t, .. } = encrypted.s2k() {
                    if *t > MAX_IMPORT_ARGON2_PASSES {
                        return Err(PgpError::InvalidKeyData {
                            reason: format!(
                                "Argon2 time cost {t} passes exceeds the maximum of {MAX_IMPORT_ARGON2_PASSES}"
                            ),
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

/// S2K (String-to-Key) parameters extracted from a passphrase-protected key.
/// Used by Swift side to check memory requirements before importing.
#[derive(Debug, uniffi::Record)]
pub struct S2kInfo {
    /// S2K type: "iterated-salted" for Portable Legacy, "argon2id" for Portable Modern · High, or "unknown".
    pub s2k_type: String,
    /// For Argon2id: memory requirement in KiB (2^encoded_m). 0 for non-Argon2id.
    pub memory_kib: u64,
}

/// Parse S2K parameters from a passphrase-protected key file.
/// This allows the Swift side to check memory requirements (e.g., Argon2id 512 MB)
/// before calling `import_secret_key`, preventing iOS Jetsam kills.
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
                    s2k_type: "argon2id".to_string(),
                    // RFC 9580 memory cost is `2^m` KiB; guard the shift so a
                    // malformed `m >= 64` saturates instead of panicking in
                    // debug/test builds (mirrors password::validate_s2k_memory).
                    memory_kib: 1u64.checked_shl(*m as u32).unwrap_or(u64::MAX),
                },
                openpgp::crypto::S2K::Iterated { .. } => S2kInfo {
                    s2k_type: "iterated-salted".to_string(),
                    memory_kib: 0,
                },
                _ => S2kInfo {
                    s2k_type: "unknown".to_string(),
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
