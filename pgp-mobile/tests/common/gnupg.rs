//! Shared GnuPG (`gpg` binary) harness for integration tests.
//!
//! Hosts the isolated-GNUPGHOME setup and the `require_gpg_or_skip` gate used by
//! both the Profile A interop tests (`gnupg_binary_tests.rs`) and the Secure Enclave
//! custody interop lanes. The gate honors `CYPHERAIR_REQUIRE_GPG=1`: the mandatory CI
//! lane fails (does not silently pass) when gpg is missing, while local/contributor
//! runs without gpg skip cleanly.
#![allow(dead_code)]

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

/// Resolve the `gpg` binary, honoring the skip-forbidden gate.
///
/// Returns `Some(path)` when gpg is available. When gpg is not found:
/// - with `CYPHERAIR_REQUIRE_GPG=1`, panics so the mandatory CI interop lane fails
///   instead of silently passing;
/// - otherwise returns `None` so the caller can skip (gpg-less dev/contributor runs).
pub fn require_gpg_or_skip() -> Option<PathBuf> {
    match find_gpg() {
        Some(path) => Some(path),
        None => {
            if gpg_is_required() {
                panic!(
                    "CYPHERAIR_REQUIRE_GPG=1 but gpg was not found on PATH or known locations; \
                     the mandatory GnuPG interop lane must not skip"
                );
            }
            eprintln!(
                "gpg not found on this system; skipping (set CYPHERAIR_REQUIRE_GPG=1 to forbid skips)"
            );
            None
        }
    }
}

fn gpg_is_required() -> bool {
    std::env::var_os("CYPHERAIR_REQUIRE_GPG").is_some_and(|value| value == "1")
}

/// Search for the `gpg` binary: PATH first, then common Homebrew/system paths.
pub fn find_gpg() -> Option<PathBuf> {
    if let Ok(output) = Command::new("which").arg("gpg").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
    }

    let candidates = [
        "/opt/homebrew/bin/gpg",
        "/usr/local/bin/gpg",
        "/usr/bin/gpg",
    ];
    for candidate in &candidates {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Some(path);
        }
    }

    None
}

/// Create a temporary GNUPGHOME with non-interactive configuration.
pub fn setup_gpg_home() -> TempDir {
    let dir = TempDir::new().expect("Failed to create temp GNUPGHOME");

    // Set directory permissions to 700 (required by gpg)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("Failed to set GNUPGHOME permissions");
    }

    // Write gpg.conf for non-interactive use
    let gpg_conf = dir.path().join("gpg.conf");
    std::fs::write(
        &gpg_conf,
        "no-tty\nbatch\nyes\ntrust-model always\nforce-mdc\n",
    )
    .expect("Failed to write gpg.conf");

    // Write gpg-agent.conf
    let agent_conf = dir.path().join("gpg-agent.conf");
    std::fs::write(&agent_conf, "allow-preset-passphrase\n")
        .expect("Failed to write gpg-agent.conf");

    dir
}

/// Create a `Command` for gpg with the given GNUPGHOME.
pub fn gpg_cmd(gpg_path: &PathBuf, gnupghome: &TempDir) -> Command {
    let mut cmd = Command::new(gpg_path);
    cmd.env("GNUPGHOME", gnupghome.path());
    cmd.arg("--batch");
    cmd.arg("--yes");
    cmd.arg("--trust-model").arg("always");
    cmd
}

/// Import a key (public or secret) into the temporary gpg keyring.
/// Writes the key data to a temp file, then runs `gpg --import`.
pub fn gpg_import_key(gpg_path: &PathBuf, gnupghome: &TempDir, key_data: &[u8]) {
    let key_file = gnupghome.path().join("import_key.tmp");
    std::fs::write(&key_file, key_data).expect("Failed to write key file");

    let output = gpg_cmd(gpg_path, gnupghome)
        .arg("--import")
        .arg(&key_file)
        .output()
        .expect("Failed to run gpg --import");

    assert!(
        output.status.success(),
        "gpg --import failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
