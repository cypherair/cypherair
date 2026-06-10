//! Reintroduction guardrail for the Phase 6 legacy signature symbols
//! (docs/LEGACY_CLEANUP.md Guardrails, 2026-06-08 support cutoff).
//!
//! Reads `pgp-mobile/src` via `CARGO_MANIFEST_DIR` and fails when a retired
//! legacy signature symbol reappears anywhere in crate sources. The current
//! API surface is `summary_state` / `summary_entry_index` plus the detailed
//! signature entries; the retired symbols must not come back as fields,
//! types, helpers, or aliases.

use std::fs;
use std::path::PathBuf;

const FORBIDDEN_SYMBOLS: &[&str] = &[
    "legacy_status",
    "legacy_signer_fingerprint",
    "LegacyFoldMode",
    "legacy_stopped",
    "state_from_legacy_status",
    // Bare retired enum name; `DetailedSignatureStatus` and
    // `CertificateSignatureStatus` are current types and do not match as
    // whole words.
    "SignatureStatus",
    // Retired `PasswordDecryptResult` field names; the current per-entry
    // field is `signer_primary_fingerprint`.
    "signature_status",
    "signer_fingerprint",
];

fn is_word_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn contains_whole_word(contents: &str, symbol: &str) -> bool {
    let bytes = contents.as_bytes();
    let mut search_start = 0;
    while let Some(offset) = contents[search_start..].find(symbol) {
        let start = search_start + offset;
        let end = start + symbol.len();
        let boundary_before = start == 0 || !is_word_byte(bytes[start - 1]);
        let boundary_after = end == bytes.len() || !is_word_byte(bytes[end]);
        if boundary_before && boundary_after {
            return true;
        }
        search_start = start + 1;
    }
    false
}

fn crate_source_files() -> Vec<PathBuf> {
    let src_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut pending = vec![src_root];
    let mut files = Vec::new();
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).expect("crate src directory should be readable") {
            let path = entry.expect("crate src entry should be readable").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

#[test]
fn test_crate_sources_do_not_reintroduce_legacy_signature_symbols() {
    let files = crate_source_files();
    assert!(
        !files.is_empty(),
        "guardrail must observe at least one crate source file"
    );

    let mut violations = Vec::new();
    for path in &files {
        let contents = fs::read_to_string(path).expect("crate source should be readable");
        for symbol in FORBIDDEN_SYMBOLS {
            if contains_whole_word(&contents, symbol) {
                violations.push(format!("{} reintroduces `{}`", path.display(), symbol));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "retired legacy signature symbols reappeared (docs/LEGACY_CLEANUP.md Phase 6):\n{}",
        violations.join("\n")
    );
}

#[test]
fn test_guardrail_word_boundary_matcher_distinguishes_current_types() {
    assert!(contains_whole_word(
        "pub legacy_status: SignatureStatus,",
        "SignatureStatus"
    ));
    assert!(!contains_whole_word(
        "status: DetailedSignatureStatus::Valid,",
        "SignatureStatus"
    ));
    assert!(!contains_whole_word(
        "status: CertificateSignatureStatus::Valid,",
        "SignatureStatus"
    ));
    assert!(!contains_whole_word(
        "entry.signer_primary_fingerprint.clone()",
        "signer_fingerprint"
    ));
    assert!(contains_whole_word(
        "pub signer_fingerprint: Option<String>,",
        "signer_fingerprint"
    ));
}
