//! Shared fixture loaders for integration tests.

use std::path::Path;

/// Load a fixture file from the fixtures directory.
#[allow(dead_code)]
pub fn load_fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("Failed to load fixture {}: {}", name, e))
}

/// Load the expected plaintext used to generate fixtures.
#[allow(dead_code)]
pub fn expected_plaintext() -> Vec<u8> {
    load_fixture("gpg_plaintext.txt")
}
