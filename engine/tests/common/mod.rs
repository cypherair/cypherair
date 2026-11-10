//! Shared test utilities for the engine's integration tests.
#![allow(dead_code)]

pub mod fixtures;
pub mod format;
pub mod gnupg;
pub mod keys;
pub mod messages;
pub mod pq;
pub mod sq;
pub mod tamper;

pub fn load_fixture(name: &str) -> Vec<u8> {
    fixtures::load_fixture(name)
}
