//! Rule E13: the unlock stretch gives its pinned answer and refuses inputs out
//! of range.

use cypher_engine::{EngineError, stretch_unlock_passphrase};

const PASSPHRASE: &[u8] = b"correct horse battery staple";
const SALT: [u8; 16] = [0x01; 16];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The vault's profile: 64 MiB, three passes, one lane. A change here locks
/// every user out of their vault.
#[test]
fn e13_pinned_answer() {
    let output = stretch_unlock_passphrase(PASSPHRASE, SALT.to_vec(), 65_536, 3, 1).unwrap();
    assert_eq!(
        hex(&output),
        "2059d35e11f775944efac46541cfcd82013946a4ce55030871f5891aacf73b07"
    );
}

#[test]
fn e13_refuses_inputs_out_of_range() {
    let refused = [
        (&[][..], SALT.to_vec(), 8_192, 1, 1),
        (PASSPHRASE, SALT[..15].to_vec(), 8_192, 1, 1),
        (PASSPHRASE, SALT.to_vec(), 8_191, 1, 1),
        (PASSPHRASE, SALT.to_vec(), 1_048_577, 1, 1),
        (PASSPHRASE, SALT.to_vec(), 8_192, 0, 1),
        (PASSPHRASE, SALT.to_vec(), 8_192, 17, 1),
        (PASSPHRASE, SALT.to_vec(), 8_192, 1, 0),
        (PASSPHRASE, SALT.to_vec(), 8_192, 1, 9),
    ];
    for (passphrase, salt, memory_kib, iterations, parallelism) in refused {
        assert_eq!(
            stretch_unlock_passphrase(passphrase, salt, memory_kib, iterations, parallelism)
                .unwrap_err(),
            EngineError::KdfOutOfRange,
            "{memory_kib} KiB, {iterations} passes, {parallelism} lanes"
        );
    }
    for (memory_kib, iterations, parallelism) in [(8_192, 16, 1), (8_192, 1, 8)] {
        assert!(
            stretch_unlock_passphrase(
                PASSPHRASE,
                SALT.to_vec(),
                memory_kib,
                iterations,
                parallelism
            )
            .is_ok()
        );
    }
}
