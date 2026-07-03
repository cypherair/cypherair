use super::*;

fn mlkem_public_with_all_coefficients(value: u16) -> Vec<u8> {
    assert!(value < 4096);
    let low = value;
    let high = value;
    let chunk = [
        (low & 0xFF) as u8,
        ((low >> 8) as u8 & 0x0F) | (((high & 0x0F) as u8) << 4),
        (high >> 4) as u8,
    ];
    let mut key = Vec::with_capacity(MLKEM768_PUBLIC_KEY_LENGTH);
    for _ in 0..(MLKEM768_PACKED_VECTOR_LENGTH / 3) {
        key.extend_from_slice(&chunk);
    }
    // Seed rho: opaque, non-zero.
    key.extend_from_slice(&[0xABu8; 32]);
    assert_eq!(key.len(), MLKEM768_PUBLIC_KEY_LENGTH);
    key
}

#[test]
fn mlkem_public_key_validation_accepts_canonical_coefficients() {
    assert!(validate_mlkem768_public_key(&mlkem_public_with_all_coefficients(0)).is_ok());
    assert!(validate_mlkem768_public_key(&mlkem_public_with_all_coefficients(1)).is_ok());
    assert!(validate_mlkem768_public_key(&mlkem_public_with_all_coefficients(MLKEM_Q - 1)).is_ok());
}

#[test]
fn mlkem_public_key_validation_rejects_non_canonical_coefficients() {
    assert!(validate_mlkem768_public_key(&mlkem_public_with_all_coefficients(MLKEM_Q)).is_err());
    assert!(validate_mlkem768_public_key(&mlkem_public_with_all_coefficients(4095)).is_err());
}

#[test]
fn mlkem_public_key_validation_rejects_bad_shapes() {
    assert!(validate_mlkem768_public_key(&[0x01u8; 100]).is_err());
    assert!(validate_mlkem768_public_key(&[0u8; MLKEM768_PUBLIC_KEY_LENGTH]).is_err());
}

#[test]
fn mldsa_public_key_validation_rejects_bad_shapes() {
    assert!(validate_mldsa65_public_key(&[0x01u8; 100]).is_err());
    assert!(validate_mldsa65_public_key(&[0u8; MLDSA65_PUBLIC_KEY_LENGTH]).is_err());
    assert!(validate_mldsa65_public_key(&[0x01u8; MLDSA65_PUBLIC_KEY_LENGTH]).is_ok());
}
