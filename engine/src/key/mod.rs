//! Keys: the private-key handle, device-bound keys, reading certificates,
//! making keys, and the bounds that every piece of key material is read under.

mod device;
mod generate;
mod handle;
mod inspect;
mod material;

pub use device::{DeviceKey, DeviceKeyError, device_key_slots};
pub use generate::{generate_device_key, generate_portable_key};
pub use handle::PrivateKey;
pub use inspect::inspect_certificate;
pub use material::armor;

pub(crate) use handle::{Decryptor, Unwrapped};
pub(crate) use material::certificate;
