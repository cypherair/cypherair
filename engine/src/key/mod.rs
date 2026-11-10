//! Keys: the private-key handle, reading certificates, making keys, and the
//! bounds that every piece of key material is read under.

mod generate;
mod handle;
mod inspect;
mod material;

pub use generate::generate_portable_key;
pub use handle::PrivateKey;
pub use inspect::inspect_certificate;
pub use material::armor;

pub(crate) use material::certificate;
