//! Messages: recipients and the outgoing format, encrypting, decrypting, the
//! signature verdict, and the header that says what a message is.

mod decrypt;
mod encrypt;
mod header;
pub(crate) mod recipients;
mod verdict;

pub use decrypt::decrypt;
pub use encrypt::encrypt;
pub use recipients::outgoing_format;
