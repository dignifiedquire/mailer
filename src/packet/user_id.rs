use std::str;

use errors::Result;
use util::read_string_lossy;

/// User ID Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.11
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UserId(String);

impl UserId {
    /// Parses a `UserId` packet from the given slice.
    pub fn from_slice(input: &[u8]) -> Result<Self> {
        let id = read_string_lossy(input);

        Ok(UserId(id))
    }

    pub fn from_str(input: &str) -> Self {
        UserId(input.to_string())
    }
}
