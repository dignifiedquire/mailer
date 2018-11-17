use errors::Result;

/// PGP as UTF-8 octets.
const PGP: [u8; 3] = [0x50, 0x47, 0x50];

/// Marker Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.8
#[derive(Debug, Clone)]
pub struct Marker {}

impl Marker {
    /// Parses a `Marker` packet from the given slice.
    pub fn from_slice(input: &[u8]) -> Result<Self> {
        ensure_eq!(input, &PGP[..], "invalid input");

        Ok(Marker {})
    }
}
