use chrono::{DateTime, TimeZone, Utc};
use nom::{be_u32, be_u8, rest};
use num_traits::FromPrimitive;

use errors::Result;
use util::read_string_lossy;

/// Literal Data Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.9
#[derive(Debug, Clone)]
pub struct LiteralData {
    mode: DataMode,
    file_name: String,
    created: DateTime<Utc>,
    data: Vec<u8>,
}

#[derive(Debug, Copy, Clone, FromPrimitive)]
#[repr(u8)]
pub enum DataMode {
    Binary = b'b',
    Text = b't',
    Utf8 = b'u',
    Mime = b'm',
}

impl LiteralData {
    /// Parses a `LiteralData` packet from the given slice.
    pub fn from_slice(input: &[u8]) -> Result<Self> {
        let (_, pk) = parse(input)?;

        Ok(pk)
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

#[rustfmt::skip]
named!(parse<LiteralData>, do_parse!(
           mode: map_opt!(be_u8, DataMode::from_u8)
    >> name_len: be_u8
    >>     name: map!(take!(name_len), read_string_lossy)
    >>  created: map!(be_u32, |v| Utc.timestamp(i64::from(v), 0))
    >>     data: rest
    >> (LiteralData {
        mode,
        created,
        file_name: name,
        data: data.to_vec(),
    })
));
