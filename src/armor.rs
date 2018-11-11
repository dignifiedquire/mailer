use std::collections::HashMap;
use std::io::Read;
use std::str;

use base64;
use byteorder::{BigEndian, ByteOrder};
use circular::Buffer;
use crc24;
use errors::{Error, Result};
use nom::{
    self, digit, line_ending, not_line_ending, InputIter, InputLength, Needed, Offset, Slice,
};
use util::base64_token as body_parser;

/// Armor block types.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BlockType {
    /// PGP Public key
    PublicKey,
    /// Public key DER encoded PKCS#1
    PublicKeyPKCS1,
    /// Public key DER encoded PKCS#8
    PublicKeyPKCS8,
    /// Public key OpenSSH
    PublicKeyOpenssh,
    /// PGP Private key
    PrivateKey,
    /// Private key DER encoded PKCS#1
    PrivateKeyPKCS1,
    /// Private key DER encoded PKCS#8
    PrivateKeyPKCS8,
    /// Private key OpenSSh
    PrivateKeyOpenssh,
    Message,
    MultiPartMessage(usize, usize),
    Signature,
    // gnupgp extension
    File,
}

/// Parses a single ascii armor header separator.
named!(armor_header_sep, tag!("-----"));

/// Parses the type inside of an ascii armor header.
#[rustfmt::skip]
named!(
    armor_header_type<BlockType>,
    alt_complete!(
        map!(tag!("PGP PUBLIC KEY BLOCK"), |_| BlockType::PublicKey)
      | map!(tag!("PGP PRIVATE KEY BLOCK"), |_| BlockType::PrivateKey)
      | do_parse!(
          tag!("PGP MESSAGE, PART ")
        >> x: digit
        >> y: opt!(preceded!(tag!("/"), digit))
        >> ({
            // unwraps are safe, as the parser already determined that this is a digit.
            let x: usize = str::from_utf8(x).unwrap().parse().unwrap();
            let y: usize = y
                .map(|s| str::from_utf8(s).unwrap().parse().unwrap())
                .unwrap_or(0);

            BlockType::MultiPartMessage(x, y)
        })
      )
      | map!(tag!("PGP MESSAGE"), |_| BlockType::Message)
      | map!(tag!("PGP SIGNATURE"), |_| BlockType::Signature)
      | map!(tag!("PGP ARMORED FILE"), |_| BlockType::File)

      // Lets also parse openssl formats :tada:

      // Public Key File PKCS#1
      | map!(tag!("RSA PUBLIC KEY"), |_| BlockType::PublicKeyPKCS1)
      // Public Key File PKCS#1
      | map!(tag!("DSA PUBLIC KEY"), |_| BlockType::PublicKeyPKCS1)
      // Public Key File PKCS#1
      | map!(tag!("EC PUBLIC KEY"), |_| BlockType::PublicKeyPKCS1)
      // Public Key File PKCS#8
      | map!(tag!("PUBLIC KEY"), |_| BlockType::PublicKeyPKCS8)

      // Public Key File Openssh
      | map!(tag!("OPENSSH PUBLIC KEY"), |_| BlockType::PublicKeyOpenssh)

      // Private Key File PKCS#1
      | map!(tag!("RSA PRIVATE KEY"), |_| BlockType::PrivateKeyPKCS1)
      // Private Key File PKCS#1
      | map!(tag!("DSA PRIVATE KEY"), |_| BlockType::PrivateKeyPKCS1)
      // Private Key File PKCS#1
      | map!(tag!("EC PRIVATE KEY"), |_| BlockType::PrivateKeyPKCS1)
      // Private Key File PKCS#8
      | map!(tag!("PRIVATE KEY"), |_| BlockType::PrivateKeyPKCS8)

      // Private Key File Openssh
      | map!(tag!("OPENSSH PRIVATE KEY"), |_| BlockType::PrivateKeyOpenssh)
    )
);

/// Parses a single armor header line.
named!(
    armor_header_line<BlockType>,
    do_parse!(
        armor_header_sep
            >> tag!("BEGIN ")
            >> typ: armor_header_type
            >> armor_header_sep
            >> line_ending
            >> (typ)
    )
);

/// Parses a single armor footer line
named!(
    armor_footer_line<BlockType>,
    do_parse!(
        armor_header_sep
            >> tag!("END ")
            >> typ: armor_header_type
            >> armor_header_sep
            >> alt_complete!(line_ending | eof!())
            >> (typ)
    )
);

/// Recognizes one or more key tokens.
fn key_token(input: &[u8]) -> nom::IResult<&[u8], &[u8]> {
    let input_length = input.input_len();

    for (idx, item) in input.iter_indices() {
        // are we done? ": " is reached
        if item == b':' && idx + 1 < input_length && input.slice(idx + 1..idx + 2)[0] == b' ' {
            return Ok((input.slice(idx + 2..), input.slice(0..idx)));
        }
    }

    Ok((input.slice(input_length..), input))
}

/// Parses a single key value pair, for the header.
named!(
    key_value_pair<(&str, &str)>,
    do_parse!(
        key: map_res!(key_token, str::from_utf8)
            >> value: map_res!(terminated!(not_line_ending, line_ending), str::from_utf8)
            >> (key, value)
    )
);

/// Parses a list of key value pairs.
named!(
    key_value_pairs<Vec<(&str, &str)>>,
    many0!(complete!(key_value_pair))
);

/// Parses the full armor header.
named!(
    armor_headers<HashMap<String, String>>,
    do_parse!(
        pairs: key_value_pairs
            >> (pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect())
    )
);

/// Armor Header
named!(armor_header(&[u8]) -> (BlockType, HashMap<String, String>), do_parse!(
    typ:     armor_header_line >>
    headers: armor_headers     >>
    (typ, headers)
));

/// Read the checksum from an base64 encoded buffer.
fn read_checksum(input: &[u8]) -> ::std::io::Result<u32> {
    let checksum = base64::decode_config(input, base64::MIME)
        .map_err(|_| ::std::io::ErrorKind::InvalidData)?;

    let mut buf = [0; 4];
    let mut i = checksum.len();
    for a in checksum.iter().rev() {
        buf[i] = *a;
        i -= 1;
    }

    Ok(BigEndian::read_u32(&buf))
}

named!(header_parser(&[u8]) -> (BlockType, HashMap<String, String>), do_parse!(
               take_until!("-----")
    >>   head: armor_header
    >>         many0!(line_ending)
    >> (head.0, head.1)
));

named!(
    footer_parser<(Option<&[u8]>, BlockType)>,
    do_parse!(
        // possible padding chars from base64
        opt!(pair!(many_m_n!(1, 3, tag!("=")), line_ending))
            >> opt!(line_ending)
            >> crc: opt!(preceded!(tag!("="), take!(4)))
            >> many0!(line_ending)
            >> footer: armor_footer_line
            >> (crc, footer)
    )
);

/// Streaming based ascii armor parsing.
pub struct Dearmor<R> {
    /// The ascii armor parsed block type.
    pub typ: Option<BlockType>,
    /// The headers found in the armored file.
    pub headers: HashMap<String, String>,
    /// Optional crc checksum
    pub checksum: Option<u32>,
    /// track what we are currently parsing
    current_part: Part,
    /// internal buffer of data already read from the underlying source
    buffer: Buffer,
    /// the underlying data source
    inner: R,
    /// the current capacity of our buffer
    capacity: usize,
}

/// Internal indicator, where in the parsing phase we are
#[derive(Debug)]
enum Part {
    Header,
    Body,
    Footer,
}

impl<R: ::std::io::Read> Dearmor<R> {
    pub fn new(input: R) -> Dearmor<R> {
        Dearmor {
            typ: None,
            headers: HashMap::new(),
            checksum: None,
            current_part: Part::Header,
            buffer: Buffer::with_capacity(32 * 1024),
            capacity: 32 * 1024,
            inner: input,
        }
    }
}

impl<R: ::std::io::Read> ::std::io::Read for Dearmor<R> {
    #[allow(unused)] // for some reason the compiler thinks `needed` is unneeded.
    fn read(&mut self, into: &mut [u8]) -> ::std::io::Result<usize> {
        // TODO: const/configurable
        let max_capacity = 1024 * 1024 * 1024;
        // how much data have we read into our target `into`
        let mut read = 0;
        // how much data do we want to read
        let into_len = into.len();

        while read < into_len {
            let b = &mut self.buffer;
            let sz = self.inner.read(b.space())?;
            b.fill(sz);

            if b.available_data() == 0 {
                break;
            }

            let mut needed = None;
            'outer: while read < into_len {
                let l = match self.current_part {
                    Part::Header => match header_parser(b.data()) {
                        Ok((remaining, (typ, header))) => {
                            self.typ = Some(typ);
                            self.headers = header;
                            self.current_part = Part::Body;
                            b.data().offset(remaining)
                        }
                        Err(err) => match err {
                            nom::Err::Incomplete(n) => {
                                needed = Some(n);
                                break 'outer;
                            }
                            _ => {
                                return Err(::std::io::Error::new(
                                    ::std::io::ErrorKind::InvalidData,
                                    "header parsing failure",
                                ));
                            }
                        },
                    },
                    Part::Body => {
                        let data = if into_len > b.data().len() {
                            b.data()
                        } else {
                            &b.data()[0..into_len]
                        };

                        match body_parser(data) {
                            Ok((remaining, bytes)) => {
                                self.current_part = Part::Body;
                                into[0..bytes.len()].copy_from_slice(bytes);
                                let bytes_read = b.data().offset(remaining);
                                read += bytes_read;

                                bytes_read
                            }
                            Err(err) => match err {
                                nom::Err::Incomplete(n) => {
                                    needed = Some(n);
                                    break 'outer;
                                }
                                nom::Err::Error(_) => {
                                    // this happens when there are no more base64 tokens, so lets move
                                    // to parse the rest
                                    self.current_part = Part::Footer;
                                    0
                                }
                                nom::Err::Failure(_) => {
                                    return Err(::std::io::Error::new(
                                        ::std::io::ErrorKind::InvalidData,
                                        "body parsing failure",
                                    ));
                                }
                            },
                        }
                    }
                    Part::Footer => match footer_parser(b.data()) {
                        Ok((remaining, (checksum, footer_typ))) => {
                            if let Some(ref header_typ) = self.typ {
                                if header_typ != &footer_typ {
                                    return Err(::std::io::Error::new(
                                        ::std::io::ErrorKind::InvalidData,
                                        format!(
                                            "missmatch in armor ascii footer: {:?} != {:?}",
                                            self.typ, footer_typ
                                        ),
                                    ));
                                }
                            }

                            if let Some(raw) = checksum {
                                self.checksum = Some(read_checksum(raw)?);
                            }

                            b.data().offset(remaining)
                        }
                        Err(err) => match err {
                            nom::Err::Incomplete(n) => {
                                needed = Some(n);
                                break 'outer;
                            }
                            _ => {
                                return Err(::std::io::Error::new(
                                    ::std::io::ErrorKind::InvalidData,
                                    format!("footer parsing failure {:?}", err),
                                ));
                            }
                        },
                    },
                };

                b.consume(l);

                // break if we filled the input
                if read == into_len {
                    break;
                }

                if let Some(Needed::Size(sz)) = needed {
                    if sz > b.capacity() && self.capacity * 2 < max_capacity {
                        self.capacity *= 2;
                        b.grow(self.capacity);
                    }
                }
            }
        }

        Ok(read)
    }
}

// helper function to parse all data at once
pub fn parse<R: ::std::io::Read>(
    input: R,
) -> Result<(BlockType, HashMap<String, String>, Vec<u8>)> {
    let mut dearmor = Dearmor::new(input);

    // estimate size
    let mut bytes = Vec::new();
    dearmor.read_to_end(&mut bytes)?;

    // TODO: streaming base64 decoding

    let decoded = base64::decode_config(&bytes, base64::MIME)?;

    if let Some(expected) = dearmor.checksum {
        let actual = crc24::hash_raw(&decoded);

        if expected != actual {
            return Err(Error::InvalidChecksum);
        }
    }

    Ok((dearmor.typ.unwrap(), dearmor.headers, decoded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::io::Read;

    #[test]
    fn test_armor_header_line() {
        assert_eq!(
            armor_header_line(&b"-----BEGIN PGP MESSAGE-----\n"[..]).unwrap(),
            (&b""[..], BlockType::Message)
        );

        assert_eq!(
            armor_header_line(&b"-----BEGIN PGP MESSAGE, PART 3/14-----\n"[..]).unwrap(),
            (&b""[..], BlockType::MultiPartMessage(3, 14))
        );

        assert_eq!(
            armor_header_line(&b"-----BEGIN PGP MESSAGE, PART 14-----\n"[..]).unwrap(),
            (&b""[..], BlockType::MultiPartMessage(14, 0))
        );
    }

    #[test]
    fn test_armor_headers() {
        let mut map = HashMap::new();
        map.insert("Version".to_string(), "12".to_string());
        map.insert("special-stuff".to_string(), "cool12.0".to_string());
        map.insert("some:colon".to_string(), "with:me".to_string());

        assert_eq!(
            armor_headers(
                &b"Version: 12\r\nspecial-stuff: cool12.0\r\nsome:colon: with:me\r\n"[..],
            )
            .unwrap(),
            (&b""[..], map)
        );
    }

    #[test]
    fn test_armor_header() {
        let mut map = HashMap::new();
        map.insert("Version".to_string(), "1.0".to_string());
        map.insert("Mode".to_string(), "Test".to_string());

        assert_eq!(
            armor_header(&b"-----BEGIN PGP MESSAGE-----\nVersion: 1.0\nMode: Test\n"[..],).unwrap(),
            (&b""[..], (BlockType::Message, map))
        );

        let mut map = HashMap::new();
        map.insert("Version".to_string(), "GnuPG v1".to_string());

        assert_eq!(
            armor_header(&b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v1\n"[..],)
                .unwrap(),
            (&b""[..], (BlockType::PublicKey, map))
        );
    }

    #[test]
    fn test_parse_armor_small() {
        let mut map = HashMap::new();
        map.insert("Version".to_string(), "GnuPG v1".to_string());

        let c = Cursor::new(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\
             Version: GnuPG v1\n\
             \n\
             aGVsbG8gd29ybGQ=\n\
             -----END PGP PUBLIC KEY BLOCK-----\n",
        );
        let (typ, headers, res) = parse(c).unwrap();

        assert_eq!(typ, (BlockType::PublicKey));
        assert_eq!(headers, map);
        assert_eq!(res.as_slice(), &b"hello world"[..]);
    }

    #[test]
    fn test_parse_armor_full() {
        let mut map = HashMap::new();
        map.insert("Version".to_string(), "GnuPG v1".to_string());

        let c = Cursor::new(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\
             Version: GnuPG v1\n\
             \n\
             mQGiBEigu7MRBAD7gZJzevtYLB3c1pE7uMwu+zHzGGJDrEyEaz0lYTAaJ2YXmJ1+\n\
             IvmvBI/iMrRqpFLR35uUcz2UHgJtIP+xenCF4WIhHv5wg3XvBvTgG/ooZaj1gtez\n\
             miXV2bXTlEMxSqsZKvkieQRrMv3eV2VYhgaPvp8xJhl+xs8eVhlrmMv94wCgzWUw\n\
             BrOICLPF5lANocvkqGNO3UUEAMH7GguhvXNlIUncqOpHC0N4FGPirPh/6nYxa9iZ\n\
             kQEEg6mB6wPkaHZ5ddpagzFC6AncoOrhX5HPin9T6+cPhdIIQMogJOqDZ4xsAYCY\n\
             KwjkoLQjfMdS5CYrMihFm4guNMKpWPfCe/T4TU7tFmTug8nnAIPFh2BNm8/EqHpg\n\
             jR4JA/9wJMxv+2eFuFGeLtiPjo+o2+AfIxTTEIlWyNkO+a9KkzmPY/JP4OyVGKjM\n\
             V+aO0vZ6FamdlrXAaAPm1ULmY5pC15P/hNr0YAbN28Y8cwNGuuKGbiYvYD35KKhs\n\
             5c5/pfMy0rgDElhFTGd4rpZdkHei3lwF5cyV0htv5s2lwGJKnrQnQW5kcm9pZCBT\n\
             ZWN1cml0eSA8c2VjdXJpdHlAYW5kcm9pZC5jb20+iGAEExECACAFAkigu7MCGwMG\n\
             CwkIBwMCBBUCCAMEFgIDAQIeAQIXgAAKCRBzHmufAFQPw547AKDIDW3mDx+84xk1\n\
             EfzH/uNQQLYBBgCeMabHPlx+2+IGnfPsQ8UsxMPLFnO5BA0ESKC72BAQALKb8W8l\n\
             U3Xs+lbquuVEA5x+mNnJriRnq1q1ZA8J43z0lCqT6n+q/nICuE/SjGxfp+8G/K3/\n\
             LrIfBWLLQHZMQyk/1Eild/ZoRxNAbjTGiQY6HWrZOd+Z2fWiSN03nSSpWImPbua3\n\
             6LwSRRZNmZ77tdY0hI9TqJzqax1WQWk7IxfWubNTbNsPiktm/d6C2P04OkKOAmr8\n\
             QCqKLLCO578zYLTgraL6F4g2YVurGgAB1KFSX2F8fh6Igr+pIW/ytoS9n2H+uecR\n\
             l+2RB6Pq7MahwZvPPeMavwUMPQpOI6Or3pYZTzp/IJWNyL6MOBzV5q4gkD0xYtEq\n\
             Ihr1hX1IdiGdOA4oH1Rk1K/XIPwLelQdYp3ftiReh4/Gb3kfKCxpmMXL1f/ndx6N\n\
             zIiqweDU5mZBpXBsBzFZfUDALL4VGqpc2eEltkVtD0RuQI2YaImBjOPsHI4StN5t\n\
             2OspWke4xJGf0PqRVjTDJmtUrIJX4X5Fh8M85unHYYIpBCaDbM/7/xIaNQbQfdeO\n\
             6yqGrj/0WAjL34wbo4D12BiPeoUTreD60aNwmpu5z1NRPS2Wn+6kTIHGhf47wGTZ\n\
             v9OFYWhgSs3INpna4VA4E8SpOWPd8LFYLs9clAlaUhqJyLJ3JlmXmhGnWM41z+p9\n\
             RA8UQXhvQcvYJSR77SC4O503wdVKJ07OH6WbAAMFD/4yjBZ+X7QBIKTLHXAIQBjB\n\
             526iOhmfxyIgmX4vWcggJFZrBxPFulkGJj65Mwr9AwZeIceukKQUGcf2LpEoIdZY\n\
             dP8gEshRDZQ1Y3GDD9ukChRDoK9kFIxnYmH8euU/TwTPtAEEDASfwEZnM5DcJQOA\n\
             Q6G3GVKr/8uwmT5hUn5sR2L9vmrjw1nPkfZeDQNBmeTI8A+byosp6Nxl8thJIGNt\n\
             8UTa02+g/nbf+ODRrEf3xeeFUNb14kTqULNT/hTj8/6xDwxwaF2ms60kYxA/EXDB\n\
             21jqmhnfUwjSa++R38Qig9tGwOo83Z7uNCqtU3caFW1P55iD/Sju/ZecHVSgfq6j\n\
             2H7mNWfvB9ILkS7w1w/InjEA7LpY9jtmPKDIYYQ7YGZuxFwOxtw69ulkS6ddc1Pt\n\
             AQ5oe0d59rBicE8R7rBCxwzMihG5ctJ+a+t4/MHqi6jy/WI9OK+SwWmCeT1nVy6F\n\
             NZ00QOPe89DFBCqhj4qSGfjOtCEKAM7SOhkyEYJ8jk5KrsLOcWPOM9i3uus1RquG\n\
             XJ2Cljt6zJYtEnpkjrw+Ge0SBDNEMGZEBLbEZKECtNJ2NBrMRKYeAseCGNQ+uJOz\n\
             8vL7ztUKoi1SbFGuHkv5N2NmPq42QrN8dftW01DceGDnJ1KHRvCUbpPcyQYFhRFb\n\
             nxd3tMIEGO83iEmozvJfB4hJBBgRAgAJBQJIoLvYAhsMAAoJEHMea58AVA/D6ewA\n\
             ninKQSW+oL4z28F3T0GHag38WeWyAJ45d7dx4z0GxhTm2b9DclLombY+nw==\n\
             =XyBX\n\
             -----END PGP PUBLIC KEY BLOCK-----\n",
        );
        let (typ, headers, decoded) = parse(c).unwrap();

        assert_eq!(typ, (BlockType::PublicKey));
        assert_eq!(headers, map);
        assert_eq!(decoded.len(), 1675);
        assert_eq!(decoded.len() % 3, 1); // two padding chars
    }

    #[test]
    fn test_parse_armor_full_no_header() {
        let c = Cursor::new(
            "-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEAxp4sIUtrNBl4Vbd4075CmtHmwxTc0FhQIGw36kptbrWReLb9
Np0RQylKyc6qUruxZlCdPVFo7iX3vs272/0GEakPv0DAsKGbe1nTsMyxxz0o3dP4
JQOlOGEnpETa0ybfPLMX1+qNiBdm7HLjqcP5+S0Exb0Z0deFNIhEP6XckUEgHmwA
/AdDdUUKwwvZeZOi4XyBVt0vXzwM/+84ro27O+CZm9Du3qe1jTIsX7jUrqsUBhp9
eUwa1jXfXuJJo9b4/GeP4S9x8U7ho+BQ6/HH03dzcKaY3FftanCZkcwxfGBBUiCK
pIA5WgKimLcgP2R75Y3jilDoBh5HyIdGXo0aFwIDAQABAoIBAQCBXLIHeXS4eUJc
KeSjnQ8KgV4Yf3UWqf5+L533lkRSUCYQhrbDpGeC49kXOejLe/4eUrEnJ+f8/HOx
LZSGwvT5+bAM9CLMqGV5YNc1Fw1PZHFCkfXUPdyVrQnBvyr7Th0mDsuf0OAf3IYn
yOipQMCGX6D1HaY8e3AB+CLjhab0X1vAwvqzPb/HIdtMhRWlJxzbuqnE3kr+Ccvz
us3vmD4VBp0CF0f+yblcibMCHdHY6j8Ir6Qeq6Mbd6lEXRPW1TgUqP15idVaJ4AF
1kGXDW9O0ycgrbopGZfk5yY60fEHGdr4QYjx2Gtx2xQcnPcjJ+j5kGgubKWxNhJE
Qx7DPdYxAoGBAP29S+wD1df0U+Tr0x06N6M/nSjNacGs12Oq/ehNJHhTYUO9fWUl
M2X/MXRMMMGsnGaLNsrLao9Jnq0ZU5GFICWYeVBvaCvRrGngbqJBy8jRv+QYyaQs
AckLcdgLGvjhcXonHDcbcxpug7/qFwakT+KY2s11FrHBEzbAIuDiSSKfAoGBAMhj
KPkrjWJh3xxpFrFnGYj5aF86ExrPe2LAP/8F6Ez7dQN+4bA6O5F4hpJ/X0q/6s0n
IBljo/DgARCBjbwDSaAMEWdm8HDeBhJsSCdQHW38ylaRDi8CQDKR60N3a/tV1MRJ
4fKoHZ+7HH3wc+Bjv3oDovwVyUMG7ekCjeqbqI2JAoGBAOkhYX5Jz9KJBAPSwLeb
4760FfuFL+PooEVMt9kV96ouQbFxiqLB2UWfgJqv3iQ0Kcb1pbQRzag1Jfs4x9Vu
ESk5vEyw729DSDxHHp8qAMhUHxC9zZZvcHx9bW3oVjHRQOfQw1XGfK0OWTKdK+bI
VTWG55HaQK21DahCREmG31dVAoGBALBH80KHmsAioziGBi2YKjGCXtvu5eGfBsdP
orzBQKOATmb91qLGB6MoaRI1NOo4POGu+qD7M7xyAt23aq0sIzfFhgX1260e1C6e
zTawVsNsL7/JqbWXAEy8az+VrguTbTIkYL2sQStEWoM75WRPu6El09p5e+0YCnEC
C0CJINUpAoGBAPF1fpPINHlUW+Bvo4Nj3935QgZI47yTplDusptyfYgFYXw6ZYel
y5Zgv9TWZlmW9FDTp4XVgn5zQTEN1LdL7vNXWV9aOvfrqPk5ClBkxhndgq7j6MFs
9+9V06HJDIsSrC0D/ajIkP+iT9Hd6eEZMkJ6y6XtTbkJGYt2zOtnrpb6
-----END RSA PRIVATE KEY-----\n",
        );
        let (typ, _, _) = parse(c).unwrap();

        assert_eq!(typ, (BlockType::PrivateKeyPKCS1));
    }

    #[test]
    fn test_dearmor_small_stream() {
        let mut map = HashMap::new();
        map.insert("Version".to_string(), "GnuPG v1".to_string());

        let c = Cursor::new(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\
             Version: GnuPG v1\n\
             \n\
             aGVsbG8gd29ybGQ=\n\
             -----END PGP PUBLIC KEY BLOCK-----\n",
        );

        let mut dec = Dearmor::new(c);

        let mut res = vec![0u8; 5];
        let read = dec.read(&mut res).unwrap();

        // first read reads the header
        assert_eq!(dec.typ, Some(BlockType::PublicKey));
        assert_eq!(dec.headers, map);

        assert_eq!(read, 5);
        assert_eq!(res.as_slice(), &b"aGVsb"[..]);

        let read = dec.read(&mut res).unwrap();
        assert_eq!(read, 5);
        assert_eq!(res.as_slice(), &b"G8gd2"[..]);

        let read = dec.read(&mut res).unwrap();
        assert_eq!(read, 5);
        assert_eq!(res.as_slice(), &b"9ybGQ"[..]);

        let read = dec.read(&mut res).unwrap();
        assert_eq!(read, 0);
        assert_eq!(res.as_slice(), &b"9ybGQ"[..]); // unchanged
    }

    #[test]
    fn test_key_value_pair() {
        assert_eq!(
            key_value_pair(&b"hello: world\n"[..]).unwrap(),
            (&b""[..], ("hello", "world")),
            "single"
        );

        assert_eq!(
            key_value_pair(&b"hello: world\nother content"[..]).unwrap(),
            (&b"other content"[..], ("hello", "world")),
            "with rest"
        );
    }

    #[test]
    fn test_key_value_pairs() {
        assert_eq!(
            key_value_pairs(&b"hello: world\ncool: stuff\n"[..]).unwrap(),
            (&b""[..], vec![("hello", "world"), ("cool", "stuff")]),
            "single"
        );

        assert_eq!(
            key_value_pairs(&b"hello: world\ncool: stuff\nother content"[..]).unwrap(),
            (
                &b"other content"[..],
                vec![("hello", "world"), ("cool", "stuff")]
            ),
            "with rest"
        );
    }

    #[test]
    fn test_body_parser() {
        assert_eq!(
            body_parser(&b"abcabc+==\n=hello"[..]),
            Ok((&b"==\n=hello"[..], &b"abcabc+"[..]))
        );
        assert_eq!(
            body_parser(&b"abcabc+==\n-other"[..]),
            Ok((&b"==\n-other"[..], &b"abcabc+"[..]))
        );

        assert_eq!(body_parser(&b"ab++\n"[..]), Ok((&b""[..], &b"ab++\n"[..])));

        assert_eq!(body_parser(&b"ab"[..]), Ok((&b""[..], &b"ab"[..])));
    }

    #[test]
    fn test_footer_parser() {
        assert_eq!(
            footer_parser(&b"=4JBj\r\n-----END PGP PUBLIC KEY BLOCK-----\r\n"[..]),
            Ok((&b""[..], (Some(&b"4JBj"[..]), BlockType::PublicKey)))
        );

        assert_eq!(
            footer_parser(&b"==\n=XyBX\n-----END PGP PUBLIC KEY BLOCK-----\n"[..]),
            Ok((&b""[..], (Some(&b"XyBX"[..]), BlockType::PublicKey)))
        );
    }
}
