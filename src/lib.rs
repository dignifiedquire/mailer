#[macro_use]
extern crate nom;
extern crate base64;
extern crate byteorder;
extern crate crc24;
extern crate openssl;
#[macro_use]
extern crate enum_primitive;
extern crate chrono;
#[macro_use]
extern crate failure;
extern crate circular;
extern crate itertools;

#[cfg(test)]
#[macro_use]
extern crate hex_literal;

pub mod email;
pub use composed::key::*;

// public so it can be used in doc test
pub mod util;

mod armor;
mod composed;
mod errors;
mod packet;
