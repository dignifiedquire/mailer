//! # rPGP
//!
//! rPGP is an OpenPGP implementation.
//!
//! Usage examples are available under the respective modules:
//! [Key generation and loading], [signing and verifying with external hashing], [packet based signing and verifying].
//!
//! [Key generation and loading]: crate::composed::key
//! [signing and verifying with external hashing]: crate::composed::signed_key
//! [packet based signing and verifying]: crate::packet

#![forbid(unsafe_code)]
#![deny(
    clippy::all,
    clippy::style,
    clippy::perf,
    clippy::complexity,
    clippy::correctness,
    clippy::result_unwrap_used,
    clippy::option_unwrap_used,
    rust_2018_idioms
)]
#![warn(clippy::nursery)]
#![allow(clippy::missing_const_for_fn, clippy::use_self)]

#[macro_use]
extern crate nom;
#[macro_use]
extern crate num_derive;
#[macro_use]
extern crate generic_array;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate derive_builder;
#[macro_use]
extern crate bitfield;
#[macro_use]
extern crate smallvec;

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

// public so it can be used in doc test
#[macro_use]
pub mod util;

#[macro_use]
pub mod errors;
pub mod armor;
pub mod base64_decoder;
pub mod base64_reader;
pub mod composed;
pub mod crypto;
pub mod de;
pub mod line_reader;
pub mod line_writer;
pub mod normalize_lines;
pub mod packet;
pub mod ser;
pub mod types;

// reexports for easier use
pub use self::composed::key::*;
pub use self::composed::*;
pub use self::packet::Signature;
