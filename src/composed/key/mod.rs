//! Internal key definitions
//!
//! These APIs do not provide guaranteed RFC4880 compliance,
//! since hashing is to be done externally.
//!
//!
//! # Generating a signed secret key and deriving a public key
//!
//! ```rust
//! use pgp::composed::{KeyType, KeyDetails, SecretKey, SecretSubkey, key::SecretKeyParamsBuilder};
//! use pgp::errors::Result;
//! use pgp::packet::{KeyFlags, UserAttribute, UserId};
//! use pgp::types::{PublicKeyTrait, SecretKeyTrait, CompressionAlgorithm};
//! use pgp::crypto::{sym::SymmetricKeyAlgorithm, hash::HashAlgorithm};
//! use smallvec::*;
//!
//! let mut key_params = SecretKeyParamsBuilder::default();
//! key_params
//!     .key_type(KeyType::Rsa(2048))
//!     .can_create_certificates(false)
//!     .can_sign(true)
//!     .primary_user_id("Me <me@example.com>".into())
//!     .preferred_symmetric_algorithms(smallvec![
//!         SymmetricKeyAlgorithm::AES256,
//!     ])
//!     .preferred_hash_algorithms(smallvec![
//!         HashAlgorithm::SHA2_256,
//!     ])
//!     .preferred_compression_algorithms(smallvec![
//!         CompressionAlgorithm::ZLIB,
//!     ]);
//! let secret_key_params = key_params.build().expect("Must be able to create secret key params");
//! let secret_key = secret_key_params.generate().expect("Failed to generate a plain key.");
//! let passwd_fn = || String::new();
//! let signed_secret_key = secret_key.sign(passwd_fn).expect("Must be able to sign its own metadata");
//! let public_key = signed_secret_key.public_key();
//! ```
//!
//! [Packet based signing and verifying] as well as
//! [signing and verifying with external hashing] are demoed seperately.
//!
//! [Packet based signing and verifying]: super::super::packet
//! [signing and verifying with external hashing]: super::signed_key
//!
//! # Loading a public key and listing its details
//!
//! ```rust
//! use pgp::composed::parse_public_keys;
//! use pgp::types::KeyTrait;
//! use std::path::Path;
//!
//! let mut path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/debian-10-archive-key.asc");
//!
//! let keys = parse_public_keys(&std::fs::read(&path).unwrap()).unwrap();
//!
//! for key in &keys {
//!     println!(
//!         "key {:?} {:?} {:?}",
//!         key.key_id(),
//!         key.fingerprint(),
//!         &key.details
//!     );
//!
//!     for subkey in &key.public_subkeys {
//!         println!("subkey {:?} {:?}", subkey.key_id(), subkey.fingerprint());
//!     }
//! }
//! ```

mod builder;
mod public;
mod secret;
mod shared;

use std::io::Cursor;

use crate::{Deserializable, SignedPublicKey};

pub use self::builder::*;
pub use self::public::*;
pub use self::secret::*;
pub use self::shared::*;

/// Parse one or more public keys from binary or ascii armored format.
///
/// If any part of the data failed to parse the whole operation will fail.
///
/// This is a convenience wrapper around [`SignedPublicKey::from_bytes_many()`]
/// and [`SignedPublicKey::from_armor_many()`].
pub fn parse_public_keys(data: &[u8]) -> Result<Vec<SignedPublicKey>, crate::errors::Error> {
    // Most significant bit of first byte of a binary PGP packet is always 1,
    // use that to distinguish ascii armored key files from binary key files.
    // Ref: https://tools.ietf.org/html/rfc4880#section-4.2
    // In theory e.g. 'asc' files should be ascii armored but often they just aren't.
    if data[0] & 0x80 != 0 {
        SignedPublicKey::from_bytes_many(Cursor::new(data)).collect::<Result<Vec<_>, _>>()
    } else {
        // Note that this discards the second part of the returned tuple,
        // which contains the ascii armor headers, if any.
        SignedPublicKey::from_armor_many(Cursor::new(data))?
            .0
            .collect::<Result<Vec<_>, _>>()
    }
}
