//! # Packet module
//!
//! Handles everything in relationship to packets.
//!
//! [`Key generation and loading`] is handled seperately as well as
//! [`signing and verifying with external hashing`] applied.
//!
//! [`Key generation and loading`]: super::composed::key
//! [`signing and verifying with external hashing`]: super::composed::signed_key
//!
//! ```rust
//! # const DATA :&'static [u8] = b"Hello World";
//! # use pgp::composed::{self, KeyType, KeyDetails, SecretKey, SecretSubkey, key::SecretKeyParamsBuilder};
//! # use pgp::errors::Result;
//! # use pgp::packet::{self, KeyFlags, UserAttribute, UserId};
//! use pgp::crypto::{self, sym::SymmetricKeyAlgorithm, hash::HashAlgorithm, public_key::PublicKeyAlgorithm};
//! use pgp::types::{self, PublicKeyTrait, SecretKeyTrait, CompressionAlgorithm};
//! use smallvec::*;
//! #
//! # let mut key_params = SecretKeyParamsBuilder::default();
//! # key_params
//! #     .key_type(KeyType::Rsa(2048))
//! #     .can_create_certificates(false)
//! #     .can_sign(true)
//! #     .primary_user_id("Me <me@example.com>".into())
//! #     .preferred_symmetric_algorithms(smallvec![
//! #          SymmetricKeyAlgorithm::AES256,
//! #     ])
//! #     .preferred_hash_algorithms(smallvec![
//! #          HashAlgorithm::SHA2_256,
//! #     ])
//! #     .preferred_compression_algorithms(smallvec![
//! #          CompressionAlgorithm::ZLIB,
//! #     ]);
//! # let secret_key_params = key_params.build().expect("Must be able to create secret key params");
//! # let secret_key = secret_key_params.generate().expect("Failed to generate a plain key.");
//! # let passwd_fn = || String::new();
//! # let signed_secret_key = secret_key.sign(passwd_fn).expect("Must be able to sign its own metadata");
//! # let public_key = signed_secret_key.public_key();
//! use pgp::types::KeyTrait;
//! use pgp::packet::{SignatureConfigBuilder, Signature};
//!
//! let signing_key = signed_secret_key;
//! let verification_key = public_key;
//!
//!
//! let passwd_fn = || String::new();
//!
//! let now = chrono::Utc::now();
//!
//! let mut sig_cfg_bldr = SignatureConfigBuilder::default();
//! let sig_cfg = sig_cfg_bldr
//!      .version(packet::SignatureVersion::V4)
//!      .typ(packet::SignatureType::Binary)
//!      .pub_alg(PublicKeyAlgorithm::RSA)
//!      .hash_alg(HashAlgorithm::SHA2_256)
//!      .issuer(Some(signing_key.key_id()))
//!      .created(Some(now))
//!      .unhashed_subpackets(vec![]) // must be initialized
//!      .hashed_subpackets(vec![
//!           packet::Subpacket::SignatureCreationTime(now),
//!           packet::Subpacket::Issuer(signing_key.key_id()),
//!      ]) // must be initialized
//!      .build()
//!      .unwrap();
//!
//! let signature_packet = sig_cfg
//!      .sign(&signing_key, passwd_fn, DATA)
//!      .expect("Should sign");
//!
//! let mut signature_bytes = Vec::with_capacity(1024);
//!     let mut buff = std::io::Cursor::new(&mut signature_bytes);
//!     packet::write_packet(&mut buff, &signature_packet).expect("Write must succeed");
//!
//! signature_packet
//!      .verify(&verification_key, DATA)
//!      .expect("Failed to validate signature");
//!
//! ```

mod many;
mod packet_sum;
mod single;

#[macro_use]
mod secret_key_macro;
#[macro_use]
mod public_key_macro;

mod compressed_data;
mod key;
mod literal_data;
mod marker;
mod mod_detection_code;
mod one_pass_signature;
mod public_key_encrypted_session_key;
mod signature;
mod sym_encrypted_data;
mod sym_encrypted_protected_data;
mod sym_key_encrypted_session_key;
mod trust;
mod user_attribute;
mod user_id;

mod public_key_parser;
mod secret_key_parser;

pub use self::compressed_data::*;
pub use self::key::*;
pub use self::literal_data::*;
pub use self::marker::*;
pub use self::mod_detection_code::*;
pub use self::one_pass_signature::*;
pub use self::public_key_encrypted_session_key::*;
pub use self::signature::*;
pub use self::sym_encrypted_data::*;
pub use self::sym_encrypted_protected_data::*;
pub use self::sym_key_encrypted_session_key::*;
pub use self::trust::*;
pub use self::user_attribute::*;
pub use self::user_id::*;

pub use self::many::*;
pub use self::packet_sum::*;
