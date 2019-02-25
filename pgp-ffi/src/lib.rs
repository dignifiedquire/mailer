#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

extern crate hex;
extern crate libc;
extern crate pgp;

use std::ffi::{CStr, CString};
use std::io::Cursor;
use std::mem::transmute;
use std::os::raw::c_char;
use std::slice::from_raw_parts;

use pgp::composed::{
    from_armor_many, KeyType, PublicOrSecret, SecretKeyParamsBuilder, SignedPublicKey,
    SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::{HashAlgorithm, SymmetricKeyAlgorithm};
use pgp::errors::Result;
use pgp::ser::Serialize;
use pgp::types::{CompressionAlgorithm, KeyTrait, SecretKeyTrait};

// TODO: Add error handling.

pub type signed_secret_key = SignedSecretKey;
pub type signed_public_key = SignedPublicKey;
pub type public_or_secret_key = PublicOrSecret;

/// Generates a new RSA key.
#[no_mangle]
pub unsafe extern "C" fn rpgp_create_rsa_skey(
    bits: u32,
    user_id: *const c_char,
) -> *mut signed_secret_key {
    let user_id = CStr::from_ptr(user_id);
    let user_id_str = user_id.to_str().expect("invalid user id");
    let key = create_key(KeyType::Rsa(bits), KeyType::Rsa(bits), user_id_str)
        .expect("failed to generate key");

    Box::into_raw(Box::new(key))
}

/// Generates a new x25519 key.
#[no_mangle]
pub unsafe extern "C" fn rpgp_create_x25519_skey(user_id: *const c_char) -> *mut signed_secret_key {
    let user_id = CStr::from_ptr(user_id);
    let user_id_str = user_id.to_str().expect("invalid user id");
    let key =
        create_key(KeyType::EdDSA, KeyType::ECDH, user_id_str).expect("failed to generate key");

    Box::into_raw(Box::new(key))
}

/// Serialize a secret key into its byte representation.
#[no_mangle]
pub unsafe extern "C" fn rpgp_skey_to_bytes(skey_ptr: *mut signed_secret_key) -> *mut cvec {
    let skey = &*skey_ptr;

    let mut res = Vec::new();
    skey.to_writer(&mut res).expect("failed to serialize key");

    Box::into_raw(Box::new(res.into()))
}

/// Get the signed public key matching the given private key. Only works for non password protected keys.
#[no_mangle]
pub unsafe extern "C" fn rpgp_skey_public_key(
    skey_ptr: *mut signed_secret_key,
) -> *mut signed_public_key {
    let skey = &*skey_ptr;

    let pkey = skey.public_key();
    let signed_pkey = pkey.sign(&skey, || "".into()).expect("failed to sign key");

    Box::into_raw(Box::new(signed_pkey))
}

/// Returns the KeyID for the passed in key.
#[no_mangle]
pub unsafe extern "C" fn rpgp_skey_key_id(ptr: *mut signed_secret_key) -> *mut c_char {
    let key = &*ptr;
    let id = CString::new(hex::encode(key.key_id().unwrap())).unwrap();

    id.into_raw()
}

/// Free the memory of a secret key.
#[no_mangle]
pub unsafe extern "C" fn rpgp_skey_drop(skey_ptr: *mut signed_secret_key) {
    let _skey: Box<signed_secret_key> = transmute(skey_ptr);
    // Drop
}

#[no_mangle]
pub unsafe extern "C" fn rpgp_pkey_to_bytes(pkey_ptr: *mut signed_public_key) -> *mut cvec {
    let pkey = &*pkey_ptr;

    let mut res = Vec::new();
    pkey.to_writer(&mut res).expect("failed to serialize key");

    Box::into_raw(Box::new(res.into()))
}

/// Returns the KeyID for the passed in key.
#[no_mangle]
pub unsafe extern "C" fn rpgp_pkey_key_id(ptr: *mut signed_public_key) -> *mut c_char {
    let key = &*ptr;
    let id = CString::new(hex::encode(key.key_id().unwrap())).unwrap();

    id.into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn rpgp_pkey_drop(pkey_ptr: *mut signed_public_key) {
    let _pkey: Box<signed_public_key> = transmute(pkey_ptr);
    // Drop
}

/// Represents a vector.
#[repr(C)]
pub struct cvec {
    data: *mut u8,
    len: libc::size_t,
}

impl Into<cvec> for Vec<u8> {
    fn into(mut self) -> cvec {
        self.shrink_to_fit();
        let res = cvec {
            data: self.as_mut_ptr(),
            len: self.len() as libc::size_t,
        };

        std::mem::forget(self);
        res
    }
}
impl Into<Vec<u8>> for cvec {
    fn into(self) -> Vec<u8> {
        unsafe { Vec::from_raw_parts(self.data, self.len, self.len) }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rpgp_cvec_len(cvec_ptr: *mut cvec) -> libc::size_t {
    let cvec = &*cvec_ptr;
    cvec.len
}

#[no_mangle]
pub unsafe extern "C" fn rpgp_cvec_data(cvec_ptr: *mut cvec) -> *const u8 {
    let cvec = &*cvec_ptr;
    cvec.data
}

#[no_mangle]
pub unsafe extern "C" fn rpgp_cvec_drop(cvec_ptr: *mut cvec) {
    let _cvec: Box<cvec> = transmute(cvec_ptr);
    // Drop
}

fn create_key(typ: KeyType, sub_typ: KeyType, user_id: &str) -> Result<SignedSecretKey> {
    let key_params = SecretKeyParamsBuilder::default()
        .key_type(typ)
        .can_create_certificates(true)
        .can_sign(true)
        .primary_user_id(user_id.into())
        .passphrase(None)
        .preferred_symmetric_algorithms(vec![
            SymmetricKeyAlgorithm::AES256,
            SymmetricKeyAlgorithm::AES192,
            SymmetricKeyAlgorithm::AES128,
        ])
        .preferred_hash_algorithms(vec![
            HashAlgorithm::SHA2_256,
            HashAlgorithm::SHA2_384,
            HashAlgorithm::SHA2_512,
            HashAlgorithm::SHA2_224,
            HashAlgorithm::SHA1,
        ])
        .preferred_compression_algorithms(vec![
            CompressionAlgorithm::ZLIB,
            CompressionAlgorithm::ZIP,
        ])
        .subkey(
            SubkeyParamsBuilder::default()
                .key_type(sub_typ)
                .can_encrypt(true)
                .passphrase(None)
                .build()
                .unwrap(),
        )
        .build()?;

    let key = key_params.generate()?;

    key.sign(|| "".into())
}

/// Creates an in-memory representation of a PGP key, based on the armor file given.
/// The returned pointer should be stored, and reused when calling methods "on" this key.
/// When done with it [rpgp_key_drop] should be called, to free the memory.
#[no_mangle]
pub unsafe extern "C" fn rpgp_key_from_armor(
    raw: *const u8,
    len: libc::size_t,
) -> *mut public_or_secret_key {
    let bytes = from_raw_parts(raw, len);
    let mut keys = from_armor_many(Cursor::new(bytes)).expect("failed to parse");

    let key = keys.nth(0).unwrap().expect("failed to parse key");

    Box::into_raw(Box::new(key))
}

/// Returns the KeyID for the passed in key. The caller is responsible to call [rpgp_string_free] with the returned memory, to free it.
#[no_mangle]
pub unsafe extern "C" fn rpgp_key_id(ptr: *mut public_or_secret_key) -> *mut c_char {
    let key = &*ptr;
    let id = CString::new(hex::encode(key.key_id().unwrap())).unwrap();

    id.into_raw()
}

/// Frees the memory of the passed in key, making the pointer invalid after this method was called.
#[no_mangle]
pub unsafe extern "C" fn rpgp_key_drop(ptr: *mut public_or_secret_key) {
    let _key: Box<PublicOrSecret> = transmute(ptr);
    // Drop
}

/// Free string, that was created by rpgp.
#[no_mangle]
pub unsafe extern "C" fn rpgp_string_free(p: *mut c_char) {
    let _ = CString::from_raw(p);
    // Drop
}

#[cfg(test)]
mod tests {
    use super::*;

    use pgp::composed::Deserializable;

    #[test]
    fn test_keygen_rsa() {
        let user_id = CStr::from_bytes_with_nul(b"<hello@world.com>\0").unwrap();

        unsafe {
            /* Create the actual key */
            let skey = rpgp_create_rsa_skey(2048, user_id.as_ptr());

            /* Serialize secret key into bytes */
            let skey_bytes = rpgp_skey_to_bytes(skey);

            /* Get the public key */
            let pkey = rpgp_skey_public_key(skey);

            /* Serialize public key into bytes */
            let pkey_bytes = rpgp_pkey_to_bytes(pkey);

            let skey_bytes_vec =
                from_raw_parts(rpgp_cvec_data(skey_bytes), rpgp_cvec_len(skey_bytes));
            let skey_back =
                SignedSecretKey::from_bytes(skey_bytes_vec).expect("invalid secret key");
            assert_eq!(&*skey, &skey_back);

            let pkey_bytes_vec =
                from_raw_parts(rpgp_cvec_data(pkey_bytes), rpgp_cvec_len(pkey_bytes));
            let pkey_back =
                SignedPublicKey::from_bytes(pkey_bytes_vec).expect("invalid public key");
            assert_eq!(&*pkey, &pkey_back);

            /* cleanup */
            rpgp_skey_drop(skey);
            rpgp_cvec_drop(skey_bytes);
            rpgp_pkey_drop(pkey);
            rpgp_cvec_drop(pkey_bytes);
        }
    }
}
