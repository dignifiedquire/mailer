use std::fmt;

use num_bigint::BigUint;
use rsa::RSAPrivateKey;
use zeroize::Zeroize;

use crate::crypto::hash::HashAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;

/// The version of the secret key that is actually exposed to users to do crypto operations.
#[allow(clippy::large_enum_variant)] // FIXME
#[derive(Debug)]
pub enum SecretKeyRepr {
    RSA(RSAPrivateKey),
    DSA(DSASecretKey),
    ECDSA,
    ECDH(ECDHSecretKey),
    EdDSA(EdDSASecretKey),
}

/// Secret key for ECDH with Curve25519, the only combination we currently support.
#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct ECDHSecretKey {
    /// The secret point.
    pub secret: [u8; 32],
    pub hash: HashAlgorithm,
    pub oid: Vec<u8>,
    pub alg_sym: SymmetricKeyAlgorithm,
}

impl fmt::Debug for ECDHSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ECDHSecretKey")
            .field("secret", &"[..]".to_string())
            .field("hash", &self.hash)
            .field("oid", &hex::encode(&self.oid))
            .field("alg_sym", &self.alg_sym)
            .finish()
    }
}

/// Secret key for EdDSA with Curve25519, the only combination we currently support.
#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct EdDSASecretKey {
    /// The secret point.
    pub secret: [u8; 32],
    pub oid: Vec<u8>,
}

impl fmt::Debug for EdDSASecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EdDSASecretKey")
            .field("secret", &"[..]".to_string())
            .field("oid", &hex::encode(&self.oid))
            .finish()
    }
}

/// Secret key for DSA.
#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct DSASecretKey {
    pub x: BigUint,
}

impl fmt::Debug for DSASecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DSASecretKey")
            .field("x", &"[..]".to_string())
            .finish()
    }
}
