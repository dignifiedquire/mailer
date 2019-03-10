use std::collections::BTreeMap;
use std::io;

use composed::key::KeyDetails;
use composed::signed_key::{SignedPublicKey, SignedSecretKey};
use crypto::public_key::PublicKeyAlgorithm;
use errors::Result;
use packet;
use ser::Serialize;
use types::{KeyId, KeyTrait, PublicKeyTrait, SignedUser, SignedUserAttribute};

/// Shared details between secret and public keys.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignedKeyDetails {
    pub revocation_signatures: Vec<packet::Signature>,
    pub direct_signatures: Vec<packet::Signature>,
    pub users: Vec<SignedUser>,
    pub user_attributes: Vec<SignedUserAttribute>,
}

impl SignedKeyDetails {
    pub fn new(
        revocation_signatures: Vec<packet::Signature>,
        direct_signatures: Vec<packet::Signature>,
        users: Vec<SignedUser>,
        user_attributes: Vec<SignedUserAttribute>,
    ) -> Self {
        let users = users
            .into_iter()
            .filter(|user| {
                if user.signatures.is_empty() {
                    warn!("ignoring unsigned {}", user.id);
                    false
                } else {
                    true
                }
            })
            .collect();
        let user_attributes = user_attributes
            .into_iter()
            .filter(|attr| {
                if attr.signatures.is_empty() {
                    warn!("ignoring unsigned {}", attr.attr);
                    false
                } else {
                    true
                }
            })
            .collect();

        SignedKeyDetails {
            revocation_signatures,
            direct_signatures,
            users,
            user_attributes,
        }
    }

    fn verify_users(&self, key: &impl PublicKeyTrait) -> Result<()> {
        for user in &self.users {
            user.verify(key)?;
        }

        Ok(())
    }

    fn verify_attributes(&self, key: &impl PublicKeyTrait) -> Result<()> {
        for attr in &self.user_attributes {
            attr.verify(key)?;
        }

        Ok(())
    }

    fn verify_revocation_signatures(&self, key: &impl PublicKeyTrait) -> Result<()> {
        for sig in &self.revocation_signatures {
            sig.verify_key(key)?;
        }

        Ok(())
    }

    fn verify_direct_signatures(&self, key: &impl PublicKeyTrait) -> Result<()> {
        for sig in &self.direct_signatures {
            sig.verify_key(key)?;
        }

        Ok(())
    }

    pub fn verify(&self, key: &impl PublicKeyTrait) -> Result<()> {
        self.verify_users(key)?;
        self.verify_attributes(key)?;
        self.verify_revocation_signatures(key)?;
        self.verify_direct_signatures(key)?;

        Ok(())
    }

    pub fn as_unsigned(&self) -> KeyDetails {
        let primary_user = if let Some(user) = self.users.iter().find(|u| u.is_primary()) {
            user
        } else {
            self.users.first().expect("missing user ids")
        };

        let primary_user_id = primary_user.id.clone();
        let primary_sig = primary_user
            .signatures
            .first()
            .expect("invalid primary user");
        let keyflags = primary_sig.key_flags();

        let preferred_symmetric_algorithms = primary_sig.preferred_symmetric_algs().to_vec();
        let preferred_hash_algorithms = primary_sig.preferred_hash_algs().to_vec();
        let preferred_compression_algorithms = primary_sig.preferred_compression_algs().to_vec();
        let revocation_key = primary_sig.revocation_key().cloned();

        KeyDetails::new(
            primary_user_id,
            self.users
                .iter()
                .filter(|u| !u.is_primary())
                .map(|u| u.id.clone())
                .collect(),
            self.user_attributes
                .iter()
                .map(|a| a.attr.clone())
                .collect(),
            keyflags,
            preferred_symmetric_algorithms,
            preferred_hash_algorithms,
            preferred_compression_algorithms,
            revocation_key,
        )
    }
}

impl Serialize for SignedKeyDetails {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        for sig in &self.revocation_signatures {
            packet::write_packet(writer, sig)?;
        }

        for sig in &self.direct_signatures {
            packet::write_packet(writer, sig)?;
        }

        for user in &self.users {
            user.to_writer(writer)?;
        }

        for attr in &self.user_attributes {
            attr.to_writer(writer)?;
        }

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[allow(clippy::large_enum_variant)] // FIXME
pub enum PublicOrSecret {
    Public(SignedPublicKey),
    Secret(SignedSecretKey),
}

impl PublicOrSecret {
    pub fn verify(&self) -> Result<()> {
        match self {
            PublicOrSecret::Public(k) => k.verify(),
            PublicOrSecret::Secret(k) => k.verify(),
        }
    }

    pub fn to_armored_writer(
        &self,
        writer: &mut impl io::Write,
        headers: Option<&BTreeMap<String, String>>,
    ) -> Result<()> {
        match self {
            PublicOrSecret::Public(k) => k.to_armored_writer(writer, headers),
            PublicOrSecret::Secret(k) => k.to_armored_writer(writer, headers),
        }
    }

    pub fn to_armored_bytes(&self, headers: Option<&BTreeMap<String, String>>) -> Result<Vec<u8>> {
        match self {
            PublicOrSecret::Public(k) => k.to_armored_bytes(headers),
            PublicOrSecret::Secret(k) => k.to_armored_bytes(headers),
        }
    }

    pub fn to_armored_string(&self, headers: Option<&BTreeMap<String, String>>) -> Result<String> {
        match self {
            PublicOrSecret::Public(k) => k.to_armored_string(headers),
            PublicOrSecret::Secret(k) => k.to_armored_string(headers),
        }
    }

    /// Panics if not a secret key.
    pub fn into_secret(self) -> SignedSecretKey {
        match self {
            PublicOrSecret::Public(_) => panic!("Can not convert a public into a secret key"),
            PublicOrSecret::Secret(k) => k,
        }
    }

    /// Panics if not a public key.
    pub fn into_public(self) -> SignedPublicKey {
        match self {
            PublicOrSecret::Secret(_) => panic!("Can not convert a secret into a public key"),
            PublicOrSecret::Public(k) => k,
        }
    }

    pub fn is_public(&self) -> bool {
        match self {
            PublicOrSecret::Secret(_) => false,
            PublicOrSecret::Public(_) => true,
        }
    }

    pub fn is_secret(&self) -> bool {
        match self {
            PublicOrSecret::Secret(_) => true,
            PublicOrSecret::Public(_) => false,
        }
    }
}

impl Serialize for PublicOrSecret {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            PublicOrSecret::Public(k) => k.to_writer(writer),
            PublicOrSecret::Secret(k) => k.to_writer(writer),
        }
    }
}

impl KeyTrait for PublicOrSecret {
    /// Returns the fingerprint of the key.
    fn fingerprint(&self) -> Vec<u8> {
        match self {
            PublicOrSecret::Public(k) => k.fingerprint(),
            PublicOrSecret::Secret(k) => k.fingerprint(),
        }
    }

    /// Returns the Key ID of the key.
    fn key_id(&self) -> KeyId {
        match self {
            PublicOrSecret::Public(k) => k.key_id(),
            PublicOrSecret::Secret(k) => k.key_id(),
        }
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        match self {
            PublicOrSecret::Public(k) => k.algorithm(),
            PublicOrSecret::Secret(k) => k.algorithm(),
        }
    }
}
