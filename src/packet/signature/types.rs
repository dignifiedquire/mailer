use std::fmt;
use std::io::Read;

use byteorder::{BigEndian, ByteOrder};
use chrono::{DateTime, Utc};
use num_traits::FromPrimitive;

use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::Result;
use crate::packet::signature::SignatureConfig;
use crate::packet::PacketTrait;
use crate::ser::Serialize;
use crate::types::{
    self, CompressionAlgorithm, KeyId, KeyVersion, Mpi, PublicKeyTrait, Tag, Version,
};
use smallvec::SmallVec;

/// Signature Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.2
#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
    packet_version: Version,

    pub config: SignatureConfig,

    pub signed_hash_value: [u8; 2],
    pub signature: Vec<Mpi>,
}

impl Signature {
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::complexity))]
    pub fn new(
        packet_version: Version,
        version: SignatureVersion,
        typ: SignatureType,
        pub_alg: PublicKeyAlgorithm,
        hash_alg: HashAlgorithm,
        signed_hash_value: [u8; 2],
        signature: Vec<Mpi>,
        hashed_subpackets: Vec<Subpacket>,
        unhashed_subpackets: Vec<Subpacket>,
    ) -> Self {
        Signature {
            packet_version,
            config: SignatureConfig::new_v4(
                version,
                typ,
                pub_alg,
                hash_alg,
                hashed_subpackets,
                unhashed_subpackets,
            ),
            signed_hash_value,
            signature,
        }
    }

    pub fn from_config(
        config: SignatureConfig,
        signed_hash_value: [u8; 2],
        signature: Vec<Mpi>,
    ) -> Self {
        Signature {
            packet_version: Default::default(),
            config,
            signed_hash_value,
            signature,
        }
    }

    /// Returns what kind of signature this is.
    pub fn typ(&self) -> SignatureType {
        self.config.typ()
    }

    /// Verify this signature.
    pub fn verify<R>(&self, key: &impl PublicKeyTrait, data: R) -> Result<()>
    where
        R: Read,
    {
        if let Some(issuer) = self.issuer() {
            if &key.key_id() != issuer {
                warn!(
                    "validating signature not possible since issueing key {:?} is not available",
                    issuer
                );
                return Ok(());
            }
        }

        let mut hasher = self.config.hash_alg.new_hasher()?;

        self.config.hash_data_to_sign(&mut *hasher, data)?;
        let len = self.config.hash_signature_data(&mut *hasher)?;
        hasher.update(&self.config.trailer(len));

        let hash = &hasher.finish()[..];
        ensure_eq!(
            &self.signed_hash_value,
            &hash[0..2],
            "invalid signed hash value"
        );

        key.verify_signature(self.config.hash_alg, hash, &self.signature)
    }

    /// Verifies a certificate signature type.
    pub fn verify_certificate(
        &self,
        key: &impl PublicKeyTrait,
        tag: Tag,
        id: &impl Serialize,
    ) -> Result<()> {
        debug!("verifying certificate {:#?}", self);

        if let Some(issuer) = self.issuer() {
            if &key.key_id() != issuer {
                warn!(
                    "validating certificate not possible since issueing key {:?} is not available",
                    issuer
                );
                return Ok(());
            }
        }

        let mut hasher = self.config.hash_alg.new_hasher()?;
        let mut key_buf = Vec::new();
        key.to_writer_old(&mut key_buf)?;

        let mut packet_buf = Vec::new();
        id.to_writer(&mut packet_buf)?;

        debug!("packet: {}", hex::encode(&packet_buf));

        hasher.update(&key_buf);

        match self.config.version {
            SignatureVersion::V2 | SignatureVersion::V3 => {
                // Nothing to do
            }
            SignatureVersion::V4 | SignatureVersion::V5 => {
                let prefix = match tag {
                    Tag::UserId => 0xB4,
                    Tag::UserAttribute => 0xD1,
                    _ => bail!("invalid tag for certificate validation: {:?}", tag),
                };

                let mut prefix_buf = [prefix, 0u8, 0u8, 0u8, 0u8];
                BigEndian::write_u32(&mut prefix_buf[1..], packet_buf.len() as u32);
                debug!("prefix: {}", hex::encode(&prefix_buf));

                // prefixes
                hasher.update(&prefix_buf);
            }
        }

        // the packet content
        hasher.update(&packet_buf);

        let len = self.config.hash_signature_data(&mut *hasher)?;
        hasher.update(&self.config.trailer(len));

        let hash = &hasher.finish()[..];
        ensure_eq!(
            &self.signed_hash_value,
            &hash[0..2],
            "invalid signed hash value"
        );

        key.verify_signature(self.config.hash_alg, hash, &self.signature)
    }

    /// Verifies a key binding.
    pub fn verify_key_binding(
        &self,
        signing_key: &impl PublicKeyTrait,
        key: &impl PublicKeyTrait,
    ) -> Result<()> {
        debug!(
            "verifying key binding: {:#?} - {:#?} - {:#?}",
            self, signing_key, key
        );

        let key_id = signing_key.key_id();
        if let Some(issuer) = self.issuer() {
            if &key_id != issuer {
                warn!(
                    "validating key binding not possible since issueing key {:?} is not available",
                    issuer
                );
                return Ok(());
            }
        }

        let mut hasher = self.config.hash_alg.new_hasher()?;

        // Signing Key
        {
            let mut key_buf = Vec::new();
            signing_key.to_writer_old(&mut key_buf)?;

            hasher.update(&key_buf);
        }
        // Key being bound
        {
            let mut key_buf = Vec::new();
            key.to_writer_old(&mut key_buf)?;

            hasher.update(&key_buf);
        }

        let len = self.config.hash_signature_data(&mut *hasher)?;
        hasher.update(&self.config.trailer(len));

        let hash = &hasher.finish()[..];
        ensure_eq!(
            &self.signed_hash_value,
            &hash[0..2],
            "invalid signed hash value"
        );

        signing_key.verify_signature(self.config.hash_alg, hash, &self.signature)
    }

    /// Verifies a direct key signature or a revocation.
    pub fn verify_key(&self, key: &impl PublicKeyTrait) -> Result<()> {
        debug!("verifying key (revocation): {:#?} - {:#?}", self, key);

        let key_id = key.key_id();
        if let Some(issuer) = self.issuer() {
            if &key_id != issuer {
                warn!(
                    "validating key (revocation) not possible since issueing key {:?} is not available",
                    issuer
                );
                return Ok(());
            }
        }

        let mut hasher = self.config.hash_alg.new_hasher()?;

        {
            let mut key_buf = Vec::new();
            key.to_writer_old(&mut key_buf)?;

            hasher.update(&key_buf);
        }

        let len = self.config.hash_signature_data(&mut *hasher)?;
        hasher.update(&self.config.trailer(len));

        let hash = &hasher.finish()[..];
        ensure_eq!(
            &self.signed_hash_value,
            &hash[0..2],
            "invalid signed hash value"
        );

        key.verify_signature(self.config.hash_alg, hash, &self.signature)
    }

    /// Returns if the signature is a certificate or not.
    pub fn is_certificate(&self) -> bool {
        self.config.is_certificate()
    }

    /// Returns an iterator over all subpackets of this signature.
    fn subpackets(&self) -> impl Iterator<Item = &Subpacket> {
        self.config.subpackets()
    }

    pub fn key_expiration_time(&self) -> Option<&DateTime<Utc>> {
        self.subpackets().find_map(|p| match p {
            Subpacket::KeyExpirationTime(d) => Some(d),
            _ => None,
        })
    }

    pub fn signature_expiration_time(&self) -> Option<&DateTime<Utc>> {
        self.subpackets().find_map(|p| match p {
            Subpacket::SignatureExpirationTime(d) => Some(d),
            _ => None,
        })
    }

    pub fn created(&self) -> Option<&DateTime<Utc>> {
        self.config.created()
    }

    pub fn issuer(&self) -> Option<&KeyId> {
        self.config.issuer()
    }

    pub fn preferred_symmetric_algs(&self) -> &[SymmetricKeyAlgorithm] {
        self.subpackets()
            .find_map(|p| match p {
                Subpacket::PreferredSymmetricAlgorithms(d) => Some(&d[..]),
                _ => None,
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn preferred_hash_algs(&self) -> &[HashAlgorithm] {
        self.subpackets()
            .find_map(|p| match p {
                Subpacket::PreferredHashAlgorithms(d) => Some(&d[..]),
                _ => None,
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn preferred_compression_algs(&self) -> &[CompressionAlgorithm] {
        self.subpackets()
            .find_map(|p| match p {
                Subpacket::PreferredCompressionAlgorithms(d) => Some(&d[..]),
                _ => None,
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn key_server_prefs(&self) -> &[u8] {
        self.subpackets()
            .find_map(|p| match p {
                Subpacket::KeyServerPreferences(d) => Some(&d[..]),
                _ => None,
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn key_flags(&self) -> KeyFlags {
        self.subpackets()
            .find_map(|p| match p {
                Subpacket::KeyFlags(d) => Some(d[..].into()),
                _ => None,
            })
            .unwrap_or_default()
    }

    pub fn features(&self) -> &[u8] {
        self.subpackets()
            .find_map(|p| match p {
                Subpacket::Features(d) => Some(&d[..]),
                _ => None,
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn revocation_reason_code(&self) -> Option<&RevocationCode> {
        self.subpackets().find_map(|p| match p {
            Subpacket::RevocationReason(code, _) => Some(code),
            _ => None,
        })
    }

    pub fn revocation_reason_string(&self) -> Option<&str> {
        self.subpackets().find_map(|p| match p {
            Subpacket::RevocationReason(_, reason) => Some(reason.as_str()),
            _ => None,
        })
    }

    pub fn is_primary(&self) -> bool {
        self.subpackets()
            .find_map(|p| match p {
                Subpacket::IsPrimary(d) => Some(*d),
                _ => None,
            })
            .unwrap_or_else(|| false)
    }

    pub fn is_revocable(&self) -> bool {
        self.subpackets()
            .find_map(|p| match p {
                Subpacket::Revocable(d) => Some(*d),
                _ => None,
            })
            .unwrap_or_else(|| true)
    }

    pub fn embedded_signature(&self) -> Option<&Signature> {
        self.subpackets().find_map(|p| match p {
            Subpacket::EmbeddedSignature(d) => Some(&**d),
            _ => None,
        })
    }

    pub fn preferred_key_server(&self) -> Option<&str> {
        self.subpackets().find_map(|p| match p {
            Subpacket::PreferredKeyServer(d) => Some(d.as_str()),
            _ => None,
        })
    }

    pub fn notations(&self) -> Vec<&Notation> {
        self.subpackets()
            .filter_map(|p| match p {
                Subpacket::Notation(d) => Some(d),
                _ => None,
            })
            .collect()
    }

    pub fn revocation_key(&self) -> Option<&types::RevocationKey> {
        self.subpackets().find_map(|p| match p {
            Subpacket::RevocationKey(d) => Some(d),
            _ => None,
        })
    }

    pub fn signers_userid(&self) -> Option<&str> {
        self.subpackets().find_map(|p| match p {
            Subpacket::SignersUserID(d) => Some(d.as_str()),
            _ => None,
        })
    }

    pub fn policy_uri(&self) -> Option<&str> {
        self.subpackets().find_map(|p| match p {
            Subpacket::PolicyURI(d) => Some(d.as_str()),
            _ => None,
        })
    }

    pub fn trust_signature(&self) -> Option<(u8, u8)> {
        self.subpackets().find_map(|p| match p {
            Subpacket::TrustSignature(depth, value) => Some((*depth, *value)),
            _ => None,
        })
    }

    pub fn regular_expression(&self) -> Option<&str> {
        self.subpackets().find_map(|p| match p {
            Subpacket::RegularExpression(d) => Some(d.as_str()),
            _ => None,
        })
    }

    pub fn exportable_certification(&self) -> bool {
        self.subpackets()
            .find_map(|p| match p {
                Subpacket::ExportableCertification(d) => Some(*d),
                _ => None,
            })
            .unwrap_or_else(|| true)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive)]
#[repr(u8)]
pub enum SignatureVersion {
    /// Deprecated
    V2 = 2,
    V3 = 3,
    V4 = 4,
    V5 = 5,
}

impl Default for SignatureVersion {
    fn default() -> Self {
        SignatureVersion::V4
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, FromPrimitive)]
#[repr(u8)]
pub enum SignatureType {
    /// Signature of a binary document.
    /// This means the signer owns it, created it, or certifies that ithas not been modified.
    Binary = 0x00,
    /// Signature of a canonical text document.
    /// This means the signer owns it, created it, or certifies that it
    /// has not been modified.  The signature is calculated over the text
    /// data with its line endings converted to <CR><LF>.
    Text = 0x01,
    /// Standalone signature.
    /// This signature is a signature of only its own subpacket contents.
    /// It is calculated identically to a signature over a zero-length
    /// binary document.  Note that it doesn't make sense to have a V3 standalone signature.
    Standalone = 0x02,
    /// Generic certification of a User ID and Public-Key packet.
    /// The issuer of this certification does not make any particular
    /// assertion as to how well the certifier has checked that the owner
    /// of the key is in fact the person described by the User ID.
    CertGeneric = 0x10,
    /// Persona certification of a User ID and Public-Key packet.
    /// The issuer of this certification has not done any verification of
    /// the claim that the owner of this key is the User ID specified.
    CertPersona = 0x11,
    /// Casual certification of a User ID and Public-Key packet.
    /// The issuer of this certification has done some casual
    /// verification of the claim of identity.
    CertCasual = 0x12,
    /// Positive certification of a User ID and Public-Key packet.
    /// The issuer of this certification has done substantial
    /// verification of the claim of identity.
    ///
    /// Most OpenPGP implementations make their "key signatures" as 0x10
    /// certifications.  Some implementations can issue 0x11-0x13
    /// certifications, but few differentiate between the types.
    CertPositive = 0x13,
    /// Subkey Binding Signature
    /// This signature is a statement by the top-level signing key that
    /// indicates that it owns the subkey.  This signature is calculated
    /// directly on the primary key and subkey, and not on any User ID or
    /// other packets.  A signature that binds a signing subkey MUST have
    /// an Embedded Signature subpacket in this binding signature that
    /// contains a 0x19 signature made by the signing subkey on the
    /// primary key and subkey.
    SubkeyBinding = 0x18,
    /// Primary Key Binding Signature
    /// This signature is a statement by a signing subkey, indicating
    /// that it is owned by the primary key and subkey.  This signature
    /// is calculated the same way as a 0x18 signature: directly on the
    /// primary key and subkey, and not on any User ID or other packets.
    KeyBinding = 0x19,
    /// Signature directly on a key
    /// This signature is calculated directly on a key.  It binds the
    /// information in the Signature subpackets to the key, and is
    /// appropriate to be used for subpackets that provide information
    /// about the key, such as the Revocation Key subpacket.  It is also
    /// appropriate for statements that non-self certifiers want to make
    /// about the key itself, rather than the binding between a key and a name.
    Key = 0x1F,
    /// Key revocation signature
    /// The signature is calculated directly on the key being revoked.  A
    /// revoked key is not to be used.  Only revocation signatures by the
    /// key being revoked, or by an authorized revocation key, should be
    /// considered valid revocation signatures.
    KeyRevocation = 0x20,
    /// Subkey revocation signature
    /// The signature is calculated directly on the subkey being revoked.
    /// A revoked subkey is not to be used.  Only revocation signatures
    /// by the top-level signature key that is bound to this subkey, or
    /// by an authorized revocation key, should be considered valid
    /// revocation signatures.
    SubkeyRevocation = 0x28,
    /// Certification revocation signature
    /// This signature revokes an earlier User ID certification signature
    /// (signature class 0x10 through 0x13) or direct-key signature
    /// (0x1F).  It should be issued by the same key that issued the
    /// revoked signature or an authorized revocation key.  The signature
    /// is computed over the same data as the certificate that it
    /// revokes, and should have a later creation date than that
    /// certificate.
    CertRevocation = 0x30,
    /// Timestamp signature.
    /// This signature is only meaningful for the timestamp contained in
    /// it.
    Timestamp = 0x40,
    /// Third-Party Confirmation signature.
    /// This signature is a signature over some other OpenPGP Signature
    /// packet(s).  It is analogous to a notary seal on the signed data.
    /// A third-party signature SHOULD include Signature Target
    /// subpacket(s) to give easy identification.  Note that we really do
    /// mean SHOULD.  There are plausible uses for this (such as a blind
    /// party that only sees the signature, not the key or source
    /// document) that cannot include a target subpacket.
    ThirdParty = 0x50,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
/// Available signature subpacket types
pub enum SubpacketType {
    SignatureCreationTime,
    SignatureExpirationTime,
    ExportableCertification,
    TrustSignature,
    RegularExpression,
    Revocable,
    KeyExpirationTime,
    PreferredSymmetricAlgorithms,
    RevocationKey,
    Issuer,
    Notation,
    PreferredHashAlgorithms,
    PreferredCompressionAlgorithms,
    KeyServerPreferences,
    PreferredKeyServer,
    PrimaryUserId,
    PolicyURI,
    KeyFlags,
    SignersUserID,
    RevocationReason,
    Features,
    SignatureTarget,
    EmbeddedSignature,
    IssuerFingerprint,
    PreferredAead,
    Experimental(u8),
    Other(u8),
}

impl Into<u8> for SubpacketType {
    #[inline]
    fn into(self) -> u8 {
        match self {
            SubpacketType::SignatureCreationTime => 2,
            SubpacketType::SignatureExpirationTime => 3,
            SubpacketType::ExportableCertification => 4,
            SubpacketType::TrustSignature => 5,
            SubpacketType::RegularExpression => 6,
            SubpacketType::Revocable => 7,
            SubpacketType::KeyExpirationTime => 9,
            SubpacketType::PreferredSymmetricAlgorithms => 11,
            SubpacketType::RevocationKey => 12,
            SubpacketType::Issuer => 16,
            SubpacketType::Notation => 20,
            SubpacketType::PreferredHashAlgorithms => 21,
            SubpacketType::PreferredCompressionAlgorithms => 22,
            SubpacketType::KeyServerPreferences => 23,
            SubpacketType::PreferredKeyServer => 24,
            SubpacketType::PrimaryUserId => 25,
            SubpacketType::PolicyURI => 26,
            SubpacketType::KeyFlags => 27,
            SubpacketType::SignersUserID => 28,
            SubpacketType::RevocationReason => 29,
            SubpacketType::Features => 30,
            SubpacketType::SignatureTarget => 31,
            SubpacketType::EmbeddedSignature => 32,
            SubpacketType::IssuerFingerprint => 33,
            SubpacketType::PreferredAead => 34,
            SubpacketType::Experimental(n) => n,
            SubpacketType::Other(n) => n,
        }
    }
}

impl FromPrimitive for SubpacketType {
    #[inline]
    fn from_i64(n: i64) -> Option<Self> {
        if n > 0 && n < 256 {
            Self::from_u64(n as u64)
        } else {
            None
        }
    }

    #[inline]
    fn from_u64(n: u64) -> Option<Self> {
        if n > 255 {
            None
        } else {
            let m = match n {
                2 => SubpacketType::SignatureCreationTime,
                3 => SubpacketType::SignatureExpirationTime,
                4 => SubpacketType::ExportableCertification,
                5 => SubpacketType::TrustSignature,
                6 => SubpacketType::RegularExpression,
                7 => SubpacketType::Revocable,
                9 => SubpacketType::KeyExpirationTime,
                11 => SubpacketType::PreferredSymmetricAlgorithms,
                12 => SubpacketType::RevocationKey,
                16 => SubpacketType::Issuer,
                20 => SubpacketType::Notation,
                21 => SubpacketType::PreferredHashAlgorithms,
                22 => SubpacketType::PreferredCompressionAlgorithms,
                23 => SubpacketType::KeyServerPreferences,
                24 => SubpacketType::PreferredKeyServer,
                25 => SubpacketType::PrimaryUserId,
                26 => SubpacketType::PolicyURI,
                27 => SubpacketType::KeyFlags,
                28 => SubpacketType::SignersUserID,
                29 => SubpacketType::RevocationReason,
                30 => SubpacketType::Features,
                31 => SubpacketType::SignatureTarget,
                32 => SubpacketType::EmbeddedSignature,
                33 => SubpacketType::IssuerFingerprint,
                34 => SubpacketType::PreferredAead,
                100..=110 => SubpacketType::Experimental(n as u8),
                _ => SubpacketType::Other(n as u8),
            };

            Some(m)
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Subpacket {
    /// The time the signature was made.
    SignatureCreationTime(DateTime<Utc>),
    /// The time the signature will expire.
    SignatureExpirationTime(DateTime<Utc>),
    /// When the key is going to expire
    KeyExpirationTime(DateTime<Utc>),
    /// The OpenPGP Key ID of the key issuing the signature.
    Issuer(KeyId),
    /// List of symmetric algorithms that indicate which algorithms the key holder prefers to use.
    PreferredSymmetricAlgorithms(SmallVec<[SymmetricKeyAlgorithm; 8]>),
    /// List of hash algorithms that indicate which algorithms the key holder prefers to use.
    PreferredHashAlgorithms(SmallVec<[HashAlgorithm; 8]>),
    /// List of compression algorithms that indicate which algorithms the key holder prefers to use.
    PreferredCompressionAlgorithms(SmallVec<[CompressionAlgorithm; 8]>),
    KeyServerPreferences(SmallVec<[u8; 4]>),
    KeyFlags(SmallVec<[u8; 1]>),
    Features(SmallVec<[u8; 1]>),
    RevocationReason(RevocationCode, String),
    IsPrimary(bool),
    Revocable(bool),
    EmbeddedSignature(Box<Signature>),
    PreferredKeyServer(String),
    Notation(Notation),
    RevocationKey(types::RevocationKey),
    SignersUserID(String),
    PolicyURI(String),
    TrustSignature(u8, u8),
    RegularExpression(String),
    ExportableCertification(bool),
    IssuerFingerprint(KeyVersion, SmallVec<[u8; 20]>),
    PreferredAeadAlgorithms(SmallVec<[AeadAlgorithm; 2]>),
    Experimental(u8, SmallVec<[u8; 2]>),
    Other(u8, Vec<u8>),
    SignatureTarget(PublicKeyAlgorithm, HashAlgorithm, Vec<u8>),
}

bitfield! {
    #[derive(Default, PartialEq, Eq, Copy, Clone)]
    pub struct KeyFlags(u8);
    impl Debug;

    pub certify, set_certify: 0;
    pub sign, set_sign: 1;
    pub encrypt_comms, set_encrypt_comms: 2;
    pub encrypt_storage, set_encrypt_storage: 3;
    pub shared, set_shared: 4;
    pub authentication, set_authentication: 5;
    pub group, set_group: 7;
}

impl<'a> From<&'a [u8]> for KeyFlags {
    fn from(other: &'a [u8]) -> Self {
        if other.is_empty() {
            Default::default()
        } else {
            KeyFlags(other[0])
        }
    }
}

impl From<KeyFlags> for SmallVec<[u8; 1]> {
    fn from(flags: KeyFlags) -> Self {
        smallvec![flags.0]
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Notation {
    pub readable: bool,
    pub name: String,
    pub value: String,
}

/// Codes for revocation reasons
#[derive(Debug, PartialEq, Eq, Copy, Clone, FromPrimitive)]
#[repr(u8)]
pub enum RevocationCode {
    /// No reason specified (key revocations or cert revocations)
    NoReason = 0,
    /// Key is superseded (key revocations)
    KeySuperseded = 1,
    /// Key material has been compromised (key revocations)
    KeyCompromised = 2,
    /// Key is retired and no longer used (key revocations)
    KeyRetired = 3,
    /// User ID information is no longer valid (cert revocations)
    CertUserIdInvalid = 32,
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signature")
            .field("packet_version", &self.packet_version)
            .field("config", &self.config)
            .field("signed_hash_value", &hex::encode(&self.signed_hash_value))
            .field(
                "signature",
                &format_args!(
                    "{:?}",
                    self.signature.iter().map(hex::encode).collect::<Vec<_>>()
                ),
            )
            .finish()
    }
}

impl PacketTrait for Signature {
    fn packet_version(&self) -> Version {
        self.packet_version
    }

    fn tag(&self) -> Tag {
        Tag::Signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyflags() {
        let flags: KeyFlags = Default::default();
        assert_eq!(flags.0, 0x00);

        let mut flags = KeyFlags::default();
        flags.set_certify(true);
        assert!(flags.certify());
        assert_eq!(flags.0, 0x01);

        let mut flags = KeyFlags::default();
        flags.set_sign(true);
        assert_eq!(flags.0, 0x02);

        let mut flags = KeyFlags::default();
        flags.set_encrypt_comms(true);
        assert_eq!(flags.0, 0x04);

        let mut flags = KeyFlags::default();
        flags.set_encrypt_storage(true);
        assert_eq!(flags.0, 0x08);

        let mut flags = KeyFlags::default();
        flags.set_shared(true);
        assert_eq!(flags.0, 0x10);

        let mut flags = KeyFlags::default();
        flags.set_authentication(true);
        assert_eq!(flags.0, 0x20);

        let mut flags = KeyFlags::default();
        flags.set_group(true);
        assert_eq!(flags.0, 0x80);
    }
}
