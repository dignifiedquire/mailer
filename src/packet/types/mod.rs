use chrono::{DateTime, Utc};
use std::collections::HashMap;

pub mod pubkey;

// const OID_ECC_P256: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
// const OID_ECC_P384: [u8; 5] = [0x2B, 0x81, 0x04, 0x00, 0x22];
// const OID_ECC_P521: [u8; 5] = [0x2B, 0x81, 0x04, 0x00, 0x23];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ECCCurve {
    Curve25519,
    Ed25519,
    P256,
    P384,
    P521,
    BrainpoolP256r1,
    BrainpoolP384r1,
    BrainpoolP512r1,
    Secp256k1,
}

impl ECCCurve {
    /// Standard name
    pub fn name(&self) -> &str {
        match *self {
            ECCCurve::Curve25519 => "Curve25519",
            ECCCurve::Ed25519 => "Ed25519",
            ECCCurve::P256 => "NIST P-256",
            ECCCurve::P384 => "NIST P-384",
            ECCCurve::P521 => "NIST P-521",
            ECCCurve::BrainpoolP256r1 => "brainpoolP256r1",
            ECCCurve::BrainpoolP384r1 => "brainpoolP384r1",
            ECCCurve::BrainpoolP512r1 => "brainpool5126r1",
            ECCCurve::Secp256k1 => "secp256k1",
        }
    }

    /// IETF formatted OID
    pub fn oid_str(&self) -> &str {
        match *self {
            ECCCurve::Curve25519 => "1.3.6.1.4.1.3029.1.5.1",
            ECCCurve::Ed25519 => "1.3.6.1.4.1.11591.15.1",
            ECCCurve::P256 => "1.2.840.10045.3.1.7",
            ECCCurve::P384 => "1.3.132.0.34",
            ECCCurve::P521 => "1.3.132.0.35",
            ECCCurve::BrainpoolP256r1 => "1.3.36.3.3.2.8.1.1.7",
            ECCCurve::BrainpoolP384r1 => "1.3.36.3.3.2.8.1.1.11",
            ECCCurve::BrainpoolP512r1 => "1.3.36.3.3.2.8.1.1.13",
            ECCCurve::Secp256k1 => "1.3.132.0.10",
        }
    }

    /// Nominal bit length of the curve
    pub fn nbits(&self) -> u16 {
        match *self {
            ECCCurve::Curve25519 => 255,
            ECCCurve::Ed25519 => 255,
            ECCCurve::P256 => 256,
            ECCCurve::P384 => 384,
            ECCCurve::P521 => 521,
            ECCCurve::BrainpoolP256r1 => 256,
            ECCCurve::BrainpoolP384r1 => 384,
            ECCCurve::BrainpoolP512r1 => 512,
            ECCCurve::Secp256k1 => 256,
        }
    }

    /// Alternative name of the curve
    pub fn alias(&self) -> Option<&str> {
        match *self {
            ECCCurve::Curve25519 => Some("cv25519"),
            ECCCurve::Ed25519 => Some("ed25519"),
            ECCCurve::P256 => Some("nistp256"),
            ECCCurve::P384 => Some("nistp384"),
            ECCCurve::P521 => Some("nistp521"),
            ECCCurve::BrainpoolP256r1 => None,
            ECCCurve::BrainpoolP384r1 => None,
            ECCCurve::BrainpoolP512r1 => None,
            ECCCurve::Secp256k1 => None,
        }
    }

    /// Required algo, or None for ECDSA/ECDH
    pub fn pubkey_algo(&self) -> Option<PublicKeyAlgorithm> {
        match *self {
            ECCCurve::Curve25519 => Some(PublicKeyAlgorithm::ECDH),
            ECCCurve::Ed25519 => Some(PublicKeyAlgorithm::EdDSA),
            ECCCurve::P256 => None,
            ECCCurve::P384 => None,
            ECCCurve::P521 => None,
            ECCCurve::BrainpoolP256r1 => None,
            ECCCurve::BrainpoolP384r1 => None,
            ECCCurve::BrainpoolP512r1 => None,
            ECCCurve::Secp256k1 => None,
        }
    }

    pub fn oid(&self) -> Vec<u8> {
        // the OID String is turned into bytes
        // with the first two numbers combined
        let mut id: Vec<u32> = self
            .oid_str()
            .split('.')
            .map(|v| v.parse::<u32>().unwrap())
            .collect();

        // combine the first two
        let first = id.remove(0) * 40 + id.remove(0);
        id.insert(0, first);

        id.iter()
            .flat_map(|ident| asn1_der_object_id_val_enc(*ident))
            .collect()
    }
}
/// Get the right curve given an oid.
pub fn ecc_curve_from_oid(oid: &[u8]) -> Option<ECCCurve> {
    if ECCCurve::Curve25519.oid().as_slice() == oid {
        return Some(ECCCurve::Curve25519);
    }
    if ECCCurve::Ed25519.oid().as_slice() == oid {
        return Some(ECCCurve::Ed25519);
    }
    if ECCCurve::P256.oid().as_slice() == oid {
        return Some(ECCCurve::P256);
    }
    if ECCCurve::P384.oid().as_slice() == oid {
        return Some(ECCCurve::P384);
    }
    if ECCCurve::P521.oid().as_slice() == oid {
        return Some(ECCCurve::P521);
    }
    if ECCCurve::BrainpoolP256r1.oid().as_slice() == oid {
        return Some(ECCCurve::BrainpoolP256r1);
    }
    if ECCCurve::BrainpoolP384r1.oid().as_slice() == oid {
        return Some(ECCCurve::BrainpoolP384r1);
    }
    if ECCCurve::BrainpoolP512r1.oid().as_slice() == oid {
        return Some(ECCCurve::BrainpoolP512r1);
    }
    if ECCCurve::Secp256k1.oid().as_slice() == oid {
        return Some(ECCCurve::Secp256k1);
    }
    None
}

fn asn1_der_object_id_val_enc(val: u32) -> Vec<u8> {
    let mut val = val;
    let mut acc = Vec::new();
    acc.push((val & 0x7f) as u8);
    val >>= 7;

    while val > 0 {
        acc.insert(0, (0x80 | (val & 0x7f)) as u8);
        val >>= 7;
    }

    acc
}

impl ToString for ECCCurve {
    fn to_string(&self) -> String {
        self.name().to_string()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
/// Available user attribute types
pub enum UserAttributeType {
    Image(Vec<u8>),
    Unknown((u8, Vec<u8>)),
}

impl UserAttributeType {
    pub fn to_u8(&self) -> u8 {
        match *self {
            UserAttributeType::Image(_) => 1,
            UserAttributeType::Unknown((typ, _)) => typ,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UserAttribute {
    pub attr: UserAttributeType,
    pub signatures: Vec<Signature>,
}

impl UserAttribute {
    pub fn new(attr: UserAttributeType, signatures: Vec<Signature>) -> Self {
        UserAttribute { attr, signatures }
    }
}

enum_from_primitive!{
#[derive(Debug, PartialEq, Eq, Clone)]
/// Codes for revocation reasons
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
}

enum_from_primitive!{
#[derive(Debug, PartialEq, Eq, Clone)]
/// Available symmetric key algorithms.
pub enum SymmetricKeyAlgorithm {
    /// Plaintext or unencrypted data
    Plaintext = 0,
    IDEA = 1,
    /// TripleDES (DES-EDE, 168 bit key derived from 192)
    TripleDES = 2,
    /// CAST5 (128 bit key, as per [RFC2144])
    CAST5 = 3,
    /// Blowfish (128 bit key, 16 rounds)
    Blowfish = 4,
    AES128 = 7,
    AES192 = 8,
    AES256 = 9,
    /// Twofish with 256-bit key [TWOFISH]
    Twofish = 10,
}
}
enum_from_primitive!{
#[derive(Debug, PartialEq, Eq, Clone)]
/// Available signature subpacket types
pub enum SubpacketType {
    SignatureCreationTime = 2,
    SignatureExpirationTime = 3,
    ExportableCertification = 4,
    TrustSignature = 5,
    RegularExpression = 6,
    Revocable = 7,
    KeyExpirationTime = 9,
    PreferredSymmetricAlgorithms = 11,
    RevocationKey = 12,
    Issuer = 16,
    NotationData = 20,
    PreferredHashAlgorithms = 21,
    PreferredCompressionAlgorithms = 22,
    KeyServerPreferences = 23,
    PreferredKeyServer = 24,
    PrimaryUserID = 25,
    PolicyURI = 26,
    KeyFlags = 27,
    SignersUserID = 28,
    RevocationReason = 29,
    Features = 30,
    SignatureTarget = 31,
    EmbeddedSignature = 32,
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
    Issuer([u8; 8]),
    /// List of symmetric algorithms that indicate which algorithms the key holder prefers to use.
    PreferredSymmetricAlgorithms(Vec<SymmetricKeyAlgorithm>),
    /// List of hash algorithms that indicate which algorithms the key holder prefers to use.
    PreferredHashAlgorithms(Vec<HashAlgorithm>),
    /// List of compression algorithms that indicate which algorithms the key holder prefers to use.
    PreferredCompressionAlgorithms(Vec<CompressionAlgorithm>),
    KeyServerPreferences(Vec<u8>),
    KeyFlags(Vec<u8>),
    Features(Vec<u8>),
    RevocationReason(RevocationCode, Vec<u8>),
    IsPrimary(bool),
    Revocable(bool),
    EmbeddedSignature(Box<Signature>),
    PreferredKeyServer(String),
    Notation(String, String),
    RevocationKey(u8, PublicKeyAlgorithm, [u8; 20]),
    SignersUserID(String),
    PolicyURI(String),
    TrustSignature(u8),
    RegularExpression(String),
    ExportableCertification(bool),
}

enum_from_primitive!{
#[derive(Debug, PartialEq, Eq, Clone)]
/// Available compression algorithms.
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-9.3
pub enum CompressionAlgorithm {
    Uncompressed = 0,
    ZIP = 1,
    ZLIB = 2,
    BZip2 = 3,
}
}

enum_from_primitive!{
#[derive(Debug, PartialEq, Eq, Clone)]
/// Available hash algorithms.
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-9.4
pub enum HashAlgorithm {
    MD5 = 1,
    SHA1 = 2,
    RIPEMD160 = 3,
    SHA256 = 8,
    SHA384 = 9,
    SHA512 = 10,
    SHA224 = 11,
}
}

enum_from_primitive!{
#[derive(Debug, PartialEq, Eq, Clone)]
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
}

enum_from_primitive!{
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SignatureVersion {
    /// Deprecated
    V2 = 2,
    V3 = 3,
    V4 = 4,
}
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RevocationKey {
    pub class: u8,
    pub algorithm: PublicKeyAlgorithm,
    pub fingerprint: [u8; 20],
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Signature {
    pub version: SignatureVersion,
    pub typ: SignatureType,
    pub pub_alg: PublicKeyAlgorithm,
    pub hash_alg: HashAlgorithm,
    pub key_expiration_time: Option<DateTime<Utc>>,
    pub signature_expiration_time: Option<DateTime<Utc>>,
    pub unhashed_subpackets: Vec<Subpacket>,
    pub created: Option<DateTime<Utc>>,
    pub issuer: Option<[u8; 8]>,
    pub preferred_symmetric_algs: Vec<SymmetricKeyAlgorithm>,
    pub preferred_hash_algs: Vec<HashAlgorithm>,
    pub preferred_compression_algs: Vec<CompressionAlgorithm>,
    pub key_server_prefs: Vec<u8>,
    pub key_flags: Vec<u8>,
    pub features: Vec<u8>,
    pub revocation_reason_code: Option<RevocationCode>,
    pub revocation_reason_string: Option<String>,
    pub is_primary: bool,
    pub is_revocable: bool,
    pub embedded_signature: Option<Box<Signature>>,
    pub preferred_key_server: Option<String>,
    pub notations: HashMap<String, String>,
    pub revocation_key: Option<RevocationKey>,
    pub signers_userid: Option<String>,
    pub signed_hash_value: Vec<u8>,
    pub signature: Vec<u8>,
    pub policy_uri: Option<String>,
    pub trust_signature: Option<u8>,
    pub regular_expression: Option<String>,
    pub exportable_certification: bool,
}

impl Signature {
    pub fn new(
        version: SignatureVersion,
        typ: SignatureType,
        pub_alg: PublicKeyAlgorithm,
        hash_alg: HashAlgorithm,
        signed_hash_value: Vec<u8>,
        signature: Vec<u8>,
    ) -> Self {
        Signature {
            version,
            typ,
            pub_alg,
            hash_alg,
            key_expiration_time: None,
            signature_expiration_time: None,
            unhashed_subpackets: Vec::new(),
            created: None,
            issuer: None,
            preferred_symmetric_algs: Vec::new(),
            preferred_hash_algs: Vec::new(),
            preferred_compression_algs: Vec::new(),
            key_server_prefs: vec![0],
            key_flags: vec![0],
            features: vec![0],
            revocation_reason_code: None,
            revocation_reason_string: None,
            is_primary: false,
            is_revocable: true,
            embedded_signature: None,
            preferred_key_server: None,
            notations: HashMap::new(),
            revocation_key: None,
            signers_userid: None,
            signed_hash_value,
            signature,
            policy_uri: None,
            trust_signature: None,
            regular_expression: None,
            exportable_certification: true,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct User {
    pub id: String,
    pub signatures: Vec<Signature>,
}

impl User {
    pub fn new<S: Into<String>>(id: S, signatures: Vec<Signature>) -> Self {
        User {
            id: id.into(),
            signatures,
        }
    }
}

enum_from_primitive!{
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum KeyVersion {
    V2 = 2,
    V3 = 3,
    V4 = 4,
}
}

enum_from_primitive!{
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PublicKeyAlgorithm {
    /// RSA (Encrypt and Sign) [HAC]
    RSA = 1,
    /// DEPRECATED: RSA (Encrypt-Only) [HAC]
    RSAEncrypt = 2,
    /// DEPRECATED: RSA (Sign-Only) [HAC]
    RSASign = 3,
    /// Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
    ElgamalSign = 16,
    /// DSA (Digital Signature Algorithm) [FIPS186] [HAC]
    DSA = 17,
    /// Elliptic Curve: RFC-6637
    ECDH = 18,
    /// ECDSA: RFC-6637
    ECDSA = 19,
    /// DEPRECATED: Elgamal (Encrypt and Sign)
    Elgamal = 20,
    /// Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)
    DiffieHellman = 21,
    /// EdDSA (not yet assigned)
    EdDSA = 22,
    /// Private experimental range (from OpenGPG)
    // TODO: genenric Unknown(u8)
    Private100 = 100,
    Private101 = 101,
    Private102 = 102,
    Private103 = 103,
    Private104 = 104,
    Private105 = 105,
    Private106 = 106,
    Private107 = 107,
    Private108 = 108,
    Private109 = 109,
    Private110 = 110,
}
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PublicKey {
    RSA {
        version: KeyVersion,
        algorithm: PublicKeyAlgorithm,
        n: Vec<u8>,
        e: Vec<u8>,
    },
    DSA {
        version: KeyVersion,
        algorithm: PublicKeyAlgorithm,
        p: Vec<u8>,
        q: Vec<u8>,
        g: Vec<u8>,
        y: Vec<u8>,
    },
    ECDSA {
        version: KeyVersion,
        algorithm: PublicKeyAlgorithm,
        curve: ECCCurve,
        p: Vec<u8>,
    },
    ECDH {
        version: KeyVersion,
        algorithm: PublicKeyAlgorithm,
        curve: ECCCurve,
        p: Vec<u8>,
        hash: u8,
        alg_sym: u8,
    },
    Elgamal {
        version: KeyVersion,
        algorithm: PublicKeyAlgorithm,
        p: Vec<u8>,
        g: Vec<u8>,
        y: Vec<u8>,
    },
}

impl PublicKey {
    /// Create a new RSA key.
    pub fn new_rsa(
        version: KeyVersion,
        algorithm: PublicKeyAlgorithm,
        n: Vec<u8>,
        e: Vec<u8>,
    ) -> Self {
        PublicKey::RSA {
            version,
            algorithm,
            n,
            e,
        }
    }

    /// Create a new DSA key.
    pub fn new_dsa(
        version: KeyVersion,
        algorithm: PublicKeyAlgorithm,
        p: Vec<u8>,
        q: Vec<u8>,
        g: Vec<u8>,
        y: Vec<u8>,
    ) -> Self {
        PublicKey::DSA {
            version,
            algorithm,
            p,
            q,
            g,
            y,
        }
    }

    /// Create a new ECDSA key.
    pub fn new_ecdsa(
        version: KeyVersion,
        algorithm: PublicKeyAlgorithm,
        curve: ECCCurve,
        p: Vec<u8>,
    ) -> Self {
        PublicKey::ECDSA {
            version,
            algorithm,
            curve,
            p,
        }
    }

    /// Create a new ECDH key.
    pub fn new_ecdh(
        version: KeyVersion,
        algorithm: PublicKeyAlgorithm,
        curve: ECCCurve,
        p: Vec<u8>,
        hash: u8,
        alg_sym: u8,
    ) -> Self {
        PublicKey::ECDH {
            version,
            algorithm,
            curve,
            p,
            hash,
            alg_sym,
        }
    }

    /// Create a new DSA key.
    pub fn new_elgamal(
        version: KeyVersion,
        algorithm: PublicKeyAlgorithm,
        p: Vec<u8>,
        g: Vec<u8>,
        y: Vec<u8>,
    ) -> Self {
        PublicKey::Elgamal {
            version,
            algorithm,
            p,
            g,
            y,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SecretKey {
    RSASecretKey {
        version: KeyVersion,
        algorithm: PublicKeyAlgorithm,
    },
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PrimaryKey {
    PublicKey(PublicKey),
    SecretKey(SecretKey),
}

impl PrimaryKey {
    /// Wrap a `PublicKey` as `PrimaryKey`.
    pub fn from_public_key(pk: PublicKey) -> Self {
        PrimaryKey::PublicKey(pk)
    }

    /// Wrap a `SecretKey` as `PrimaryKey`.
    pub fn from_secret_key(sk: SecretKey) -> Self {
        PrimaryKey::SecretKey(sk)
    }

    /// Create a new RSA public key.
    pub fn new_public_rsa(
        ver: KeyVersion,
        alg: PublicKeyAlgorithm,
        n: Vec<u8>,
        e: Vec<u8>,
    ) -> Self {
        Self::from_public_key(PublicKey::new_rsa(ver, alg, n, e))
    }

    /// Create a new DSA public key.
    pub fn new_public_dsa(
        ver: KeyVersion,
        alg: PublicKeyAlgorithm,
        p: Vec<u8>,
        q: Vec<u8>,
        g: Vec<u8>,
        y: Vec<u8>,
    ) -> Self {
        Self::from_public_key(PublicKey::new_dsa(ver, alg, p, q, g, y))
    }

    /// Create a new ECDSA public key.
    pub fn new_public_ecdsa(
        ver: KeyVersion,
        alg: PublicKeyAlgorithm,
        curve: ECCCurve,
        p: Vec<u8>,
    ) -> Self {
        Self::from_public_key(PublicKey::new_ecdsa(ver, alg, curve, p))
    }

    /// Create a new ECDH public key.
    pub fn new_public_ecdh(
        ver: KeyVersion,
        alg: PublicKeyAlgorithm,
        curve: ECCCurve,
        p: Vec<u8>,
        hash: u8,
        alg_sym: u8,
    ) -> Self {
        Self::from_public_key(PublicKey::new_ecdh(ver, alg, curve, p, hash, alg_sym))
    }

    /// Create a new Elgamal public key.
    pub fn new_public_elgamal(
        ver: KeyVersion,
        alg: PublicKeyAlgorithm,
        p: Vec<u8>,
        g: Vec<u8>,
        y: Vec<u8>,
    ) -> Self {
        Self::from_public_key(PublicKey::new_elgamal(ver, alg, p, g, y))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecc_curve_to_oid() {
        assert_eq!(
            ECCCurve::P256.oid(),
            vec![0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
        );
        assert_eq!(ECCCurve::P384.oid(), vec![0x2B, 0x81, 0x04, 0x00, 0x22]);
    }

    #[test]
    fn test_ecc_curve_from_oid() {
        let one = vec![0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
        assert_eq!(ecc_curve_from_oid(one.as_slice()).unwrap(), ECCCurve::P256);

        assert_eq!(ecc_curve_from_oid(vec![1, 2, 3].as_slice()), None);
    }

    #[test]
    fn test_asn1_der_object_id_val_enc() {
        assert_eq!(asn1_der_object_id_val_enc(840), vec![0x86, 0x48]);
        assert_eq!(asn1_der_object_id_val_enc(113549), vec![0x86, 0xf7, 0x0d]);
    }
}