#[macro_export]
macro_rules! impl_public_key {
    ($name:ident, $tag:expr) => {
        #[derive(Debug, PartialEq, Eq, Clone)]
        pub struct $name {
            pub(crate) packet_version: $crate::types::Version,
            pub(crate) version: $crate::types::KeyVersion,
            pub(crate) algorithm: $crate::crypto::public_key::PublicKeyAlgorithm,
            pub(crate) created_at: chrono::DateTime<chrono::Utc>,
            pub(crate) expiration: Option<u16>,
            pub(crate) public_params: $crate::types::PublicParams,
        }

        impl $name {
            /// Parses a `PublicKeyKey` packet from the given slice.
            pub fn from_slice(
                packet_version: $crate::types::Version,
                input: &[u8],
            ) -> $crate::errors::Result<Self> {
                use $crate::crypto::PublicKeyAlgorithm;
                use $crate::types::KeyVersion;

                let (_, details) = $crate::packet::public_key_parser::parse(input)?;
                let (version, algorithm, created_at, expiration, public_params) = details;

                if version == KeyVersion::V2 || version == KeyVersion::V3 {
                    ensure!(
                        algorithm == PublicKeyAlgorithm::RSA
                            || algorithm == PublicKeyAlgorithm::RSAEncrypt
                            || algorithm == PublicKeyAlgorithm::RSASign,
                        "Invalid algorithm {:?} for key version: {:?}",
                        algorithm,
                        version,
                    );
                }

                Ok($name {
                    packet_version,
                    version,
                    algorithm,
                    created_at,
                    expiration,
                    public_params,
                })
            }

            pub fn version(&self) -> $crate::types::KeyVersion {
                self.version
            }

            pub fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
                &self.created_at
            }

            pub fn expiration(&self) -> Option<u16> {
                self.expiration
            }

            pub fn public_params(&self) -> &$crate::types::PublicParams {
                &self.public_params
            }

            pub fn verify(&self) -> $crate::errors::Result<()> {
                unimplemented!("verify");
            }

            fn to_writer_old<W: std::io::Write>(
                &self,
                writer: &mut W,
            ) -> $crate::errors::Result<()> {
                use byteorder::{BigEndian, WriteBytesExt};
                use $crate::ser::Serialize;

                writer.write_u32::<BigEndian>(self.created_at.timestamp() as u32)?;
                writer.write_u16::<BigEndian>(
                    self.expiration
                        .expect("old key versions have an expiration"),
                )?;
                writer.write_all(&[self.algorithm as u8])?;
                self.public_params.to_writer(writer)?;

                Ok(())
            }

            fn to_writer_new<W: std::io::Write>(
                &self,
                writer: &mut W,
            ) -> $crate::errors::Result<()> {
                use byteorder::{BigEndian, WriteBytesExt};
                use $crate::ser::Serialize;

                writer.write_u32::<BigEndian>(self.created_at.timestamp() as u32)?;
                writer.write_all(&[self.algorithm as u8])?;
                self.public_params.to_writer(writer)?;

                Ok(())
            }

            pub fn sign<F>(
                &self,
                key: &impl $crate::types::SecretKeyTrait,
                key_pw: F,
            ) -> $crate::errors::Result<$crate::packet::Signature>
            where
                F: FnOnce() -> String,
            {
                use chrono::SubsecRound;

                let mut config = $crate::packet::SignatureConfigBuilder::default();
                match $tag {
                    $crate::types::Tag::PublicKey => {
                        config.typ($crate::packet::SignatureType::KeyBinding);
                    }
                    $crate::types::Tag::PublicSubkey => {
                        config.typ($crate::packet::SignatureType::SubkeyBinding);
                    }
                    _ => panic!("invalid tag"),
                };

                config
                    .pub_alg(key.algorithm())
                    .hashed_subpackets(vec![$crate::packet::Subpacket::SignatureCreationTime(
                        chrono::Utc::now().trunc_subsecs(0),
                    )])
                    .unhashed_subpackets(vec![$crate::packet::Subpacket::Issuer(key.key_id())])
                    .build()?
                    .sign_key(key, key_pw, &self)
            }
        }

        impl $crate::ser::Serialize for $name {
            fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> $crate::errors::Result<()> {
                writer.write_all(&[self.version as u8])?;

                match self.version {
                    $crate::types::KeyVersion::V2 | $crate::types::KeyVersion::V3 => {
                        self.to_writer_old(writer)
                    }
                    $crate::types::KeyVersion::V4 => self.to_writer_new(writer),
                    $crate::types::KeyVersion::V5 => unimplemented_err!("V5 keys"),
                }
            }
        }

        impl $crate::packet::PacketTrait for $name {
            fn packet_version(&self) -> $crate::types::Version {
                self.packet_version
            }

            fn tag(&self) -> $crate::types::Tag {
                $tag
            }
        }

        impl $crate::types::KeyTrait for $name {
            /// Returns the fingerprint of this key.
            fn fingerprint(&self) -> Vec<u8> {
                use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
                use md5::Md5;
                use sha1::{Digest, Sha1};

                use $crate::ser::Serialize;
                use $crate::types::KeyVersion;

                match self.version() {
                    KeyVersion::V5 => unimplemented!("V5 keys"),
                    KeyVersion::V4 => {
                        // A one-octet version number (4).
                        let mut packet = vec![4, 0, 0, 0, 0];

                        // A four-octet number denoting the time that the key was created.
                        BigEndian::write_u32(
                            &mut packet[1..5],
                            self.created_at().timestamp() as u32,
                        );

                        // A one-octet number denoting the public-key algorithm of this key.
                        packet.push(self.algorithm() as u8);
                        self.public_params
                            .to_writer(&mut packet)
                            .expect("write to vec");

                        let mut h = Sha1::new();
                        h.update(&[0x99]);
                        h.write_u16::<BigEndian>(packet.len() as u16)
                            .expect("write to hasher");
                        h.update(&packet);

                        h.finalize().to_vec()
                    }
                    KeyVersion::V2 | KeyVersion::V3 => {
                        let mut h = Md5::new();
                        self.public_params
                            .to_writer(&mut h)
                            .expect("write to hasher");
                        h.finalize().to_vec()
                    }
                }
            }

            fn key_id(&self) -> $crate::types::KeyId {
                use $crate::types::{KeyId, KeyVersion, PublicParams};

                match self.version() {
                    KeyVersion::V5 => unimplemented!("V5 keys"),
                    KeyVersion::V4 => {
                        // Lower 64 bits
                        let f = self.fingerprint();
                        let offset = f.len() - 8;

                        KeyId::from_slice(&f[offset..]).expect("fixed size slice")
                    }
                    KeyVersion::V2 | KeyVersion::V3 => match &self.public_params {
                        PublicParams::RSA { n, .. } => {
                            let offset = n.len() - 8;

                            KeyId::from_slice(&n.as_bytes()[offset..]).expect("fixed size slice")
                        }
                        _ => panic!("invalid key constructed: {:?}", &self.public_params),
                    },
                }
            }

            fn algorithm(&self) -> $crate::crypto::public_key::PublicKeyAlgorithm {
                self.algorithm
            }
        }

        impl $crate::types::PublicKeyTrait for $name {
            fn verify_signature(
                &self,
                hash: $crate::crypto::hash::HashAlgorithm,
                hashed: &[u8],
                sig: &[$crate::types::Mpi],
            ) -> $crate::errors::Result<()> {
                use $crate::types::PublicParams;

                match self.public_params {
                    PublicParams::RSA { ref n, ref e } => {
                        ensure_eq!(sig.len(), 1, "invalid signature");
                        $crate::crypto::rsa::verify(
                            n.as_bytes(),
                            e.as_bytes(),
                            hash,
                            hashed,
                            sig[0].as_bytes(),
                        )
                    }
                    PublicParams::EdDSA { ref curve, ref q } => {
                        $crate::crypto::eddsa::verify(curve, q.as_bytes(), hash, hashed, sig)
                    }
                    PublicParams::ECDSA { ref curve, .. } => {
                        unimplemented_err!("verify ECDSA: {:?}", curve);
                    }
                    PublicParams::ECDH {
                        ref curve,
                        ref hash,
                        ref alg_sym,
                        ..
                    } => {
                        unimplemented_err!("verify ECDH: {:?} {:?} {:?}", curve, hash, alg_sym);
                    }
                    PublicParams::Elgamal { .. } => {
                        unimplemented_err!("verify Elgamal");
                    }
                    PublicParams::DSA {
                        ref p,
                        ref q,
                        ref g,
                        ref y,
                    } => {
                        ensure_eq!(sig.len(), 2, "invalid signature");

                        $crate::crypto::dsa::verify(
                            &p.into(),
                            &q.into(),
                            &g.into(),
                            &y.into(),
                            hashed,
                            &sig[0].clone().into(),
                            &sig[1].clone().into(),
                        )
                    }
                }
            }

            fn encrypt<R: rand::CryptoRng + rand::Rng>(
                &self,
                rng: &mut R,
                plain: &[u8],
            ) -> $crate::errors::Result<Vec<$crate::types::Mpi>> {
                use $crate::types::{KeyTrait, PublicParams};

                let res = match self.public_params {
                    PublicParams::RSA { ref n, ref e } => {
                        $crate::crypto::rsa::encrypt(rng, n.as_bytes(), e.as_bytes(), plain)
                    }
                    PublicParams::EdDSA { .. } => bail!("EdDSA is only used for signing"),
                    PublicParams::ECDSA { .. } => bail!("ECDSA is only used for signing"),
                    PublicParams::ECDH {
                        ref curve,
                        hash,
                        alg_sym,
                        ref p,
                    } => $crate::crypto::ecdh::encrypt(
                        rng,
                        curve,
                        alg_sym,
                        hash,
                        &self.fingerprint(),
                        p.as_bytes(),
                        plain,
                    ),
                    PublicParams::Elgamal { .. } => unimplemented_err!("encryption with Elgamal"),
                    PublicParams::DSA { .. } => bail!("DSA is only used for signing"),
                }?;

                Ok(res
                    .iter()
                    .map(|v| $crate::types::Mpi::from_raw_slice(&v[..]))
                    .collect::<Vec<_>>())
            }

            fn to_writer_old(
                &self,
                writer: &mut impl std::io::Write,
            ) -> $crate::errors::Result<()> {
                use $crate::ser::Serialize;

                let mut key_buf = Vec::new();
                self.to_writer(&mut key_buf)?;

                // old style packet header for the key
                writer.write_all(&[0x99, (key_buf.len() >> 8) as u8, key_buf.len() as u8])?;
                writer.write_all(&key_buf)?;

                Ok(())
            }
        }
    };
}
