#[macro_export]
macro_rules! impl_secret_key {
    ($name:ident, $tag:expr, $details:ident) => {
        #[derive(Debug, PartialEq, Eq, Clone)]
        pub struct $name {
            pub(crate) details: $crate::packet::$details,
            pub(crate) secret_params: $crate::types::SecretParams,
        }

        impl zeroize::Zeroize for $name {
            fn zeroize(&mut self) {
                // details are not zeroed as they are public knowledge.

                self.secret_params.zeroize();
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                use zeroize::Zeroize;
                self.zeroize();
            }
        }

        impl $name {
            /// Parses a `SecretKey` packet from the given slice.
            pub fn from_slice(
                packet_version: $crate::types::Version,
                input: &[u8],
            ) -> $crate::errors::Result<Self> {
                let (_, details) = $crate::packet::secret_key_parser::parse(input)?;
                let (version, algorithm, created_at, expiration, public_params, secret_params) =
                    details;
                Ok($name {
                    details: $crate::packet::$details {
                        packet_version,
                        version,
                        algorithm,
                        created_at,
                        expiration,
                        public_params,
                    },
                    secret_params,
                })
            }

            pub fn version(&self) -> $crate::types::KeyVersion {
                self.details.version()
            }

            pub fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
                &self.details.created_at()
            }

            pub fn expiration(&self) -> Option<u16> {
                self.details.expiration()
            }

            pub fn public_params(&self) -> &$crate::types::PublicParams {
                &self.details.public_params()
            }

            pub fn verify(&self) -> $crate::errors::Result<()> {
                unimplemented!("verify");
            }

            fn repr_from_ciphertext<F>(
                &self,
                pw: F,
                ciphertext: &$crate::types::EncryptedSecretParams,
            ) -> $crate::errors::Result<$crate::types::SecretKeyRepr>
            where
                F: FnOnce() -> String,
            {
                let plain = ciphertext.unlock(pw, self.details.algorithm)?;
                self.repr_from_plaintext(&plain)
            }

            fn repr_from_plaintext(
                &self,
                plaintext: &$crate::types::PlainSecretParams,
            ) -> $crate::errors::Result<$crate::types::SecretKeyRepr> {
                plaintext.as_ref().as_repr(self.public_params())
            }

            pub fn secret_params(&self) -> &$crate::types::SecretParams {
                &self.secret_params
            }

            /// Checks if we should expect a SHA1 checksum in the encrypted part.
            pub fn has_sha1_checksum(&self) -> bool {
                self.secret_params.string_to_key_id() == 254
            }

            fn to_writer_old<W: std::io::Write>(
                &self,
                writer: &mut W,
            ) -> $crate::errors::Result<()> {
                use $crate::ser::Serialize;

                self.details.to_writer_old(writer)?;
                self.secret_params.to_writer(writer)?;

                Ok(())
            }

            fn to_writer_new<W: std::io::Write>(
                &self,
                writer: &mut W,
            ) -> $crate::errors::Result<()> {
                use $crate::ser::Serialize;

                self.details.to_writer_new(writer)?;
                self.secret_params.to_writer(writer)?;

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
                    $crate::types::Tag::SecretKey => {
                        config.typ($crate::packet::SignatureType::KeyBinding);
                    }
                    $crate::types::Tag::SecretSubkey => {
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

        impl $crate::types::SecretKeyTrait for $name {
            type PublicKey = $details;

            /// Unlock the raw data in the secret parameters.
            fn unlock<F, G>(&self, pw: F, work: G) -> $crate::errors::Result<()>
            where
                F: FnOnce() -> String,
                G: FnOnce(&$crate::types::SecretKeyRepr) -> $crate::errors::Result<()>,
            {
                use $crate::types::SecretParams;

                let decrypted = match self.secret_params {
                    SecretParams::Plain(ref k) => self.repr_from_plaintext(k),
                    SecretParams::Encrypted(ref k) => self.repr_from_ciphertext(pw, k),
                }?;

                work(&decrypted)
            }

            fn create_signature<F>(
                &self,
                key_pw: F,
                hash: $crate::crypto::hash::HashAlgorithm,
                data: &[u8],
            ) -> $crate::errors::Result<Vec<$crate::types::Mpi>>
            where
                F: FnOnce() -> String,
            {
                use $crate::crypto::ECCCurve;
                use $crate::types::{PublicParams, SecretKeyRepr};

                let mut signature: Option<Vec<$crate::types::Mpi>> = None;
                self.unlock(key_pw, |priv_key| {
                    debug!("unlocked key");
                    let sig = match *priv_key {
                        SecretKeyRepr::RSA(ref priv_key) => {
                            $crate::crypto::rsa::sign(priv_key, hash, data)
                        }
                        SecretKeyRepr::DSA(ref priv_key) => {
                            let (p, q, g) = match self.public_params() {
                                PublicParams::DSA {
                                    ref p,
                                    ref q,
                                    ref g,
                                    ..
                                } => (p, q, g),
                                _ => unreachable!("inconsistent key state"),
                            };
                            $crate::crypto::dsa::sign(
                                &p.into(),
                                &q.into(),
                                &g.into(),
                                &priv_key.x,
                                hash,
                                data,
                            )
                            .map(|(r, s)| vec![r.to_bytes_be(), s.to_bytes_be()])
                        }
                        SecretKeyRepr::ECDSA => unimplemented_err!("sign ECDSA"),
                        SecretKeyRepr::ECDH(_) => {
                            bail!("ECDH can not be used to for signing operations")
                        }
                        SecretKeyRepr::EdDSA(ref priv_key) => match self.public_params() {
                            PublicParams::EdDSA { ref curve, ref q } => match *curve {
                                ECCCurve::Ed25519 => {
                                    $crate::crypto::eddsa::sign(q.as_bytes(), priv_key, hash, data)
                                }
                                _ => unsupported_err!("curve {:?} for EdDSA", curve.to_string()),
                            },
                            _ => unreachable!("inconsistent key state"),
                        },
                    }?;

                    // strip leading zeros, to match parse results from MPIs
                    signature = Some(
                        sig.iter()
                            .map(|v| $crate::types::Mpi::from_raw_slice(&v[..]))
                            .collect::<Vec<_>>(),
                    );
                    Ok(())
                })?;

                signature.ok_or_else(|| unreachable!())
            }

            fn public_key(&self) -> $details {
                self.details.clone()
            }
        }

        impl $crate::ser::Serialize for $name {
            fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> $crate::errors::Result<()> {
                writer.write_all(&[self.version() as u8])?;

                match self.version() {
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
                self.details.packet_version()
            }

            fn tag(&self) -> $crate::types::Tag {
                $tag
            }
        }

        impl $crate::types::KeyTrait for $name {
            /// Returns the fingerprint of this key.
            fn fingerprint(&self) -> Vec<u8> {
                self.details.fingerprint()
            }

            fn key_id(&self) -> $crate::types::KeyId {
                self.details.key_id()
            }

            fn algorithm(&self) -> $crate::crypto::public_key::PublicKeyAlgorithm {
                self.details.algorithm()
            }
        }

        impl $crate::types::PublicKeyTrait for $name {
            fn verify_signature(
                &self,
                hash: $crate::crypto::hash::HashAlgorithm,
                hashed: &[u8],
                sig: &[$crate::types::Mpi],
            ) -> $crate::errors::Result<()> {
                self.details.verify_signature(hash, hashed, sig)
            }

            fn encrypt<R: rand::Rng + rand::CryptoRng>(
                &self,
                rng: &mut R,
                plain: &[u8],
            ) -> $crate::errors::Result<Vec<$crate::types::Mpi>> {
                self.details.encrypt(rng, plain)
            }

            fn to_writer_old(
                &self,
                writer: &mut impl std::io::Write,
            ) -> $crate::errors::Result<()> {
                use $crate::ser::Serialize;

                let mut key_buf = Vec::new();
                self.details.to_writer(&mut key_buf)?;

                // old style packet header for the key
                writer.write_all(&[0x99, (key_buf.len() >> 8) as u8, key_buf.len() as u8])?;
                writer.write_all(&key_buf)?;

                Ok(())
            }
        }
    };
}
