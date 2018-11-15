use std::boxed::Box;

use flate2::read::{DeflateDecoder, ZlibDecoder};
use num_traits::FromPrimitive;

use composed::key::PrivateKey;
use composed::shared::Deserializable;
use crypto::checksum;
use crypto::ecc::decrypt_ecdh;
use crypto::hash::HashAlgorithm;
use crypto::rsa::decrypt_rsa;
use crypto::sym::SymmetricKeyAlgorithm;
use errors::{Error, Result};
use packet::tags::literal;
use packet::tags::public_key_encrypted_session_key::PKESK;
use packet::types::key::{KeyID, PrivateKeyRepr};
use packet::types::{CompressionAlgorithm, Packet, Signature, Tag, Version};

#[derive(Debug)]
pub struct Message(Vec<MessagePacket>);

/// A PGP message
#[derive(Clone, Debug)]
pub enum MessagePacket {
    Literal {
        packet_version: Version,
        packet_tag: Tag,
        mode: u8,
        name: String,
        created: Vec<u8>,
        data: Vec<u8>,
    },
    Compressed {
        packet_version: Version,
        packet_tag: Tag,
        compression_algorithm: CompressionAlgorithm,
        compressed_data: Vec<u8>,
    },
    Signed {
        /// nested message
        message: Option<Box<MessagePacket>>,
        /// for signature packets that contain a one pass message
        one_pass_signature: Option<OnePassSignaturePacket>,
        // actual signature
        signature: Option<Signature>,
    },
    Encrypted {
        esk: Vec<PKESK>,
        edata: Vec<Packet>,
        protected: bool,
    },
}

/// https://tools.ietf.org/html/rfc4880.html#section-5.4
#[derive(Debug, Clone)]
pub struct OnePassSignaturePacket {
    packet_version: Version,
    packet_tag: Tag,
    version: u8,
    hash_algorithm: HashAlgorithm,
    key_id: KeyID,
    is_nested: bool,
}

impl Message {
    /// Decrypt the message using the given password and key.
    // TODO: allow for multiple keys to be passed in
    pub fn decrypt<F, G>(&self, msg_pw: F, key_pw: G, key: &PrivateKey) -> Result<Vec<u8>>
    where
        F: FnOnce() -> String,
        G: FnOnce() -> String,
    {
        match self {
            Message::Compressed(packet) => Ok(packet.body.clone()),
            Message::Literal(packet) => Ok(packet.body.clone()),
            Message::Signed { message, .. } => match message {
                Some(message) => message.as_ref().decrypt(msg_pw, key_pw, key),
                None => Ok(Vec::new()),
            },
            Message::Encrypted {
                esk,
                edata,
                protected,
            } => {
                info!("unlocked key! msg protected={}", protected);

                // search for a packet with a key id that we have and that key
                let mut packet = None;
                let mut encoding_key = None;
                let mut encoding_subkey = None;

                for esk_packet in esk {
                    info!("esk packet: {:?}", esk_packet);
                    info!("{:?}", key.key_id());
                    info!(
                        "{:?}",
                        key.subkeys.iter().map(|k| k.key_id()).collect::<Vec<_>>()
                    );

                    // find the key with the matching key id

                    if key
                        .primary_key
                        .key_id()
                        .ok_or_else(|| format_err!("missing key_id"))?
                        == esk_packet.id
                    {
                        encoding_key = Some(&key.primary_key);
                    } else {
                        encoding_subkey = key.subkeys.iter().find_map(|subkey| {
                            if let Some(id) = subkey.key_id() {
                                if id == esk_packet.id {
                                    Some(subkey)
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        });
                    }

                    if encoding_key.is_some() || encoding_subkey.is_some() {
                        packet = Some(esk_packet);
                        break;
                    }
                }

                let packet = packet.ok_or_else(|| Error::MissingKey)?;

                let mut res = Vec::new();
                if let Some(encoding_key) = encoding_key {
                    encoding_key.unlock(key_pw, |priv_key| {
                        res = decrypt(
                            priv_key,
                            &packet.mpis,
                            edata,
                            *protected,
                            &encoding_key.fingerprint(),
                        )?;
                        Ok(())
                    })?;
                } else if let Some(encoding_key) = encoding_subkey {
                    let mut sym_key = vec![0u8; 8];
                    encoding_key.unlock(key_pw, |priv_key| {
                        res = decrypt(
                            priv_key,
                            &packet.mpis,
                            edata,
                            *protected,
                            &encoding_key.fingerprint(),
                        )?;
                        Ok(())
                    })?;
                    info!("symkey {:?}", sym_key);
                } else {
                    return Err(Error::MissingKey);
                }

                Ok(res)
            }
        }
    }

    /// Check if this message is a signature, that was signed with a one pass signature.
    pub fn is_one_pass_signed(&self) -> bool {
        match self {
            Message::Signed {
                one_pass_signature, ..
            } => one_pass_signature.is_some(),
            _ => false,
        }
    }

    pub fn is_literal(&self) -> bool {
        match self {
            Message::Literal(_) => true,
            Message::Signed { message, .. } => {
                if let Some(msg) = message {
                    msg.is_literal()
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    pub fn get_literal(&self) -> Option<&Message> {
        match self {
            Message::Literal(_) => Some(self),
            Message::Signed { message, .. } => {
                if let Some(msg) = message {
                    msg.get_literal()
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

fn decrypt(
    priv_key: &PrivateKeyRepr,
    mpis: &[Vec<u8>],
    edata: &[Packet],
    protected: bool,
    fingerprint: &[u8],
) -> Result<Vec<u8>> {
    let decrypted_key = match *priv_key {
        PrivateKeyRepr::RSA(ref priv_key) => decrypt_rsa(priv_key, mpis, fingerprint)?,
        PrivateKeyRepr::DSA => unimplemented_err!("DSA"),
        PrivateKeyRepr::ECDSA => unimplemented_err!("ECDSA"),
        PrivateKeyRepr::ECDH(ref priv_key) => decrypt_ecdh(priv_key, mpis, fingerprint)?,
        PrivateKeyRepr::EdDSA(_) => unimplemented_err!("EdDSA"),
    };

    let alg = SymmetricKeyAlgorithm::from_u8(decrypted_key[0])
        .ok_or_else(|| format_err!("invalid symmetric key algorithm"))?;
    info!("alg: {:?}", alg);

    let (key, checksum) = match *priv_key {
        PrivateKeyRepr::ECDH(_) => {
            let dec_len = decrypted_key.len();
            (
                &decrypted_key[1..dec_len - 2],
                &decrypted_key[dec_len - 2..],
            )
        }
        _ => {
            let key_size = alg.key_size();
            (
                &decrypted_key[1..=key_size],
                &decrypted_key[key_size + 1..key_size + 3],
            )
        }
    };

    checksum::simple(checksum, key)?;

    info!("decrypting {} packets", edata.len());
    let mut messages = Vec::with_capacity(edata.len());

    for packet in edata {
        ensure_eq!(packet.body[0], 1, "invalid packet version");

        let mut res = packet.body[1..].to_vec();
        info!("decrypting protected = {:?}", protected);
        let decrypted_packet = if protected {
            alg.decrypt_protected(key, &mut res)?
        } else {
            alg.decrypt(key, &mut res)?
        };
        info!("decoding message");
        let msgs = Message::from_bytes_many(decrypted_packet)?
            .into_iter()
            .map(|msg: Message| -> Result<Vec<Message>> {
                // decompress messages if any are compressed
                match msg {
                    Message::Compressed(packet) => {
                        info!("uncompressing message");
                        let compression_alg = CompressionAlgorithm::from_u8(packet.body[0])
                            .ok_or_else(|| format_err!("invalid compression algorithm"))?;
                        match compression_alg {
                            CompressionAlgorithm::Uncompressed => {
                                Message::from_bytes_many(&packet.body[1..])
                            }
                            CompressionAlgorithm::ZIP => {
                                let mut deflater = DeflateDecoder::new(&packet.body[1..]);
                                Message::from_bytes_many(deflater)
                            }
                            CompressionAlgorithm::ZLIB => {
                                let mut deflater = ZlibDecoder::new(&packet.body[1..]);
                                Message::from_bytes_many(deflater)
                            }
                            CompressionAlgorithm::BZip2 => unimplemented!("BZip2"),
                        }
                    }
                    Message::Encrypted { .. } => {
                        unimplemented!("nested encryption is not supported");
                    }
                    Message::Literal { .. } | Message::Signed { .. } => Ok(vec![msg]),
                }
            })
            .collect::<Result<Vec<Vec<Message>>>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<Message>>();

        info!("msg: {:?}", msgs);
        messages.extend(msgs);
    }

    // TODO: validate found signatures

    // search for literal data packet and return its value
    // TODO: handle different types of packets to be decrypted
    let literal = messages
        .iter()
        .find(|msg| msg.is_literal())
        .ok_or_else(|| format_err!("missing literal message"))?;

    if let Some(Message::Literal(packet)) = literal.get_literal() {
        let (_, l) = literal::parser(&packet.body)?;
        info!("result: {:?}", l);
        Ok(l.data)
    } else {
        unreachable!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use std::fs::File;

    use composed::key::{PrivateKey, PublicKey};
    use composed::Deserializable;

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct Testcase {
        typ: Option<String>,
        decrypt_key: String,
        passphrase: String,
        verify_key: Option<String>,
        filename: Option<String>,
        timestamp: Option<u64>,
        textcontent: Option<String>,
        keyid: Option<String>,
    }

    fn test_parse_msg(entry: &str, base_path: &str) {
        // TODO: verify with the verify key
        // TODO: verify filename
        let n = format!("{}/{}", base_path, entry);
        let mut file = File::open(&n).unwrap_or_else(|_| panic!("no file: {}", &n));

        let details: Testcase = serde_json::from_reader(&mut file).unwrap();
        warn!(
            "Testcase: {}",
            serde_json::to_string_pretty(&details).unwrap()
        );

        let mut decrypt_key_file =
            File::open(format!("{}/{}", base_path, details.decrypt_key)).unwrap();
        let decrypt_key = PrivateKey::from_armor_single(&mut decrypt_key_file)
            .expect("failed to read decryption key");
        let decrypt_id = hex::encode(decrypt_key.key_id().unwrap().to_vec());

        info!("decrypt key (ID={})", &decrypt_id);
        if let Some(id) = &details.keyid {
            assert_eq!(id, &decrypt_id, "invalid keyid");
        }

        if let Some(verify_key_str) = details.verify_key.clone() {
            let mut verify_key_file =
                File::open(format!("{}/{}", base_path, verify_key_str)).unwrap();
            let verify_key = PublicKey::from_armor_single(&mut verify_key_file)
                .expect("failed to read verification key");
            let verify_id = hex::encode(verify_key.key_id().unwrap().to_vec());
            info!("verify key (ID={})", &verify_id);
            if let Some(id) = &details.keyid {
                assert_eq!(id, &verify_id, "invalid keyid");
            }
        }

        let file_name = entry.replace(".json", ".asc");
        let mut cipher_file = File::open(format!("{}/{}", base_path, file_name)).unwrap();

        let message =
            Message::from_armor_single(&mut cipher_file).expect("failed to parse message");
        info!("message: {:?}", message);

        let decrypted = message
            .decrypt(
                || "".to_string(),
                || details.passphrase.clone(),
                &decrypt_key,
            )
            .expect("failed to decrypt message");
        assert_eq!(
            ::std::str::from_utf8(&decrypted).unwrap(),
            details.textcontent.unwrap_or_else(|| "".to_string())
        );
    }

    macro_rules! msg_test {
        ($name:ident, $pos:expr) => {
            #[test]
            fn $name() {
                test_parse_msg(
                    &format!("{}.json", $pos),
                    "./tests/opengpg-interop/testcases/messages",
                );
            }
        };
    }

    // RSA
    msg_test!(msg_gnupg_v1_001, "gnupg-v1-001");
    // Elgamal
    // msg_test!(msg_gnupg_v1_002, "gnupg-v1-002");
    // RSA
    msg_test!(msg_gnupg_v1_003, "gnupg-v1-003");

    // disabled because of blockciphers not updated
    // msg_test!(msg_gnupg_v1_4_11_001, "gnupg-v1-4-11-001");
    msg_test!(msg_gnupg_v1_4_11_002, "gnupg-v1-4-11-002");
    msg_test!(msg_gnupg_v1_4_11_003, "gnupg-v1-4-11-003");
    msg_test!(msg_gnupg_v1_4_11_004, "gnupg-v1-4-11-004");
    // disabled because of blockciphers not updated
    // msg_test!(msg_gnupg_v1_4_11_005, "gnupg-v1-4-11-005");
    msg_test!(msg_gnupg_v1_4_11_006, "gnupg-v1-4-11-006");
    // disabled because of blockciphers not updated
    // msg_test!(msg_gnupg_v2_0_17_001, "gnupg-v2-0-17-001");
    msg_test!(msg_gnupg_v2_0_17_002, "gnupg-v2-0-17-002");
    msg_test!(msg_gnupg_v2_0_17_003, "gnupg-v2-0-17-003");
    msg_test!(msg_gnupg_v2_0_17_004, "gnupg-v2-0-17-004");
    // disabled because of blockciphers not updated
    // msg_test!(msg_gnupg_v2_0_17_005, "gnupg-v2-0-17-005");
    msg_test!(msg_gnupg_v2_0_17_006, "gnupg-v2-0-17-006");
    // parsing error
    // ECDH key - nist p256
    // msg_test!(msg_gnupg_v2_1_5_001, "gnupg-v2-1-5-001");
    // parsing error
    // ECDH key - nist p384
    // msg_test!(msg_gnupg_v2_1_5_002, "gnupg-v2-1-5-002");
    // parsing error
    // ECDH key - nist p512
    // msg_test!(msg_gnupg_v2_1_5_003, "gnupg-v2-1-5-003");
    // disabled because of blockciphers not updated
    // msg_test!(msg_gnupg_v2_10_001, "gnupg-v2-10-001");
    msg_test!(msg_gnupg_v2_10_002, "gnupg-v2-10-002");
    msg_test!(msg_gnupg_v2_10_003, "gnupg-v2-10-003");
    msg_test!(msg_gnupg_v2_10_004, "gnupg-v2-10-004");
    msg_test!(msg_gnupg_v2_10_005, "gnupg-v2-10-005");
    // disabled because of blockciphers not updated
    // msg_test!(msg_gnupg_v2_10_006, "gnupg-v2-10-006");
    msg_test!(msg_gnupg_v2_10_007, "gnupg-v2-10-007");

    // ECDH
    // msg_test!(msg_e2e_001, "e2e-001");
    // ECDH
    // msg_test!(msg_e2e_002, "e2e-001");

    // disabled because of blockciphers not updated
    // msg_test!(msg_pgp_10_0_001, "pgp-10-0-001");
    msg_test!(msg_pgp_10_0_002, "pgp-10-0-002");
    msg_test!(msg_pgp_10_0_003, "pgp-10-0-003");
    msg_test!(msg_pgp_10_0_004, "pgp-10-0-004");
    msg_test!(msg_pgp_10_0_005, "pgp-10-0-005");
    msg_test!(msg_pgp_10_0_006, "pgp-10-0-006");
    // IDEA
    // msg_test!(msg_pgp_10_0_007, "pgp-10-0-007");

    // ECDH
    // msg_test!(msg_openkeychain_001, "openkeychain-001");

    msg_test!(msg_openpgp_001, "openpgp-001");

    macro_rules! msg_test_js {
        ($name:ident, $pos:expr) => {
            #[test]
            fn $name() {
                test_parse_msg(&format!("{}.json", $pos), "./tests/openpgpjs");
            }
        };
    }

    msg_test_js!(msg_openpgpjs_x25519, "x25519");
}
