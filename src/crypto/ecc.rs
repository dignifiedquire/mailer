use aes;
use aes::block_cipher_trait::generic_array::sequence::{Concat, Split};
use aes::block_cipher_trait::generic_array::typenum::U8;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use byteorder::{BigEndian, WriteBytesExt};

use crypto::hash::HashAlgorithm;
use crypto::sym::SymmetricKeyAlgorithm;
use errors::Result;
use packet::types::PublicKeyAlgorithm;

// 20 octets representing "Anonymous Sender    ".
const ANON_SENDER: [u8; 20] = [
    0x41, 0x6E, 0x6F, 0x6E, 0x79, 0x6D, 0x6F, 0x75, 0x73, 0x20, 0x53, 0x65, 0x6E, 0x64, 0x65, 0x72,
    0x20, 0x20, 0x20, 0x20,
];

lazy_static! {
    static ref IV: GenericArray<u8, U8> = arr![u8; 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];
}

/// Build param for ECDH algorithm (as defined in RFC 6637)
/// https://tools.ietf.org/html/rfc6637#section-8
pub fn build_ecdh_param(
    oid: &[u8],
    alg_sym: SymmetricKeyAlgorithm,
    hash: HashAlgorithm,
    fingerprint: &[u8],
) -> Vec<u8> {
    // TODO
    let kdf_params = vec![
        0x01, // reserved for future extensions
        hash as u8,
        alg_sym as u8,
    ];

    let oid_len = [oid.len() as u8];
    let kdf_params_len = [kdf_params.len() as u8];

    let values: Vec<&[u8]> = vec![
        &oid_len,
        oid,
        &[PublicKeyAlgorithm::ECDH as u8],
        &kdf_params_len,
        &kdf_params,
        &ANON_SENDER[..],
        fingerprint,
    ];

    values.concat()
}

/// AES Key Wrap
/// As defined in RFC 3394.
pub fn aes_kw_wrap(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    ensure_eq!(data.len() % 8, 0, "data must be a multiple of 64bit");

    let aes_size = key.len() * 8;
    match aes_size {
        128 => Ok(aes_kw_wrap_128(key, data)),
        192 => Ok(aes_kw_wrap_192(key, data)),
        256 => Ok(aes_kw_wrap_256(key, data)),
        _ => bail!("invalid aes key size: {}", aes_size),
    }
}

/// AES Key Unwrap
/// As defined in RFC 3394.
pub fn aes_kw_unwrap(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    ensure_eq!(data.len() % 8, 0, "data must be a multiple of 64bit");

    let aes_size = key.len() * 8;
    match aes_size {
        128 => aes_kw_unwrap_128(key, data),
        192 => aes_kw_unwrap_192(key, data),
        256 => aes_kw_unwrap_256(key, data),
        _ => bail!("invalid aes key size: {}", aes_size),
    }
}

macro_rules! impl_aes_kw {
    ($name_wrap:ident, $name_unwrap:ident, $size:expr, $hasher:ty) => {
        #[inline]
        fn $name_wrap(key: &[u8], data: &[u8]) -> Vec<u8> {
            // 0) Prepare inputs

            // number of 64 bit blocks in the input data
            let n = data.len() / 8;

            let p: Vec<_> = data.chunks(8).map(|chunk|{
                GenericArray::<u8, _>::clone_from_slice(chunk)
            }).collect();

            let key = GenericArray::from_slice(key);

            // 1) Initialize variables

            //   Set A to the IV
            let mut a = *IV;

            //   for i = 1 to n: R[i] = P[i]
            let mut r = p.clone();

            // 2) calculate intermediate values

            let mut t_arr = arr![u8; 0, 0, 0, 0, 0, 0, 0, 0];
            for j in 0..=5 {
                for i in 0..n {
                    let t = (n * j + (i + 1)) as u64;

                    let mut cipher = <$hasher as BlockCipher>::new(&key);
                    (&mut t_arr[..]).write_u64::<BigEndian>(t).unwrap();

                    // A | R[i]
                    let mut b = a.concat(r[i]);
                    // B = AES(K, ..)
                    cipher.encrypt_block(&mut b);

                    let (hi, lo) = b.split();

                    // A = MSB(64, B) ^ t
                    a = hi;
                    a.iter_mut().zip(t_arr.iter()).for_each(|(ai, ti)| *ai ^= ti);

                    // R[i] = LSB(64, B)
                    r[i] = lo;
                }
            }

            // 3) output the results
            r.iter().fold(a.to_vec(), |mut acc, v| {
                acc.extend(v);
                acc
            })
        }

        #[inline]
        fn $name_unwrap(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
            // 0) Prepare inputs

            let n = (data.len() / 8) - 1;

            let c: Vec<_> = data.chunks(8).map(|chunk|{
                GenericArray::<u8, _>::clone_from_slice(chunk)
            }).collect();

            let key = GenericArray::from_slice(key);

            // 1) Initialize variables

            //   A = C[0]
            let mut a = c[0];

            //   for i = 1 to n: R[i] = C[i]
            let mut r = (&c[1..]).to_vec();

            // 2) calculate intermediate values

            let mut t_arr = arr![u8; 0, 0, 0, 0, 0, 0, 0, 0];

            for j in (0..=5).rev() {
                for i in (0..n).rev() {
                    let t = (n * j + (i + 1)) as u64;

                    let mut cipher = <$hasher as BlockCipher>::new(&key);
                    (&mut t_arr[..]).write_u64::<BigEndian>(t).unwrap();

                    // A ^ t
                    a.iter_mut().zip(t_arr.iter()).for_each(|(ai, ti)| *ai ^= ti);

                    // (A ^ t) | R[i]
                    let mut b = a.concat(r[i]);
                    // B = AES-1(K, ..)
                    cipher.decrypt_block(&mut b);

                    let (hi, lo) = b.split();

                    // A = MSB(64, B)
                    a = hi;

                    // R[i] = LSB(64, B)
                    r[i] = lo;
                }
            }

            // 3) output the results

            if a == *IV {
                Ok(r.iter().fold(Vec::with_capacity(r.len() * 8), |mut acc, v| {
                    acc.extend(v);
                    acc
                }))
            } else {
                bail!("failed integrity check");
            }
        }
    };
}

impl_aes_kw!(aes_kw_wrap_128, aes_kw_unwrap_128, 128, aes::Aes128);
impl_aes_kw!(aes_kw_wrap_192, aes_kw_unwrap_192, 192, aes::Aes192);
impl_aes_kw!(aes_kw_wrap_256, aes_kw_unwrap_256, 256, aes::Aes256);

#[cfg(test)]
mod tests {
    use super::*;

    use hex;

    macro_rules! test_aes_kw {
        ($name:ident, $kek:expr, $input:expr, $output:expr) => {
            #[test]
            fn $name() {
                let kek = hex::decode($kek).unwrap();
                let input_bin = hex::decode($input).unwrap();
                let output_bin = hex::decode($output).unwrap();

                assert_eq!(
                    hex::encode(aes_kw_wrap(&kek, &input_bin).unwrap()),
                    $output.to_lowercase(),
                    "failed wrap"
                );
                assert_eq!(
                    hex::encode(aes_kw_unwrap(&kek, &output_bin).unwrap()),
                    $input.to_lowercase(),
                    "failed unwrap"
                );
            }
        };
    }

    test_aes_kw!(
        aes_kw_wrap_unwrap_128_key_128_kek,
        "000102030405060708090A0B0C0D0E0F",
        "00112233445566778899AABBCCDDEEFF",
        "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"
    );

    test_aes_kw!(
        aes_kw_wrap_unwrap_128_key_192_kek,
        "000102030405060708090A0B0C0D0E0F1011121314151617",
        "00112233445566778899AABBCCDDEEFF",
        "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"
    );

    test_aes_kw!(
        aes_kw_wrap_unwrap_128_key_256_kek,
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "00112233445566778899AABBCCDDEEFF",
        "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"
    );
    test_aes_kw!(
        aes_kw_wrap_unwrap_192_key_192_kek,
        "000102030405060708090A0B0C0D0E0F1011121314151617",
        "00112233445566778899AABBCCDDEEFF0001020304050607",
        "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2"
    );
    test_aes_kw!(
        aes_kw_wrap_unwrap_192_key_256_kek,
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "00112233445566778899AABBCCDDEEFF0001020304050607",
        "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1"
    );
    test_aes_kw!(
        aes_kw_wrap_unwrap_256_key_256_kek,
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
        "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"
    );
}
