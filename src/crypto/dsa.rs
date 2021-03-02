use digest::{generic_array::typenum::Unsigned, Digest};
use digest::{BlockInput, FixedOutput, Reset, Update};
use generic_array::{ArrayLength, GenericArray};
use hmac::{Hmac, Mac, NewMac};
use md5::Md5;
use num_bigint::{prime::probably_prime_miller_rabin, traits::ModInverse, BigUint, RandBigInt};
use num_traits::{CheckedSub, One, Zero};
use rand::Rng;
use ripemd160::Ripemd160;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};

use crate::errors::Result;

use super::HashAlgorithm;

pub fn generate_p_q<D: Digest, R: Rng>(
    rng: &mut R,
    plen: usize,
    qlen: usize,
    seedlen: usize,
) -> Result<(BigUint, BigUint)> {
    // FIPS.186-4 A.1.1.2 Generation of the Probable Primes p and q Using an Approved Hash Function
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf

    // Some notes on the translation to code:
    // * Uppercase variable names (W) were turned into doubled variable names (ww)
    // * 'L' was renamed 'plen', 'N' was renamed 'qlen', as they are the desired bit length of p and q.
    // * The pseudocode algorithm in the standard is really hard to read.
    // * Loop bounds are INCLUSIVE, so "0..(n-1)" translates to "0..n" in Rust.
    //   (I started by stripping out all that "-1" nonsense pretty much.)
    // * I extracted helper functions to generate "bottom n bits set" and "bit #n set",
    //   named 'mask(n)' and 'bit(n)'. Note that bit(n) is NOT in mask(n), but bit(n-1) is.
    // * Once you start simplifying the loop conditions about half the logic just disappears,
    //   and the rest of it suddenly makes sense.

    // List of approved key sizes is in section 4.2 of FIPS.186-4.
    // The Miller-Rabin repetition numbers are in Appendix C.3 of FIPS.186-4.
    // "Table C.1. Minimum number of Miller-Rabin iterations for DSA"
    let mr_reps = match (plen, qlen) {
        (1024, 160) => 40,
        (2048, 224) => 56,
        (2048, 256) => 56,
        (3072, 256) => 64,
        _ => {
            // I made this up, it's just a very, very loose sanity check.
            ensure!(plen > 2 * qlen, "invalid parameters");
            // If this goes wrong it's entirely your responsibility.
            warn!(
                "L = {}, N = {} is not a NIST specified DSA key size",
                plen, qlen
            );
            // TODO FIXME even more conservative default
            64
        }
    };

    // originally named 'outlen'. the number of bits obtained per call to extract()
    let extractlen = D::OutputSize::to_usize() * 8;

    ensure!(seedlen >= qlen && extractlen >= qlen, "invalid parameters");

    let bit = |bit| BigUint::one() << bit;
    let mask = |bits| (BigUint::one() << bits) - BigUint::one();

    loop {
        let mut domain_param_seed = vec![0; seedlen / 8];
        rng.fill_bytes(&mut domain_param_seed);

        // Closure which extracts the next `extractlen` bits from `domain_param_seed`.
        // It is a counter which we take the hash of and increment every time we need a value.
        let mut extract = || {
            // Hash current value and turn it into a BigUint.
            // The spec does not make clear whether leading zero bytes in the domain_param_seed
            // should be hashed or not (the way it's expressed in the standard seems to require
            // converting to and from integer, and the way *that* is defined in the spec strongly
            // suggests leading zeroes ought to be dropped).
            // I actually asked NIST nicely if they would add a test vector for this case. I'm not
            // sure if they will or not, but they did share that their internal implementation
            // strips leading *32 bit zero values* due to implementation details. This does not
            // seem to me to be a reasonable interpretation of the standard as written.
            // OpenSSL does the same thing I do here, and assumes a fixed size for the value.
            let value = BigUint::from_bytes_be(D::digest(&domain_param_seed).as_slice());
            // Directly increment `domain_param_seed` as if it is a big endian counter.
            // This replaces both the j and offset variables in the pseudocode.
            domain_param_seed.iter_mut().rev().all(|b| {
                let (b1, carry) = b.overflowing_add(1);
                *b = b1;
                carry
            });
            value
        };

        // extract qlen-1 bits from seed
        let uu = extract() & mask(qlen - 1);

        // append 1 as new msb, set lsb to 1
        let q = bit(qlen - 1) | uu | bit(0);

        if probably_prime_miller_rabin(&q, mr_reps, false) {
            for _counter in 0..(4 * plen) {
                // extract plen-1 bits from seed
                let mut ww = BigUint::zero();
                for b in (0..plen).step_by(extractlen) {
                    ww |= extract() << b;
                }
                ww &= mask(plen - 1);

                // append 1 as new msb
                let xx = bit(plen - 1) | ww;

                // round down to nearest multiple of 2q and add 1
                let c = &xx % (&q << 1);
                let p = xx - c + BigUint::one();

                // For comparison to the intermediate output in NIST test vectors
                debug!("{:?}", hex::encode(&p.to_bytes_be()));

                if p.bits() >= plen && probably_prime_miller_rabin(&p, mr_reps, false) {
                    return Ok((p, q));
                }
            }
        }
    }
}

pub fn generate_g<R: Rng>(rng: &mut R, p: &BigUint, q: &BigUint) -> Result<BigUint> {
    // FIPS.186-4 A.2.1 Unverifiable Generation of the Generator g

    // "Unverifiable" means you can't prove this procedure was used to generate it.

    let e = (p - BigUint::one()) / q;

    // Generate 1 < h < (p-1)
    // (but gen_biguint_range takes lower bound as inclusive)
    let lbound = BigUint::from(2u32);
    let ubound = p - BigUint::one();

    loop {
        let h = rng.gen_biguint_range(&lbound, &ubound);

        let g = h.modpow(&e, p);

        if g != BigUint::one() {
            return Ok(g);
        }
    }
}

pub fn validate_g(p: &BigUint, q: &BigUint, g: &BigUint) -> Result<()> {
    // FIPS.186-4 A.2.2 Assurance of the Validity of the Generator g

    ensure!(
        &BigUint::from(2u32) <= g && g <= &(p - BigUint::one()) && g.modpow(q, p) == BigUint::one(),
        "invalid generator"
    );

    Ok(())
}

pub fn generate_x_y<R: Rng>(
    rng: &mut R,
    p: &BigUint,
    q: &BigUint,
    g: &BigUint,
) -> Result<(BigUint, BigUint)> {
    // This does NOT strictly follow either of the two standard methods:
    // FIPS.186-4 B.1.1 Key Pair Generation Using Extra Random Bits
    // FIPS.186-4 B.1.2 Key Pair Generation by Testing Candidates

    // Instead, it delegates the generation of uniform random 1 <= x <= p-1 to gen_biguint_range.

    // TODO check assurances that this really is uniform
    let x = rng.gen_biguint_range(&BigUint::one(), q);

    let y = g.modpow(&x, p);

    Ok((x, y))
}

/// Divides i by j and rounds up to the nearest integer
fn div_ceil(i: usize, j: usize) -> usize {
    (i + j - 1) / j
}

/// Rounds up i to the nearest multiple of j
fn next_multiple_of(i: usize, j: usize) -> usize {
    div_ceil(i, j) * j
}

/// Implements int2octets as defined in RFC6979
///
/// Reference: https://tools.ietf.org/html/rfc6979#section-2.3.3
fn int_to_octets(i: &BigUint, q: &BigUint) -> Vec<u8> {
    let q_bytes = div_ceil(q.bits(), 8);
    assert!(i < q); // should only be called on numbers known to be smaller than q
    let mut tmp = i.to_bytes_le(); // little endian + reverse so resize pads at the big end
    tmp.resize(q_bytes, 0u8);
    tmp.reverse();
    tmp
}

/// Implements bits2int as defined in RFC6979
///
/// Reference: https://tools.ietf.org/html/rfc6979#section-2.3.2
fn bits_to_int(data: &[u8], q: &BigUint) -> BigUint {
    let excess_bits = (data.len() * 8).saturating_sub(q.bits());
    BigUint::from_bytes_be(data) >> excess_bits
}

/// Equivalent to `bits_to_int(data, q) % q`, but more efficient.
fn bits_to_int_mod(data: &[u8], q: &BigUint) -> BigUint {
    let tmp = bits_to_int(data, q);
    tmp.checked_sub(q).unwrap_or(tmp)
}

/// Calculate the modular inverse of i mod q. Requires 0 < i < q as a precondition.
///
/// If this fails q is not prime, meaning q is not part of a valid DSA key.
fn inverse(i: &BigUint, q: &BigUint) -> Result<BigUint> {
    match i.mod_inverse(q).and_then(|x| x.to_biguint()) {
        Some(x) => Ok(x),
        _ => bail!("invalid key"), // q isn't prime
    }
}

// TODO FIXME This is copy/pasted from the ecdsa crate until it can be split out
struct HmacDrbg<D>
where
    D: BlockInput + FixedOutput + Clone + Default + Reset + Update,
{
    /// HMAC key `K` (see RFC 6979 Section 3.2.c)
    k: Hmac<D>,

    /// Chaining value `V` (see RFC 6979 Section 3.2.c)
    v: GenericArray<u8, D::OutputSize>,
}

impl<D> HmacDrbg<D>
where
    D: BlockInput + FixedOutput + Clone + Default + Reset + Update,
{
    /// Initialize `HMAC_DRBG`
    pub fn new(entropy_input: &[u8], nonce: &[u8], additional_data: &[u8]) -> Self {
        let mut k = Hmac::new(&Default::default());
        let mut v = GenericArray::default();

        for b in &mut v {
            *b = 0x01;
        }

        for i in 0..=1 {
            k.update(&v);
            k.update(&[i]);
            k.update(entropy_input);
            k.update(nonce);
            k.update(additional_data);
            k = Hmac::new_varkey(&k.finalize().into_bytes()).unwrap();

            // Steps 3.2.e,g: v = HMAC_k(v)
            k.update(&v);
            v = k.finalize_reset().into_bytes();
        }

        Self { k, v }
    }

    /// Get the next `HMAC_DRBG` output
    pub fn generate_into(&mut self, out: &mut [u8]) {
        for out_chunk in out.chunks_mut(self.v.len()) {
            self.k.update(&self.v);
            self.v = self.k.finalize_reset().into_bytes();
            out_chunk.copy_from_slice(&self.v[..out_chunk.len()]);
        }

        self.k.update(&self.v);
        self.k.update(&[0x00]);
        self.k = Hmac::new_varkey(&self.k.finalize_reset().into_bytes()).unwrap();
        self.k.update(&self.v);
        self.v = self.k.finalize_reset().into_bytes();
    }
}



/// So we can make a trait object out of differently parameterized HmacDRBG instances.
/// HMAC DRBG is what RFC6979 uses for generating the k parameter for DSA signatures.
/// This makes the signatures deterministic and eliminates the risk of leaking secret
/// information through poor quality or repetitive values of k.
trait KGenerator {
    fn next(&mut self, q: &BigUint) -> BigUint;
}

impl<D> KGenerator for HmacDrbg<D>
where
    D: Update + FixedOutput + BlockInput + Reset + Clone + Default,
    D::BlockSize: ArrayLength<u8>,
    D::OutputSize: ArrayLength<u8>,
{
    fn next(&mut self, q: &BigUint) -> BigUint {
        let output_size = D::OutputSize::to_usize();
        let q_bytes = div_ceil(q.bits(), 8);
        let mut tmp = vec![0u8; next_multiple_of(q_bytes, output_size)];
        self.generate_into(&mut tmp);
        bits_to_int(&tmp, &q)
    }
}

fn make_k_generator(
    hash_algorithm: HashAlgorithm,
    entropy: &[u8],
    nonce: &[u8],
    pers: &[u8],
) -> Result<Box<dyn KGenerator>> {
    Ok(match hash_algorithm {
        HashAlgorithm::MD5 => Box::new(HmacDrbg::<Md5>::new(entropy, nonce, pers)),
        HashAlgorithm::SHA1 => Box::new(HmacDrbg::<Sha1>::new(entropy, nonce, pers)),
        HashAlgorithm::RIPEMD160 => Box::new(HmacDrbg::<Ripemd160>::new(entropy, nonce, pers)),
        HashAlgorithm::SHA2_256 => Box::new(HmacDrbg::<Sha256>::new(entropy, nonce, pers)),
        HashAlgorithm::SHA2_384 => Box::new(HmacDrbg::<Sha384>::new(entropy, nonce, pers)),
        HashAlgorithm::SHA2_512 => Box::new(HmacDrbg::<Sha512>::new(entropy, nonce, pers)),
        HashAlgorithm::SHA2_224 => Box::new(HmacDrbg::<Sha224>::new(entropy, nonce, pers)),
        HashAlgorithm::None
        | HashAlgorithm::SHA3_256
        | HashAlgorithm::SHA3_512
        | HashAlgorithm::Private10 => unimplemented_err!("Hash not implemented for DSA signatures"),
    })
}

/// Produce a DSA signature
pub fn sign(
    p: &BigUint,
    q: &BigUint,
    g: &BigUint,
    x: &BigUint,
    hash_algorithm: HashAlgorithm,
    hashed: &[u8],
) -> Result<(BigUint, BigUint)> {
    // Hash
    let h = bits_to_int_mod(hashed, q);

    // Choose k and produce signature
    let mut rng = make_k_generator(
        hash_algorithm,
        &int_to_octets(x, q),
        &int_to_octets(&h, q),
        &[],
    )?;

    loop {
        let k = rng.next(q);
        if &k >= q || k == BigUint::zero() {
            continue;
        }

        let k_inv = inverse(&k, q)?;

        let r = g.modpow(&k, p) % q;
        if r == BigUint::zero() {
            continue;
        }

        let s = (k_inv * (&h + x * &r)) % q;
        if s == BigUint::zero() {
            continue;
        }

        return Ok((r, s));
    }
}

/// Verify a DSA signature.
pub fn verify(
    p: &BigUint,
    q: &BigUint,
    g: &BigUint,
    y: &BigUint,
    hashed: &[u8],
    r: &BigUint,
    s: &BigUint,
) -> Result<()> {
    ensure!(
        &BigUint::zero() < r && r < q && &BigUint::zero() < s && s < q,
        "invalid signature"
    );

    // Hash
    let h = bits_to_int_mod(hashed, q);

    // Check signature
    let w = inverse(s, q)?;
    let u1 = (h * &w) % q;
    let u2 = (r * &w) % q;
    let v = ((g.modpow(&u1, p) * y.modpow(&u2, p)) % p) % q;

    ensure!(&v == r, "invalid signature");

    Ok(())
}

#[cfg(test)]
mod test {
    use std::io::{Cursor, Read};

    use super::*;
    use hex_literal::hex;
    use num_bigint::BigUint;
    use num_traits::Num;
    use rand::{thread_rng, RngCore};

    fn hex_num(s: &str) -> BigUint {
        BigUint::from_str_radix(s, 16).unwrap()
    }

    fn hash(hash_algorithm: HashAlgorithm, text: &str) -> Vec<u8> {
        hash_algorithm.digest(text.as_bytes()).unwrap()
    }

    struct FakeRng {
        data: Cursor<Vec<u8>>,
    }

    impl FakeRng {
        fn new(data: &[u8]) -> Self {
            Self {
                data: Cursor::new(data.to_owned()),
            }
        }
    }

    impl RngCore for FakeRng {
        fn next_u32(&mut self) -> u32 {
            let mut tmp = 0u32.to_le_bytes();
            self.fill_bytes(&mut tmp);
            u32::from_le_bytes(tmp)
        }

        fn next_u64(&mut self) -> u64 {
            let mut tmp = 0u64.to_le_bytes();
            self.fill_bytes(&mut tmp);
            u64::from_le_bytes(tmp)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.try_fill_bytes(dest).unwrap()
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand::Error> {
            self.data.read_exact(dest).map_err(|e| rand::Error::new(e))
        }
    }

    fn generate_p_q_with_seed<D: Digest>(
        plen: usize,
        qlen: usize,
        seed: &[u8],
    ) -> Result<(BigUint, BigUint)> {
        let mut rng = FakeRng::new(seed);
        generate_p_q::<D, _>(&mut rng, plen, qlen, seed.len() * 8)
    }

    /// Test vectors from https://tools.ietf.org/html/rfc6979#appendix-A.2.1
    #[test]
    fn test_dsa_1024() {
        let _ = pretty_env_logger::try_init();

        let p = hex_num(
            "86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447\
             E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88\
             73ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C\
             881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779",
        );

        let q = hex_num("996F967F6C8E388D9E28D01E205FBA957A5698B1");

        let g = hex_num(
            "07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D\
             89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD\
             87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4\
             17BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD",
        );

        let x = hex_num("411602CB19A6CCC34494D79D98EF1E7ED5AF25F7");

        let y = hex_num(
            "5DF5E01DED31D0297E274E1691C192FE5868FEF9E19A84776454B100CF16F653\
             92195A38B90523E2542EE61871C0440CB87C322FC4B4D2EC5E1E7EC766E1BE8D\
             4CE935437DC11C3C8FD426338933EBFE739CB3465F4D3668C5E473508253B1E6\
             82F65CBDC4FAE93C2EA212390E54905A86E2223170B44EAA7DA5DD9FFCFB7F3B",
        );

        let check =
            |hash_algorithm: HashAlgorithm, text: &str, _k: BigUint, r: BigUint, s: BigUint| {
                let hashed = hash(hash_algorithm, text);
                let (new_r, new_s) = sign(&p, &q, &g, &x, hash_algorithm, &hashed).unwrap();
                assert_eq!((&new_r, &new_s), (&r, &s));
                verify(&p, &q, &g, &y, &hashed, &r, &s).unwrap();
            };

        check(
            HashAlgorithm::SHA1,
            "sample",
            hex_num("7BDB6B0FF756E1BB5D53583EF979082F9AD5BD5B"),
            hex_num("2E1A0C2562B2912CAAF89186FB0F42001585DA55"),
            hex_num("29EFB6B0AFF2D7A68EB70CA313022253B9A88DF5"),
        );
        check(
            HashAlgorithm::SHA2_224,
            "sample",
            hex_num("562097C06782D60C3037BA7BE104774344687649"),
            hex_num("4BC3B686AEA70145856814A6F1BB53346F02101E"),
            hex_num("410697B92295D994D21EDD2F4ADA85566F6F94C1"),
        );
        check(
            HashAlgorithm::SHA2_256,
            "sample",
            hex_num("519BA0546D0C39202A7D34D7DFA5E760B318BCFB"),
            hex_num("81F2F5850BE5BC123C43F71A3033E9384611C545"),
            hex_num("4CDD914B65EB6C66A8AAAD27299BEE6B035F5E89"),
        );
        check(
            HashAlgorithm::SHA2_384,
            "sample",
            hex_num("95897CD7BBB944AA932DBC579C1C09EB6FCFC595"),
            hex_num("07F2108557EE0E3921BC1774F1CA9B410B4CE65A"),
            hex_num("54DF70456C86FAC10FAB47C1949AB83F2C6F7595"),
        );
        check(
            HashAlgorithm::SHA2_512,
            "sample",
            hex_num("09ECE7CA27D0F5A4DD4E556C9DF1D21D28104F8B"),
            hex_num("16C3491F9B8C3FBBDD5E7A7B667057F0D8EE8E1B"),
            hex_num("02C36A127A7B89EDBB72E4FFBC71DABC7D4FC69C"),
        );
        check(
            HashAlgorithm::SHA1,
            "test",
            hex_num("5C842DF4F9E344EE09F056838B42C7A17F4A6433"),
            hex_num("42AB2052FD43E123F0607F115052A67DCD9C5C77"),
            hex_num("183916B0230D45B9931491D4C6B0BD2FB4AAF088"),
        );
        check(
            HashAlgorithm::SHA2_224,
            "test",
            hex_num("4598B8EFC1A53BC8AECD58D1ABBB0C0C71E67297"),
            hex_num("6868E9964E36C1689F6037F91F28D5F2C30610F2"),
            hex_num("49CEC3ACDC83018C5BD2674ECAAD35B8CD22940F"),
        );
        check(
            HashAlgorithm::SHA2_256,
            "test",
            hex_num("5A67592E8128E03A417B0484410FB72C0B630E1A"),
            hex_num("22518C127299B0F6FDC9872B282B9E70D0790812"),
            hex_num("6837EC18F150D55DE95B5E29BE7AF5D01E4FE160"),
        );
        check(
            HashAlgorithm::SHA2_384,
            "test",
            hex_num("220156B761F6CA5E6C9F1B9CF9C24BE25F98CD89"),
            hex_num("854CF929B58D73C3CBFDC421E8D5430CD6DB5E66"),
            hex_num("91D0E0F53E22F898D158380676A871A157CDA622"),
        );
        check(
            HashAlgorithm::SHA2_512,
            "test",
            hex_num("65D2C2EEB175E370F28C75BFCDC028D22C7DBE9C"),
            hex_num("8EA47E475BA8AC6F2D821DA3BD212D11A3DEB9A0"),
            hex_num("7C670C7AD72B6C050C109E1790008097125433E8"),
        );
    }

    /// Test vectors from https://tools.ietf.org/html/rfc6979#appendix-A.2.2
    #[test]
    fn test_dsa_2048() {
        let _ = pretty_env_logger::try_init();

        let p = hex_num(
            "9DB6FB5951B66BB6FE1E140F1D2CE5502374161FD6538DF1648218642F0B5C48\
             C8F7A41AADFA187324B87674FA1822B00F1ECF8136943D7C55757264E5A1A44F\
             FE012E9936E00C1D3E9310B01C7D179805D3058B2A9F4BB6F9716BFE6117C6B5\
             B3CC4D9BE341104AD4A80AD6C94E005F4B993E14F091EB51743BF33050C38DE2\
             35567E1B34C3D6A5C0CEAA1A0F368213C3D19843D0B4B09DCB9FC72D39C8DE41\
             F1BF14D4BB4563CA28371621CAD3324B6A2D392145BEBFAC748805236F5CA2FE\
             92B871CD8F9C36D3292B5509CA8CAA77A2ADFC7BFD77DDA6F71125A7456FEA15\
             3E433256A2261C6A06ED3693797E7995FAD5AABBCFBE3EDA2741E375404AE25B",
        );

        let q = hex_num("F2C3119374CE76C9356990B465374A17F23F9ED35089BD969F61C6DDE9998C1F");

        let g = hex_num(
            "5C7FF6B06F8F143FE8288433493E4769C4D988ACE5BE25A0E24809670716C613\
             D7B0CEE6932F8FAA7C44D2CB24523DA53FBE4F6EC3595892D1AA58C4328A06C4\
             6A15662E7EAA703A1DECF8BBB2D05DBE2EB956C142A338661D10461C0D135472\
             085057F3494309FFA73C611F78B32ADBB5740C361C9F35BE90997DB2014E2EF5\
             AA61782F52ABEB8BD6432C4DD097BC5423B285DAFB60DC364E8161F4A2A35ACA\
             3A10B1C4D203CC76A470A33AFDCBDD92959859ABD8B56E1725252D78EAC66E71\
             BA9AE3F1DD2487199874393CD4D832186800654760E1E34C09E4D155179F9EC0\
             DC4473F996BDCE6EED1CABED8B6F116F7AD9CF505DF0F998E34AB27514B0FFE7",
        );

        let x = hex_num("69C7548C21D0DFEA6B9A51C9EAD4E27C33D3B3F180316E5BCAB92C933F0E4DBC");

        let y = hex_num(
            "667098C654426C78D7F8201EAC6C203EF030D43605032C2F1FA937E5237DBD94\
             9F34A0A2564FE126DC8B715C5141802CE0979C8246463C40E6B6BDAA2513FA61\
             1728716C2E4FD53BC95B89E69949D96512E873B9C8F8DFD499CC312882561ADE\
             CB31F658E934C0C197F2C4D96B05CBAD67381E7B768891E4DA3843D24D94CDFB\
             5126E9B8BF21E8358EE0E0A30EF13FD6A664C0DCE3731F7FB49A4845A4FD8254\
             687972A2D382599C9BAC4E0ED7998193078913032558134976410B89D2C171D1\
             23AC35FD977219597AA7D15C1A9A428E59194F75C721EBCBCFAE44696A499AFA\
             74E04299F132026601638CB87AB79190D4A0986315DA8EEC6561C938996BEADF",
        );

        let check =
            |hash_algorithm: HashAlgorithm, text: &str, _k: BigUint, r: BigUint, s: BigUint| {
                let hashed = hash(hash_algorithm, text);
                let (new_r, new_s) = sign(&p, &q, &g, &x, hash_algorithm, &hashed).unwrap();
                assert_eq!((&new_r, &new_s), (&r, &s));
                verify(&p, &q, &g, &y, &hashed, &r, &s).unwrap();
            };

        check(
            HashAlgorithm::SHA1,
            "sample",
            hex_num("888FA6F7738A41BDC9846466ABDB8174C0338250AE50CE955CA16230F9CBD53E"),
            hex_num("3A1B2DBD7489D6ED7E608FD036C83AF396E290DBD602408E8677DAABD6E7445A"),
            hex_num("D26FCBA19FA3E3058FFC02CA1596CDBB6E0D20CB37B06054F7E36DED0CDBBCCF"),
        );
        check(
            HashAlgorithm::SHA2_224,
            "sample",
            hex_num("BC372967702082E1AA4FCE892209F71AE4AD25A6DFD869334E6F153BD0C4D806"),
            hex_num("DC9F4DEADA8D8FF588E98FED0AB690FFCE858DC8C79376450EB6B76C24537E2C"),
            hex_num("A65A9C3BC7BABE286B195D5DA68616DA8D47FA0097F36DD19F517327DC848CEC"),
        );
        check(
            HashAlgorithm::SHA2_256,
            "sample",
            hex_num("8926A27C40484216F052F4427CFD5647338B7B3939BC6573AF4333569D597C52"),
            hex_num("EACE8BDBBE353C432A795D9EC556C6D021F7A03F42C36E9BC87E4AC7932CC809"),
            hex_num("7081E175455F9247B812B74583E9E94F9EA79BD640DC962533B0680793A38D53"),
        );
        check(
            HashAlgorithm::SHA2_384,
            "sample",
            hex_num("C345D5AB3DA0A5BCB7EC8F8FB7A7E96069E03B206371EF7D83E39068EC564920"),
            hex_num("B2DA945E91858834FD9BF616EBAC151EDBC4B45D27D0DD4A7F6A22739F45C00B"),
            hex_num("19048B63D9FD6BCA1D9BAE3664E1BCB97F7276C306130969F63F38FA8319021B"),
        );
        check(
            HashAlgorithm::SHA2_512,
            "sample",
            hex_num("5A12994431785485B3F5F067221517791B85A597B7A9436995C89ED0374668FC"),
            hex_num("2016ED092DC5FB669B8EFB3D1F31A91EECB199879BE0CF78F02BA062CB4C942E"),
            hex_num("D0C76F84B5F091E141572A639A4FB8C230807EEA7D55C8A154A224400AFF2351"),
        );
        check(
            HashAlgorithm::SHA1,
            "test",
            hex_num("6EEA486F9D41A037B2C640BC5645694FF8FF4B98D066A25F76BE641CCB24BA4F"),
            hex_num("C18270A93CFC6063F57A4DFA86024F700D980E4CF4E2CB65A504397273D98EA0"),
            hex_num("414F22E5F31A8B6D33295C7539C1C1BA3A6160D7D68D50AC0D3A5BEAC2884FAA"),
        );
        check(
            HashAlgorithm::SHA2_224,
            "test",
            hex_num("06BD4C05ED74719106223BE33F2D95DA6B3B541DAD7BFBD7AC508213B6DA6670"),
            hex_num("272ABA31572F6CC55E30BF616B7A265312018DD325BE031BE0CC82AA17870EA3"),
            hex_num("E9CC286A52CCE201586722D36D1E917EB96A4EBDB47932F9576AC645B3A60806"),
        );
        check(
            HashAlgorithm::SHA2_256,
            "test",
            hex_num("1D6CE6DDA1C5D37307839CD03AB0A5CBB18E60D800937D67DFB4479AAC8DEAD7"),
            hex_num("8190012A1969F9957D56FCCAAD223186F423398D58EF5B3CEFD5A4146A4476F0"),
            hex_num("7452A53F7075D417B4B013B278D1BB8BBD21863F5E7B1CEE679CF2188E1AB19E"),
        );
        check(
            HashAlgorithm::SHA2_384,
            "test",
            hex_num("206E61F73DBE1B2DC8BE736B22B079E9DACD974DB00EEBBC5B64CAD39CF9F91C"),
            hex_num("239E66DDBE8F8C230A3D071D601B6FFBDFB5901F94D444C6AF56F732BEB954BE"),
            hex_num("6BD737513D5E72FE85D1C750E0F73921FE299B945AAD1C802F15C26A43D34961"),
        );
        check(
            HashAlgorithm::SHA2_512,
            "test",
            hex_num("AFF1651E4CD6036D57AA8B2A05CCF1A9D5A40166340ECBBDC55BE10B568AA0AA"),
            hex_num("89EC4BB1400ECCFF8E7D9AA515CD1DE7803F2DAFF09693EE7FD1353E90A68307"),
            hex_num("C9F0BDABCC0D880BB137A994CC7F3980CE91CC10FAF529FC46565B15CEA854E1"),
        );
    }

    /// NIST Cryptographic Algorithm Validation Program (CAVP) -> Test Vectors -> FIPS 186-4 -> DSA
    /// https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/digital-signatures
    /// Download this zip:
    /// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-3dsatestvectors.zip
    /// Look in file PQGGen.txt
    /// These are just two tests, and these are some of the fastest runs in the list of test vectors.
    /// But in debug mode each test still costs more than 2 seconds on my local system...
    #[test]
    fn test_domain_generation_1() {
        let _ = pretty_env_logger::try_init();

        let seed = hex!("1f5da0af598eeadee6e6665bf880e63d8b609ba2");
        let (p, q) = generate_p_q_with_seed::<Sha1>(1024, 160, &seed).unwrap();

        assert_eq!(p, hex_num("b5cf7916632405a72a407979949ee858c91adfcabfaa6cca0e5456090b0d8eb7f36c34f23dfe1759c4a3adcd776629d871214560e5e11b2f79792f040042987091c55951060bcb5fdf7cb93fed8b45fea26376e7682fc601df883dc7e272489b83181aac7340a1eb0a0fc97f53ac80f3f965cd8abcd7aa5fe1d2e38a357cb9f1"));
        assert_eq!(q, hex_num("ab1a788bce3c557a965a5bfa6908faa665fdeb7d"));
    }

    /// See above, split out to try and parallelize it.
    #[test]
    fn test_domain_generation_2() {
        let _ = pretty_env_logger::try_init();

        let seed = hex!("39f637d1c0b3286d1900b2de9769a14e0f6c9945");
        let (p, q) = generate_p_q_with_seed::<Sha224>(1024, 160, &seed).unwrap();

        assert_eq!(p, hex_num("801052c33c93eac96defda9044c1f26c3089003f9cbd8cf47103e5847e858e30f6114384af7c83ac77b21a130c109ed21027bdf196ba8b36dccdeeda2a6ae326752fddd3b305b1058ca1837457b370a4aea666878704dc11a69686ae4b18a55df6f1a250225d14d58bbe243d77c933aeb15da3b399ca549e60740e946170cb09"));
        assert_eq!(q, hex_num("a02bc4e4265bbfa82b1a7769f4d1ad936744623f"));
    }

    #[test]
    fn test_end_to_end() {
        let mut rng = thread_rng();

        let (p, q) = generate_p_q::<Sha256, _>(&mut rng, 1024, 160, 256).unwrap();

        let g = generate_g(&mut rng, &p, &q).unwrap();

        validate_g(&p, &q, &g).unwrap();

        let (x, y) = generate_x_y(&mut rng, &p, &q, &g).unwrap();

        let message = "hello world!".as_bytes();

        let hashed = Sha256::digest(message);

        let (r, s) = sign(&p, &q, &g, &x, HashAlgorithm::SHA2_256, hashed.as_slice()).unwrap();

        verify(&p, &q, &g, &y, hashed.as_slice(), &r, &s).unwrap();
    }
}
