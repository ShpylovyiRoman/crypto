use num_bigint::{BigInt, Sign};
use num_traits::One;

use crate::{prime, utils};

const EXP: u32 = 65537;

const MIN_KEY_SIZE: usize = 64;
const MAX_KEY_SIZE: usize = 16384;

pub struct RsaPrivate {
    d: BigInt,
    n: BigInt,
}

impl RsaPrivate {
    /// Get a reference to the rsa private's d.
    pub fn d(&self) -> &BigInt {
        &self.d
    }

    /// Get a reference to the rsa private's n.
    pub fn n(&self) -> &BigInt {
        &self.n
    }

    pub fn decrypt(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let invalid_msg = || anyhow::anyhow!("invalid message");

        let num = BigInt::from_bytes_be(Sign::Plus, msg);
        if num >= self.n {
            return Err(invalid_msg());
        }

        let decrypted = num.modpow(&self.d, &self.n);
        let (_, bytes) = decrypted.to_bytes_be();
        let padd_end = bytes.iter().position(|b| *b != 0).ok_or_else(invalid_msg)?;
        if bytes[padd_end] != 0x01 {
            Err(invalid_msg())
        } else {
            Ok(bytes[padd_end + 1..].into())
        }
    }
}

pub struct RsaPublic {
    e: BigInt,
    n: BigInt,
}

impl RsaPublic {
    /// Get a reference to the rsa public's e.
    pub fn e(&self) -> &BigInt {
        &self.e
    }

    /// Get a reference to the rsa public's n.
    pub fn n(&self) -> &BigInt {
        &self.n
    }

    pub fn encrypt(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        // To deal with leading zeroes, our data would look like:
        // data = 01 || msg
        let mut buff = vec![0x01];
        buff.extend_from_slice(data);
        let num = BigInt::from_bytes_be(Sign::Plus, &buff);
        if num >= self.n {
            anyhow::bail!("message is too large")
        }

        let encrypted = num.modpow(&self.e, &self.n);
        let (_sign, bytes) = encrypted.to_bytes_be();
        Ok(bytes)
    }
}

/// Generates RSA key pair
#[allow(clippy::many_single_char_names)]
pub fn gen_pair(size: usize) -> anyhow::Result<(RsaPublic, RsaPrivate)> {
    if size < MIN_KEY_SIZE {
        anyhow::bail!("key size is too small")
    }
    if size > MAX_KEY_SIZE {
        anyhow::bail!("key size is too big")
    }
    let size = size / 2;
    let e = BigInt::from(EXP);

    let try_generate = || {
        let (p, q) = gen_prime_pair(size, &e);
        let n = &p * &q;
        let totient = (p - 1u32) * (q - 1u32);
        let d = utils::mod_inv(&e, &totient)?;
        Some((d, n))
    };

    let (d, n) = loop {
        if let Some(pair) = try_generate() {
            break pair;
        }
    };
    let public = RsaPublic { e, n: n.clone() };
    let private = RsaPrivate { d, n };
    Ok((public, private))
}

/// Generates prime P of given size until P % e != 1
fn gen_prime(size: usize, e: &BigInt) -> BigInt {
    loop {
        let p = prime::gen(size);
        if &p % e != One::one() {
            return p;
        }
    }
}

fn gen_prime_pair(size: usize, e: &BigInt) -> (BigInt, BigInt) {
    let p = gen_prime(size, e);
    loop {
        let q = gen_prime(size, e);
        if p != q {
            break (p, q);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gen_composite() {
        let (public, private) = gen_pair(256).unwrap();

        assert_eq!(public.n(), private.n());
        assert!(!prime::is_prime(private.n()));
    }

    #[test]
    fn encrypt_decrypt() {
        let (public, private) = gen_pair(256).unwrap();

        let data = b"attack at dawn";
        let encrypted = public.encrypt(data).unwrap();

        let decrypted = private.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, data)
    }

    #[test]
    fn encrypt_decrypt_empty() {
        let (public, private) = gen_pair(256).unwrap();

        let data = b"";
        let encrypted = public.encrypt(data).unwrap();

        let decrypted = private.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, data)
    }

    #[test]
    fn encrypt_decrypt_zero_padding() {
        let (public, private) = gen_pair(256).unwrap();

        let data = [0, 0, 0, 1, 2, 17];
        let encrypted = public.encrypt(&data).unwrap();

        let decrypted = private.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, data)
    }
}
