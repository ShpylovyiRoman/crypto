use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, Zero};

/// Extended Euclidian algorithm. Taken directly from wikipedia
#[allow(clippy::many_single_char_names)]
pub fn egcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    let (mut old_r, mut r) = (a.to_owned(), b.to_owned());
    let (mut old_s, mut s) = (BigInt::one(), BigInt::zero());
    let (mut old_t, mut t) = (BigInt::zero(), BigInt::one());

    while !r.is_zero() {
        let q = &old_r / &r;

        let temp = r.clone();
        r = old_r - &q * r;
        old_r = temp;

        let temp = s.clone();
        s = old_s - &q * s;
        old_s = temp;

        let temp = t.clone();
        t = old_t - q * t;
        old_t = temp;
    }
    (old_r, old_s, old_t)
}

#[allow(clippy::many_single_char_names)]
pub fn mod_inv(a: &BigInt, n: &BigInt) -> Option<BigInt> {
    let (gcd, inverse, _) = egcd(a, n);
    if gcd == One::one() {
        Some(inverse.mod_floor(n))
    } else {
        None
    }
}
