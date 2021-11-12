#![allow(clippy::many_single_char_names)]

extern crate num;
extern crate num_bigint as bigint;
extern crate primal;
extern crate rand;
extern crate rustc_serialize;

use bigint::{BigInt, BigUint, RandBigInt, ToBigInt, ToBigUint};
use num::{Integer, One, Zero};

// Find all prime numbers
fn small_primes(bound: usize) -> Vec<usize> {
    primal::Primes::all().take(bound).collect::<Vec<usize>>()
}

// Modular exponentiation by squaring
pub fn mod_exp(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    let mut result = One::one();
    let mut b = base.to_owned();
    let mut exp = exponent.to_owned();

    while exp > Zero::zero() {
        // Accumulate current base if current exponent bit is 1
        if (&exp & 1.to_biguint().unwrap()) == One::one() {
            result *= &b;
            result %= modulus;
        }
        // Get next base by squaring
        b = &b * &b;
        b = &b % modulus;

        // Get next bit of exponent
        exp >>= 1;
    }
    result
}

// Given an even `n`, find first `s` and odd `d` such that n = 2^s*d
fn rewrite(n: &BigUint) -> (BigUint, BigUint) {
    let mut d = n.clone();
    let mut s: BigUint = Zero::zero();
    let one: BigUint = One::one();
    let two = 2.to_biguint().unwrap();

    while d.is_even() {
        d /= &two;
        s += &one;
    }
    (s, d)
}

/// Rabin-Miller primality test
///
/// TODO: this speudocode is outdated. Check for changes in new version.
///
/// [Pseudocode](https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test)
///
///'''text
///     Input: n > 3, an odd integer to be tested for primality;
///     Input: k, a parameter that determines the accuracy of the test
///     Output: composite if n is composite, otherwise probably prime
///     write n − 1 as 2s·d with d odd by factoring powers of 2 from n − 1
///     WitnessLoop: repeat k times:
///       pick a random integer a in the range [2, n − 2]
///        x ← a^d mod n
///        if x = 1 or x = n − 1 then do next WitnessLoop
///       repeat s − 1 times:
///           x ← x2 mod n
///           if x = 1 then return composite
///           if x = n − 1 then do next WitnessLoop
///       return composite
///    return probably prime
///'''

fn rabin_miller(candidate: &BigUint) -> bool {
    // Rabin-Miller until probability of false-positive is < 2^-128
    const K: usize = 128usize;

    //let zero: BigUint = Zero::zero();
    let one: BigUint = One::one();
    let two = 2.to_biguint().unwrap();
    let three = 3.to_biguint().unwrap();

    //println!("prime candidate = {}", candidate.to_bytes_be().to_hex());

    // Rabin-Miller has trouble with even numbers, so special case them
    if candidate == &two {
        return true;
    }
    if candidate == &three {
        return true;
    }
    if candidate.is_even() {
        return false;
    }

    let (mut s, d) = rewrite(&(candidate - &one));
    // Probability of false-positive is 2^-k
    'witness_loop: for _ in 0..K {
        let mut rng = rand::thread_rng();
        let basis = rng.gen_biguint_range(&two, &(candidate - &one));
        let mut x = mod_exp(&basis, &d, candidate);

        if x == one || x == (candidate - &one) {
            break 'witness_loop;
        }

        while s > one {
            // loop s-1 times

            x = (&x * &x) % candidate;
            if x == candidate - &one {
                break 'witness_loop;
            } else if x == one {
                return false;
            }
            s -= &one;
        }
        return false;
    }
    true
}

pub fn is_prime(candidate: &BigUint) -> bool {
    for p in small_primes(100).iter() {
        let bigp = p.to_biguint().unwrap();
        if *candidate == bigp {
            return true;
        } else if bigp.divides(candidate) {
            return false;
        }
    }
    rabin_miller(candidate)
}

pub fn big_prime(bitsize: usize) -> BigUint {
    let one: BigUint = One::one();
    let two = 2.to_biguint().unwrap();

    let mut rng = rand::thread_rng();
    let mut candidate = rng.gen_biguint(bitsize);
    if candidate.is_even() {
        candidate = &candidate + &one;
    }
    while !is_prime(&candidate) {
        candidate = &candidate + &two;
    }
    candidate
}

/// An prime suitable for RSA with exponent `e`
/// The prime `p` - 1 can't be a multiple of `e`
pub fn rsa_prime(size: usize, e: &BigUint) -> BigUint {
    loop {
        let p = big_prime(size);
        if &p % e != One::one() {
            return p;
        }
    }
}

/// Extended Euclidean GCD algorithm
/// Returns k, s,and t such that as + bt = k, where k is the gcd of a and b
///
/// [Pseudocode](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Polynomial_extended_Euclidean_algorithm)
///
///'''text
///     function extended_gcd(a, b)
///     s := 0;    old_s := 1
///     t := 1;    old_t := 0
///     r := b;    old_r := a
///     while r ≠ 0
///        quotient := old_r div r
///         (old_r, r) := (r, old_r - quotient * r)
///         (old_s, s) := (s, old_s - quotient * s)
///        (old_t, t) := (t, old_t - quotient * t)
///     output "Bézout coefficients:", (old_s, old_t)
///     output "greatest common divisor:", old_r
///     output "quotients by the gcd:", (t, s)
///'''

pub fn extended_gcd(a: &BigUint, b: &BigUint) -> (BigInt, BigInt, BigInt) {
    //println!("a={},\tb={}", a, b);

    let (mut s, mut old_s, mut t, mut old_t): (BigInt, BigInt, BigInt, BigInt) =
        (Zero::zero(), One::one(), One::one(), Zero::zero());

    let (mut r, mut old_r) = (b.to_bigint().unwrap(), a.to_bigint().unwrap());

    while r != Zero::zero() {
        let quotient = &old_r / &r;

        let mut tmp = &old_r - &quotient * &r;
        old_r = r;
        r = tmp;

        tmp = &old_s - &quotient * &s;
        old_s = s;
        s = tmp;

        tmp = &old_t - &quotient * &t;
        old_t = t;
        t = tmp;

        //println!("old_r={},\tr={},\told_s={},\ts={},\told_t={},\tt={}",
        //                                old_r,r,old_s,s,old_t,t);
        //println!("gcd= {}, s={}, t={}",&old_r,&s,&t);
    }
    let gcd = old_r;
    (gcd, s, t)
}

/// Returns the multiplicative inverse of a modulo n.
///
/// Bézout's identity asserts that a and n are coprime if and only
/// if there exist integers s and t such that
///    ns+at=1
/// Reducing this identity modulo n gives
///    at=1 \mod n.
///
/// Thus the remainder of the division of t by n, is the multiplicative
/// inverse of a modulo n.
///
/// [Pseudocode](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Computing_multiplicative_inverses_in_modular_structures)
///
///'''text
/// function inverse(a, n)
///     t := 0;     newt := 1;
///     r := n;     newr := a;
///     while newr ≠ 0
///         quotient := r div newr
///         (t, newt) := (newt, t - quotient * newt)
///        (r, newr) := (newr, r - quotient * newr)
///     if r > 1 then return "a is not invertible"
///     if t < 0 then t := t + n
///    return t
///'''
pub fn invmod(a: &BigUint, n: &BigUint) -> Option<BigUint> {
    let (mut t, mut new_t): (BigInt, BigInt) = (Zero::zero(), One::one());

    let (mut r, mut new_r) = (n.to_bigint().unwrap(), a.to_bigint().unwrap());

    while new_r != Zero::zero() {
        let quotient = &r / &new_r;

        let mut tmp = &t - &quotient * &new_t;
        t = new_t;
        new_t = tmp;

        tmp = &r - &quotient * &new_r;
        r = new_r;
        new_r = tmp;
    }
    if r > One::one() {
        return None;
    };
    if t < Zero::zero() {
        t = &t + &n.to_bigint().unwrap()
    };

    Some(t.to_biguint().unwrap())
}

// Run test with: cargo test -- --nocapture

#[cfg(test)]
mod test_primes {
    use super::{
        big_prime, extended_gcd, invmod, is_prime, mod_exp, rewrite, rsa_prime, small_primes,
    };
    use num::bigint::{BigUint, ToBigInt, ToBigUint};
    use num::One;
    use std::str::FromStr;
    //use rustc_serialize::hex::{ToHex};

    #[test]
    fn test_small_primes() {
        assert_eq!(small_primes(8), &[2, 3, 5, 7, 11, 13, 17, 19]);
    }

    // ok
    #[test]
    fn test_mod_exp() {
        let two = 2.to_biguint().unwrap();
        let three = 3.to_biguint().unwrap();
        let four = 4.to_biguint().unwrap();
        let seven = 7.to_biguint().unwrap();
        let one: BigUint = One::one();
        assert_eq!(mod_exp(&two, &two, &seven), four);
        assert_eq!(mod_exp(&two, &three, &seven), one);
    }

    #[test]
    fn test_rewrite() {
        let one: BigUint = One::one();
        let candidate = &221.to_biguint().unwrap();
        let (s, d) = rewrite(&(candidate - &one));

        assert!(s == 2.to_biguint().unwrap());
        assert!(d == 55.to_biguint().unwrap());
    }

    #[test]
    fn test_is_prime() {
        // Trivial composites
        assert!(!is_prime(&27.to_biguint().unwrap()));
        assert!(!is_prime(&1000.to_biguint().unwrap()));

        // Big composite
        let known_composite_str = "5998532537771751919223292779480088814208363735733315189796\
       0101571924729278483053936094631318228299245382944144514257\
       1892041750575871002135423472834270012679636490411466324906\
       0917779866191551702619628937679141866044903982454458080353\
       0712317148561932424450480592940247925414152689953357952137\
       58437410764432671";

        let known_composite: BigUint = FromStr::from_str(known_composite_str).unwrap();
        assert!(!is_prime(&known_composite));

        // Small primes, test first hundred
        for p in small_primes(100).iter() {
            assert!(is_prime(&p.to_biguint().unwrap()));
        }

        // Big primes
        assert!(is_prime(&15486869.to_biguint().unwrap()));
        assert!(is_prime(&179425357.to_biguint().unwrap()));
        let known_prime_str = "1185953636795374682612582767575507043186511556015932992921\
      98496313960907653004730006758459999825003212944725610469590\
      67402012450624977056639426083223780925249450568325586119944\
      94823851964743424816413015031211427409331862791112093760615\
      35491003888763334916103110474472949854230628809878558752830\
      476310536476569";
        let known_prime: BigUint = FromStr::from_str(known_prime_str).unwrap();
        assert!(is_prime(&known_prime));
    }

    #[test]
    fn test_big_prime() {
        let bitsize = 256;
        let p = big_prime(bitsize);

        assert!(is_prime(&p));
        assert!(p.bits() <= bitsize);
    }

    #[test]
    fn test_rsa_prime() {
        let one = One::one();
        let three = 3.to_biguint().unwrap();
        let five = 5.to_biguint().unwrap();
        let size = 256;
        assert!(rsa_prime(size, &three) % (&three) != one);
        assert!(rsa_prime(size, &five) % (&five) != one);
    }

    #[test]
    fn test_extended_gcd() {
        let a = 240.to_biguint().unwrap();
        let b = 46.to_biguint().unwrap();
        assert!(
            (
                2.to_bigint().unwrap(),
                23.to_bigint().unwrap(),
                (-129).to_bigint().unwrap()
            ) != extended_gcd(&a, &b)
        );

        let a = FromStr::from_str("129084327430198").unwrap();
        let b = FromStr::from_str("2130948098700134").unwrap();
        let (gcd, s, t) = extended_gcd(&a, &b);
        assert!((a.to_bigint().unwrap() * &s + b.to_bigint().unwrap() * &t) != gcd);
    }

    #[test]
    fn test_invmod() {
        let three = 3.to_biguint().unwrap();
        let five = 5.to_biguint().unwrap();
        let six = 6.to_biguint().unwrap();
        let seven = 7.to_biguint().unwrap();
        let fortyone = 41.to_biguint().unwrap();

        assert_eq!(invmod(&seven, &fortyone).unwrap(), six);
        assert_eq!(invmod(&three, &six), None);
        assert_eq!(invmod(&three, &seven).unwrap(), five);
    }
}
