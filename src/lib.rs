#![allow(clippy::many_single_char_names)]

extern crate num;
extern crate rand;
extern crate rustc_serialize;

use num::bigint::{BigUint, ToBigUint};

use num::traits::Num;
use rustc_serialize::hex::ToHex;
use std::fmt;

pub mod primes;

pub enum KeySizeT {
    DefaultKeySize,
    KeySize(usize),
}

pub enum PublicExponentT {
    DefaultExponent,
    Exponent(usize),
}

#[derive(Debug)]
pub struct PublicKey {
    e: BigUint,
    n: BigUint,
    key_size: usize,
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "e=0x{}, ", self.e.to_bytes_be().to_hex())?;
        write!(f, "n=0x{}, ", self.n.to_bytes_be().to_hex())?;
        write!(f, "key_size={}", self.key_size)
    }
}

#[derive(Debug)]
pub struct PrivateKey {
    d: BigUint,
    n: BigUint,
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "d=0x{}, ", self.d.to_bytes_be().to_hex())?;
        write!(f, "n=0x{}, ", self.n.to_bytes_be().to_hex())
    }
}

/// Generate RSA key-pair with default size and exponent.
pub fn gen_keys_default() -> (PublicKey, PrivateKey) {
    gen_keys(KeySizeT::DefaultKeySize, PublicExponentT::DefaultExponent)
}

/// Generate RSA key-pair with given size and exponent.
pub fn gen_keys(key_size: KeySizeT, e: PublicExponentT) -> (PublicKey, PrivateKey) {
    let key_size = match key_size {
        KeySizeT::KeySize(key_size) => key_size,
        _ => 1024, // This is the default key size!
    };
    let prime_size = key_size / 2;

    let e = match e {
        PublicExponentT::Exponent(e) => e,
        _ => 3, // This is the default exponent!
    }
    .to_biguint()
    .unwrap();

    let p = primes::rsa_prime(prime_size, &e);
    let q = primes::rsa_prime(prime_size, &e);
    let n = &p * &q;
    let one = 1.to_biguint().unwrap();
    let et = (&p - &one) * (&q - &one);
    let d = primes::invmod(&e, &et).unwrap();

    let public_key = PublicKey {
        e,
        n: n.clone(),
        key_size,
    };
    let private_key = PrivateKey { d, n };
    (public_key, private_key)
}

impl PublicKey {
    pub fn encrypt_biguint<'a>(&'a self, m: &BigUint) -> BigUint {
        primes::mod_exp(m, &self.e, &self.n)
    }

    /// Encrypt a message using this public key
    pub fn encrypt(self, m: &str) -> String {
        let max_len = self.key_size / 8;
        assert!(
            m.len() < max_len,
            "Message must be less than {} bytes for RSA with key size {}",
            max_len,
            self.key_size
        );

        let p: BigUint = m.as_utf8_to_biguint();
        let c: BigUint = self.encrypt_biguint(&p);
        let c_hex: String = c.to_bytes_be().to_hex();
        c_hex
    }
}

impl PrivateKey {
    pub fn decrypt_biguint(&self, c: &BigUint) -> BigUint {
        primes::mod_exp(c, &self.d, &self.n)
    }

    /// Decrypt a message using this private key
    pub fn decrypt(&self, m: &str) -> String {
        let p = self.decrypt_biguint(&m.as_hex_to_biguint());
        p.to_string_as_utf8()
    }
}

/// Encoding helper functions

trait ParseToBigUint {
    fn as_hex_to_biguint(&self) -> BigUint;
    fn as_utf8_to_biguint(&self) -> BigUint;
}

impl ParseToBigUint for str {
    fn as_hex_to_biguint(&self) -> BigUint {
        BigUint::from_str_radix(self, 16).unwrap()
    }

    fn as_utf8_to_biguint(&self) -> BigUint {
        BigUint::from_bytes_be(self.as_bytes())
    }
}

trait ParseToString {
    fn to_string_as_hex(&self) -> String;
    fn to_binstr_as_ascii(&self) -> String;
    fn to_string_as_utf8(&self) -> String;
}

impl ParseToString for BigUint {
    fn to_string_as_hex(&self) -> String {
        self.to_bytes_be().to_hex()
    }

    fn to_binstr_as_ascii(&self) -> String {
        let mut r = String::new();
        for x in self.to_bytes_be() {
            r.push_str(&*format!("{:8b}", x).replace(" ", "0"));
        }
        r
    }

    fn to_string_as_utf8(&self) -> String {
        String::from_utf8(self.to_bytes_be()).unwrap()
    }
}

#[cfg(test)]
mod test_rsa {
    use super::{gen_keys, gen_keys_default};
    use super::{KeySizeT, PublicExponentT};
    use super::{ParseToBigUint, ParseToString};
    use num::bigint::ToBigUint;

    #[test]
    fn test_conversions() {
        assert_eq!(
            "abcd".as_utf8_to_biguint(),
            1633837924.to_biguint().unwrap()
        );
        assert_eq!(
            "61626364".as_hex_to_biguint(),
            1633837924.to_biguint().unwrap()
        );
        assert_eq!(
            &1633837924.to_biguint().unwrap().to_string_as_utf8(),
            "abcd"
        );
        assert_eq!(
            &1633837924.to_biguint().unwrap().to_string_as_hex(),
            "61626364"
        );
    }

    #[test]
    fn test_encrypt_decrypt_biguint() {
        let (public, private) = gen_keys_default();
        let m = 1633837924.to_biguint().unwrap();
        let encrypted = public.encrypt_biguint(&m);
        let decrypted = private.decrypt_biguint(&encrypted);
        assert_eq!(m, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_default() {
        let (public, private) = gen_keys_default();
        let m = "my super secret";
        let encrypted = public.encrypt(m.clone());
        let decrypted = private.decrypt(&*encrypted);
        assert_eq!(m, &*decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_five() {
        let (public, private) = gen_keys(KeySizeT::KeySize(512), PublicExponentT::Exponent(5));
        let m = "my super secret";
        let encrypted = public.encrypt(m.clone());
        let decrypted = private.decrypt(&*encrypted);
        assert_eq!(m, &*decrypted);
    }
}
