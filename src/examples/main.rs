extern crate libplayrsa;
use libplayrsa::*;

#[allow(dead_code)]
fn main() {
    println!("\nFINDING BIG PRIME NUMBERS");
    let p = primes::big_prime(256);
    println!(
        "\n'{} is prime' is a {} statement!",
        p,
        primes::is_prime(&p)
    );

    println!("\n\nRSA PUBLIC KEY ENCRYPTION");
    let message = "Coming tomorrow!";
    println!("\nPlaintext:            '{}'", message);
    println!("\nGenerating key pair...");
    //let (public_key, private_key) = gen_keys_default();
    let (public_key, private_key) =
        gen_keys(KeySizeT::KeySize(256), PublicExponentT::DefaultExponent);
    println!("* Private key is: {}", private_key);
    println!("* Public key is:  {}", public_key);

    let encrypted = public_key.encrypt(message);
    println!("\nCiphertext:           '0x{}'", encrypted);
    let decrypted = private_key.decrypt(&encrypted);
    println!("\nDecrypted ciphertext: '{}'", decrypted);
}
