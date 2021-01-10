---
title:    Play-RSA
subtitle: Implementation of RSA cryptography in Rust for pedagogical use
author:   Jens Getreu
date:     2020-03-31
lang:     en-GB
---

<!-- first version: v1.0, 31.7.2015 -->


_Play-RSA_ is an implementation of RSA cryptography in Rust [^1].

[![Cargo](https://img.shields.io/crates/v/play-rsa.svg)](
https://crates.io/crates/play-rsa)
[![Documentation](https://docs.rs/play-rsa/badge.svg)](
https://docs.rs/play-rsa)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](
https://gitlab.com/getreu/play-rsa)

The algorithms are implemented as described on Wikipedia.[^2] Please find
concrete links and pseudocode samples in the source code. 

Disclaimer
> This code is written for pedagogical use only. It does not provide
> security in real world settings.


## Installation

Download, compile and install

    > cargo install play-rsa

Test

    > play-rsa

## Build and execute the encryption/decryption binary

Download, unpack and change into directory `play-rsa` where the file
`Cargo.toml` resides.

    > cargo run --release

With my notebook the key generation of the 1024 bit key takes some seconds.
Because all calculations are preformed with the `BigUint` type,
the key length is mainly limited by the execution time. 1024 bit seems
a good compromise for the chosen algorithms and hardware.

**Sample output for a key length of 256 bits.**

```
FINDING BIG PRIME NUMBERS

'96543390677764721740735128239245428995208381696823499601989570975501893576667 is prime' is a true statement!


RSA PUBLIC KEY ENCRYPTION

Plaintext:            'Coming tomorrow!'

Generating key pair...
* Private key is: d=0x0ae6893332356966ecb6eec38e11a8dc6f6ec7925f5d4f18eb3b1c6c400d39ab, n=0x1059cdcccb501e1a63126625551a7d4b28dd4077e5b850ee69a8551081d2c6f5, 
* Public key is:  e=0x03, n=0x1059cdcccb501e1a63126625551a7d4b28dd4077e5b850ee69a8551081d2c6f5, key_size=256

Ciphertext:           '0x01a93489f8f4bfb95ed88a99ff4faa9894c3f2fa26f401df6f7e40601444fdb2'

Decrypted ciphertext: 'Coming tomorrow!'
```

[^1]: Rust version > 1.1

[^2]: Some tests are based on
  [jsanders/rust-rsa](https://github.com/jsanders/rust-rsa).

