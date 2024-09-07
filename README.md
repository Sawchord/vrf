# VRF

:warning: This Library is currently a proof of concept. It has not been audited, nor am I currently planing to develop this into a production ready library. Use at your own risk! :warning:

This is a (partially) [RFC9381](https://www.rfc-editor.org/rfc/rfc9381.html) compliant implementation of a verifiable random function.
In particular, currently only the `ECVRF-EDWARDS25519-SHA512-TAI` ciphersuite is implemented.
It supports `![no_std]` environments and does not need an allocator.

## Description

A VRF is a construction that fulfills the following properties:
1. **Full Uniqueness**: It is infeasible to generate two different proofs for the same public key and context.
2. **Collision Resistance**: Same as for hash functions, it is infeasible to find two sets of proof intputs, such that the output randomness is identical.
3. **Pseudorandom**: The randomness output of a VRF has the same properties as a PRF.

## API

> Note: At the moment, key generation is not supported.
> You can use [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek) generated keys in this library.

```rust
        let pub_key = PublicKey::from(&sk);

        // Generate the proof
        let (proof, gen_hash) = VrfProof::generate(&pub_key, &sk, r"Context");

        // Validate the proof
        val_hash = proof.verify(&pub_key, r"Context").unwrap();

        assert_eq!(gen_hash, val_hash);
```

### License

This software is licensed either under Apache 2.0 or the MIT license.

### Contributing

I am currently not planning to implement the full ciphersuite.
Contributions welcome.