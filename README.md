# Crypto

Cryptographic algorithms in [Zig](https://ziglang.org/).

## Algorithms

- Verifiable Random Functions (VRFs) [RFC 9381](https://datatracker.ietf.org/doc/rfc9381/)
  - [x] ECVRF-P256-SHA256-TAI
  - [ ] ECVRF-P256-SHA256-SSWU
  - [ ] ECVRF-EDWARDS25519-SHA512-TAI
  - [ ] ECVRF-EDWARDS25519-SHA512-ELL2
- Zero-Knowledge Proof
  - [ ] Schnorr Non-interactive Zero-Knowledge Proof [RFC 8235](https://datatracker.ietf.org/doc/html/rfc8235)
- Deterministic Random Bit Generator (DRBG)
  - [ ] XDRBG [iacr](https://tosc.iacr.org/index.php/ToSC/article/view/11399)

### Verifiable Random Functions (VRFs)

A Verifiable Random Function (VRF) [RFC9381](https://datatracker.ietf.org/doc/rfc9381/)
can be seen as a public-key version of a cryptographic hash function with the following
properties:
- A private-key is used to calculate a hash value.
- The hash value can be verified using the corresponding public-key.
- The hash is unpredictable and can't be skewed.

A key application of the VRF is to provide privacy against offline
dictionary attacks on data stored in a hash-based data structure.

VRFs can be used as verifiable random numbers with the following properties:
- *Uniqueness*: There is exactly one result for every computation
- *Collision Resistance*: It is (almost) impossible to find two inputs that result in the same hash.
- *Pseudo-randomness*: A hash is indistinguishable from a random value.
- *Unpredictability*: If the input is unpredictable, the output is uniformly distributed.

---

A VRF comes with a key generation algorithm that generates
a VRF key-pair.
```zig
const crypto = @import("crypto");
const vrf = crypto.EcvrfP256Sha256Tai;
const kp = try vrf.KeyPair.generate();
```

The Prover uses the secret key to construct a proof pi that
beta is the correct hash output.
```zig
const alpha = "test";
const pi = try kp.prove(alpha, null);
```

The VRF hash output beta can be directly obtained from the
proof value pi.
```zig
const beta = try vrf.proofToHash(pi);
```

The proof pi allows a Verifier holding the public key to
verify that beta is the correct VRF hash of input alpha
under the given private key.

This requires that the Prover and the Verifier exchange
public keys beforehand.

Then, the Prover submits alpha, beta, and pi to the Verifier.

The Verifier can verify the correctness by calling `verify`.
On success, verify will return beta.
```zig
// For demonstration purposes we (the Prover) also call verify.
const beta2 = try kp.public_key.verify(alpha, pi, null);
if (!std.mem.eql(u8, beta[0..], beta2[0..])) {
    // handle error...
}
```

> **Proofs Provide No Secrecy for the VRF Input**
> 
> The VRF proof pi is not designed to provide secrecy and, in general,
> may reveal the VRF input alpha.  Anyone who knows the public-key and pi is able
> to perform an offline dictionary attack to search for alpha, by
> verifying guesses for alpha using VRF_verify.  This is in contrast to
> the VRF hash output beta, which, without the proof, is pseudorandom
> and thus is designed to reveal no information about alpha.

Note: the key exchange, as well as the submission of alpha,
beta and pi are out of scope.
