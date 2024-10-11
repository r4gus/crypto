//! A Verifiable Random Function (VRF) [RFC9381](https://datatracker.ietf.org/doc/rfc9381/)
//! can be seen as a public-key version of a cryptographic hash function with the following
//! properties:
//! - A private-key is used to calculate a hash value.
//! - The hash value can be verified using the corresponding public-key.
//! - The hash is unpredictable and can't be skewed.
//!
//! A key application of the VRF is to provide privacy against offline
//! dictionary attacks on data stored in a hash-based data structure.
//!
//! VRFs can be used as verifiable random numbers with the following properties:
//! - *Uniqueness*: There is exactly one result for every computation
//! - *Collision Resistance*: It is (almost) impossible to find two
//!                           inputs that result in the same hash.
//! - *Pseudo-randomness*: A hash is indistinguishable from a random value.
//! - *Unpredictability*: If the input is unpredictable, the output is uniformly distributed.
//! # Cipher Suites
//!
//! - ECVRF-P256-SHA256-TAI
//!
//! # Example
//!
//! A VRF comes with a key generation algorithm that generates
//! a VRF key-pair.
//! ```zig
//! const vrf = EcvrfP256Sha256Tai;
//! const kp = try vrf.KeyPair.generate();
//! ```
//!
//! The Prover uses the secret key to construct a proof pi that
//! beta is the correct hash output.
//! ```zig
//! const alpha = "test";
//! const pi = try kp.prove(alpha, null);
//! ```
//!
//! The VRF hash output beta can be directly obtained from the
//! proof value pi.
//! ```zig
//! const beta = try vrf.proofToHash(pi);
//! ```
//!
//! The proof pi allows a Verifier holding the public key to
//! verify that beta is the correct VRF hash of input alpha
//! under the given private key.
//!
//! This requires that the Prover and the Verifier exchange
//! public keys beforehand.
//!
//! Then, the Prover submits alpha, beta, and pi to the Verifier.
//!
//! The Verifier can verify the correctness by calling `verify`.
//! On success, verify will return beta.
//! ```zig
//! // For demonstration purposes we (the Prover) also call verify.
//! const beta2 = try kp.public_key.verify(alpha, pi, null);
//! if (!std.mem.eql(u8, beta[0..], beta2[0..])) {
//!     // handle error...
//! }
//! ```
//!
//! Note: the key exchange, as well as the submission of alpha,
//! beta and pi are out of scope.

const std = @import("std");
const crypto = std.crypto;

const IdentityElementError = crypto.errors.IdentityElementError;
const NonCanonicalError = crypto.errors.NonCanonicalError;

/// ECVRF-P256-SHA256-TAI as defined by [RFC9381](https://datatracker.ietf.org/doc/rfc9381/)
pub const EcvrfP256Sha256Tai = struct {
    pub const suite_string = "\x01";
    pub const Curve = crypto.ecc.P256;
    pub const Hash = crypto.hash.sha2.Sha256;

    const HMAC_K = std.crypto.auth.hmac.Hmac(Hash);

    /// The length of the prime order of the group in octets.
    const qLen = Curve.scalar.encoded_length;
    /// Length, in octets, of a challenge value used by the VRF.
    const cLen = qLen / 2;
    const ptLen = 1 + Curve.Fe.encoded_length;
    const hLen = Hash.digest_length;
    pub const Pi = [ptLen + cLen + qLen]u8;
    pub const Beta = [hLen]u8;

    /// An ECVRF secret key.
    pub const SecretKey = struct {
        /// Length (in bytes) of a raw secret key.
        pub const encoded_length = Curve.scalar.encoded_length;

        bytes: Curve.scalar.CompressedScalar,

        pub fn fromBytes(bytes: [encoded_length]u8) !SecretKey {
            return SecretKey{ .bytes = bytes };
        }

        pub fn toBytes(sk: SecretKey) [encoded_length]u8 {
            return sk.bytes;
        }

        /// TFC6979 (3.2)
        pub fn nonceGeneration(sk: SecretKey, m: []const u8) Curve.scalar.CompressedScalar {
            var h1: [Hash.digest_length]u8 = undefined;
            Hash.hash(m, &h1, .{});
            var V: [Hash.digest_length]u8 = .{1} ** Hash.digest_length;
            var K: [Hash.digest_length]u8 = .{0} ** Hash.digest_length;

            // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
            var mac = HMAC_K.init(&K);
            mac.update(&V);
            mac.update("\x00");
            mac.update(&sk.toBytes());
            mac.update(&h1);
            mac.final(&K);

            // V = HMAC_K(V)
            HMAC_K.create(&V, &V, &K);

            // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
            mac = HMAC_K.init(&K);
            mac.update(&V);
            mac.update("\x01");
            mac.update(&sk.toBytes());
            mac.update(&h1);
            mac.final(&K);

            // V = HMAC_K(V)
            HMAC_K.create(&V, &V, &K);

            while (true) {
                // NOTE: tlen = qlen = 256 bits, i.e. we don't need the inner loop!
                var TV: [HMAC_K.mac_length]u8 = undefined;
                HMAC_K.create(&TV, &V, &K);
                const T: Curve.scalar.CompressedScalar = TV;
                Curve.Fe.rejectNonCanonical(T, .big) catch {
                    // K = HMAC_K(V || 0x00)
                    mac = HMAC_K.init(&K);
                    mac.update(&V);
                    mac.update("\x00");
                    mac.final(&K);

                    // V = HMAC_K(V)
                    HMAC_K.create(&V, &V, &K);

                    continue;
                };
                return T;
            }
        }
    };

    /// An ECVRF public key.
    pub const PublicKey = struct {
        p: Point,

        pub fn pointToString(pk: PublicKey) [ptLen]u8 {
            return pk.p.toCompressedSec1();
        }

        pub fn verify(
            pk: PublicKey,
            alpha: []const u8,
            pi_string: Pi,
            encode_to_curve_salt: ?[]const u8,
        ) !Beta {
            _ = encode_to_curve_salt;
            const D = try DecodedProof.decodeProof(pi_string);
            const H = try helper.encodeToCurve(&pk.pointToString(), alpha);
            const sB = try Curve.basePoint.mul(D.s, .big);
            const cY = try pk.p.p.mul(D.c, .big);
            const U = sB.sub(cY);

            const sH = try H.p.mul(D.s, .big);
            const cGamma = try D.Gamma.p.mul(D.c, .big);
            const V = sH.sub(cGamma);

            const ctick = helper.challengeGeneration(
                pk.p,
                H,
                D.Gamma,
                Point{ .p = U },
                Point{ .p = V },
            );

            if (!std.mem.eql(u8, D.c[0..], ctick[0..])) return error.Invalid;
            return try proofToHash(pi_string);
        }
    };

    /// An ECVRF point.
    pub const Point = struct {
        /// Length (in bytes) of a compressed sec1-encoded point.
        pub const compressed_sec1_encoded_length = 1 + Curve.Fe.encoded_length;
        /// Length (in bytes) of a compressed sec1-encoded point.
        pub const uncompressed_sec1_encoded_length = 1 + 2 * Curve.Fe.encoded_length;

        p: Curve,

        /// Create a public key from a SEC-1 representation.
        pub fn fromSec1(sec1: []const u8) !PublicKey {
            return PublicKey{ .p = try Curve.fromSec1(sec1) };
        }

        /// Encode the public key using the compressed SEC-1 format.
        pub fn toCompressedSec1(point: Point) [compressed_sec1_encoded_length]u8 {
            return point.p.toCompressedSec1();
        }

        /// Encoding the public key using the uncompressed SEC-1 format.
        pub fn toUncompressedSec1(point: Point) [uncompressed_sec1_encoded_length]u8 {
            return point.p.toUncompressedSec1();
        }

        pub fn pointToString(point: Point) [ptLen]u8 {
            return point.p.toCompressedSec1();
        }

        pub fn stringToPoint(s: [ptLen]u8) !Point {
            return Point{ .p = try Curve.fromSec1(&s) };
        }
    };

    /// An ECVRF key pair.
    pub const KeyPair = struct {
        /// Public part.
        public_key: PublicKey,
        /// Secret scalar.
        secret_key: SecretKey,

        /// Create a new random key pair. `crypto.random.bytes` must be supported
        /// for the target.
        pub fn generate() IdentityElementError!KeyPair {
            // Elliptic Curve Key Pair Generation Primitive (3.2.1.)
            // https://www.secg.org/sec1-v2.pdf
            const d = Curve.scalar.random(.big);
            return fromSecretKey(SecretKey{ .bytes = d });
        }

        /// Return the public key corresponding to the secret key.
        pub fn fromSecretKey(secret_key: SecretKey) IdentityElementError!KeyPair {
            const public_key = try Curve.basePoint.mul(
                secret_key.bytes,
                .big,
            );
            return KeyPair{
                .secret_key = secret_key,
                .public_key = PublicKey{
                    .p = Point{ .p = public_key },
                },
            };
        }

        pub fn encodeToCurve(key_pair: KeyPair, alpha: []const u8) !Point {
            return helper.encodeToCurve(
                &key_pair.public_key.pointToString(),
                alpha,
            );
        }

        /// Construct a proof `Pi` that `Beta` is the correct hash output.
        ///
        /// note: salt is ignored for the given implementation.
        pub fn prove(key_pair: KeyPair, alpha: []const u8, salt: ?[]const u8) !Pi {
            _ = salt;
            const H = try key_pair.encodeToCurve(alpha);
            const h_string = H.pointToString();
            const Gamma = Point{ .p = try H.p.mul(key_pair.secret_key.toBytes(), .big) };
            const k = key_pair.secret_key.nonceGeneration(&h_string);
            const U = Point{ .p = try Curve.basePoint.mul(k, .big) };
            const V = Point{ .p = try H.p.mul(k, .big) };
            const c = helper.challengeGeneration(key_pair.public_key.p, H, Gamma, U, V);
            const s = try Curve.scalar.mulAdd(c, key_pair.secret_key.toBytes(), k, .big);

            var pi: Pi = undefined;
            @memcpy(pi[0..ptLen], &Gamma.pointToString());
            @memcpy(pi[ptLen .. ptLen + cLen], c[cLen..]);
            @memcpy(pi[ptLen + cLen .. ptLen + cLen + qLen], &s);

            return pi;
        }
    };

    /// The decoded version of a proof Pi.
    pub const DecodedProof = struct {
        /// A Point on the Curve
        Gamma: Point,
        /// An integer between 0 and 2^(8*cLen)-1
        c: [qLen]u8,
        /// An integer between 0 and q-1
        s: [qLen]u8,

        pub fn decodeProof(pi_string: Pi) !DecodedProof {
            const gamma_string = pi_string[0..ptLen];
            const c_string = pi_string[ptLen .. ptLen + cLen];
            const s_string = pi_string[ptLen + cLen ..];
            const Gamma = Point.stringToPoint(gamma_string.*) catch {
                return error.Invalid;
            };
            var c: [qLen]u8 = .{0} ** qLen;
            @memcpy(c[cLen..], c_string);
            var s: [qLen]u8 = .{0} ** qLen;
            @memcpy(&s, s_string);
            Curve.Fe.rejectNonCanonical(s, .big) catch {
                return error.Invalid;
            };

            return .{
                .Gamma = Gamma,
                .c = c,
                .s = s,
            };
        }
    };

    /// ECVRF proof to hash
    ///
    /// Deterministically obtain the VRF hash output `Beta` directly
    /// from the proof value `Pi`.
    ///
    /// note: `proofToHash` should be run only on a pi_string value that
    /// is known to have been produced by `prove`, or from within
    /// `verify` as specified in Section 5.3. of RFC9381.
    pub fn proofToHash(pi_string: Pi) !Beta {
        const proof_to_hash_domain_separator_front = "\x03";
        const proof_to_hash_domain_separator_back = "\x00";
        const D = try DecodedProof.decodeProof(pi_string);
        var beta_string: Beta = .{0} ** hLen;

        var h = Hash.init(.{});
        h.update(suite_string);
        h.update(proof_to_hash_domain_separator_front);
        h.update(&D.Gamma.pointToString());
        h.update(proof_to_hash_domain_separator_back);
        h.final(&beta_string);

        return beta_string;
    }

    pub const helper = struct {
        /// ECVRF_encode_to_curve_try_and_increment RFC9381 5.4.1.1
        pub fn encodeToCurve(salt: []const u8, alpha: []const u8) !Point {
            var ctr: u8 = 0;
            const encode_to_curve_domain_separator_front = "\x01";
            const encode_to_curve_domain_separator_back = "\x00";
            // loop is expected to stop after roughly two iterations!
            // we allow one iteration less but that's ok... no one
            // should ever reach this.
            while (ctr < 255) : (ctr += 1) {
                const ctr_string: [1]u8 = .{ctr};
                var h = Hash.init(.{});
                h.update(suite_string);
                h.update(encode_to_curve_domain_separator_front);
                h.update(salt);
                h.update(alpha);
                h.update(&ctr_string);
                h.update(encode_to_curve_domain_separator_back);

                var H: [ptLen]u8 = .{0} ** ptLen;
                H[0] = 0x02;
                h.final(H[1..]);
                const pk = Point.stringToPoint(H) catch continue;
                return pk;
            }

            return error.NoCurve;
        }

        /// ECVRF Challenge Generation (5.4.3.)
        ///
        /// This function takes five points and generates a
        /// challenge from them by calculating:
        /// ```
        /// h = Hash(suite_string || 0x02 || P1 || ... || P5 || 0x00)
        /// scalar = 0x00 ** (qLen - cLen) || h[0..cLen]
        /// ```
        /// The return values is a scalar of qLen bytes.
        ///
        /// Note: The LSBytes of the scalar are all set to 0x00, i.e.,
        /// one can directly use it for arithmetic operations. The
        /// actual challenge is located in the second half of the
        /// scalar.
        pub fn challengeGeneration(
            p1: Point,
            p2: Point,
            p3: Point,
            p4: Point,
            p5: Point,
        ) Curve.scalar.CompressedScalar {
            const challenge_generation_domain_separator_front = "\x02";
            const challenge_generation_domain_separator_back = "\x00";
            var str: [3 + ptLen * 5]u8 = undefined;
            str[0] = suite_string[0];
            str[1] = challenge_generation_domain_separator_front[0];
            @memcpy(str[2 .. 2 + ptLen], &p1.pointToString());
            @memcpy(str[2 + ptLen .. 2 + ptLen * 2], &p2.pointToString());
            @memcpy(str[2 + ptLen * 2 .. 2 + ptLen * 3], &p3.pointToString());
            @memcpy(str[2 + ptLen * 3 .. 2 + ptLen * 4], &p4.pointToString());
            @memcpy(str[2 + ptLen * 4 .. 2 + ptLen * 5], &p5.pointToString());
            str[2 + ptLen * 5] = challenge_generation_domain_separator_back[0];
            var c_string: [Hash.digest_length]u8 = undefined;
            Hash.hash(&str, &c_string, .{});

            var truncated_c_string: Curve.scalar.CompressedScalar = .{0} ** qLen;
            @memcpy(truncated_c_string[cLen..], c_string[0..cLen]);
            return truncated_c_string;
        }
    };
};

test "ECVRF-P256-SHA256-TAI Example 10 with steps" {
    const vrf = EcvrfP256Sha256Tai;
    const x = try vrf.SecretKey.fromBytes("\xc9\xaf\xa9\xd8\x45\xba\x75\x16\x6b\x5c\x21\x57\x67\xb1\xd6\x93\x4e\x50\xc3\xdb\x36\xe8\x9b\x12\x7b\x8a\x62\x2b\x12\x0f\x67\x21".*);
    const xy = try vrf.KeyPair.fromSecretKey(x);

    try std.testing.expectEqualSlices(
        u8,
        "\x03\x60\xfe\xd4\xba\x25\x5a\x9d\x31\xc9\x61\xeb\x74\xc6\x35\x6d\x68\xc0\x49\xb8\x92\x3b\x61\xfa\x6c\xe6\x69\x62\x2e\x60\xf2\x9f\xb6",
        &xy.public_key.pointToString(),
    );

    const alpha = "sample";

    // try_and_increment should succeed on ctr = 1
    const H = try xy.encodeToCurve(alpha);
    const h_string = H.pointToString();
    try std.testing.expectEqualSlices(
        u8,
        "\x02\x72\xa8\x77\x53\x2e\x9a\xc1\x93\xaf\xf4\x40\x12\x34\x26\x6f\x59\x90\x0a\x4a\x9e\x3f\xc3\xcf\xc6\xa4\xb7\xe4\x67\xa1\x5d\x06\xd4",
        &h_string,
    );

    const k = x.nonceGeneration(&h_string);
    try std.testing.expectEqualSlices(
        u8,
        "\x0d\x90\x59\x12\x73\x45\x3d\x2d\xc6\x73\x12\xd3\x99\x14\xe3\xa9\x3e\x19\x4a\xb4\x7a\x58\xcd\x59\x88\x86\x89\x70\x76\x98\x6f\x77",
        &k,
    );

    const U = try vrf.Curve.basePoint.mul(k, .big);
    try std.testing.expectEqualSlices(
        u8,
        "\x02\xbb\x6a\x03\x4f\x67\x64\x3c\x61\x83\xc1\x0f\x8b\x41\xdc\x4b\xab\xf8\x8b\xff\x15\x4b\x67\x4e\x37\x7d\x90\xbd\xe0\x09\xc2\x16\x72",
        &U.toCompressedSec1(),
    );

    const V = try H.p.mul(k, .big);
    try std.testing.expectEqualSlices(
        u8,
        "\x02\x89\x3e\xbe\xe7\xaf\x9a\x0f\xaa\x6d\xa8\x10\xda\x8a\x91\xf9\xd5\x0e\x1d\xc0\x71\x24\x0c\x97\x06\x72\x68\x20\xff\x91\x9e\x83\x94",
        &V.toCompressedSec1(),
    );
}

test "decode proof" {
    const vrf = EcvrfP256Sha256Tai;
    const pi: vrf.Pi = "\x03\x5b\x5c\x72\x6e\x8c\x0e\x2c\x48\x8a\x10\x7c\x60\x05\x78\xee\x75\xcb\x70\x23\x43\xc1\x53\xcb\x1e\xb8\xde\xc7\x7f\x4b\x50\x71\xb4\xa5\x3f\x0a\x46\xf0\x18\xbc\x2c\x56\xe5\x8d\x38\x3f\x23\x05\xe0\x97\x59\x72\xc2\x6f\xee\xa0\xeb\x12\x2f\xe7\x89\x3c\x15\xaf\x37\x6b\x33\xed\xf7\xde\x17\xc6\xea\x05\x6d\x4d\x82\xde\x6b\xc0\x2f".*;
    const dpi = try vrf.DecodedProof.decodeProof(pi);
    try std.testing.expectEqualSlices(
        u8,
        "\x03\x5b\x5c\x72\x6e\x8c\x0e\x2c\x48\x8a\x10\x7c\x60\x05\x78\xee\x75\xcb\x70\x23\x43\xc1\x53\xcb\x1e\xb8\xde\xc7\x7f\x4b\x50\x71\xb4",
        &dpi.Gamma.pointToString(),
    );
    try std.testing.expectEqualSlices(
        u8,
        "\xa5\x3f\x0a\x46\xf0\x18\xbc\x2c\x56\xe5\x8d\x38\x3f\x23\x05\xe0",
        dpi.c[16..],
    );
    try std.testing.expectEqualSlices(
        u8,
        "\x97\x59\x72\xc2\x6f\xee\xa0\xeb\x12\x2f\xe7\x89\x3c\x15\xaf\x37\x6b\x33\xed\xf7\xde\x17\xc6\xea\x05\x6d\x4d\x82\xde\x6b\xc0\x2f",
        &dpi.s,
    );
}

test "ECVRF-P256-SHA256-TAI Example 10" {
    const vrf = EcvrfP256Sha256Tai;
    const x = try vrf.SecretKey.fromBytes("\xc9\xaf\xa9\xd8\x45\xba\x75\x16\x6b\x5c\x21\x57\x67\xb1\xd6\x93\x4e\x50\xc3\xdb\x36\xe8\x9b\x12\x7b\x8a\x62\x2b\x12\x0f\x67\x21".*);
    const xy = try vrf.KeyPair.fromSecretKey(x);
    const alpha = "sample";

    const pi = try xy.prove(alpha, null);
    try std.testing.expectEqualSlices(
        u8,
        "\x03\x5b\x5c\x72\x6e\x8c\x0e\x2c\x48\x8a\x10\x7c\x60\x05\x78\xee\x75\xcb\x70\x23\x43\xc1\x53\xcb\x1e\xb8\xde\xc7\x7f\x4b\x50\x71\xb4\xa5\x3f\x0a\x46\xf0\x18\xbc\x2c\x56\xe5\x8d\x38\x3f\x23\x05\xe0\x97\x59\x72\xc2\x6f\xee\xa0\xeb\x12\x2f\xe7\x89\x3c\x15\xaf\x37\x6b\x33\xed\xf7\xde\x17\xc6\xea\x05\x6d\x4d\x82\xde\x6b\xc0\x2f",
        &pi,
    );

    const beta = try vrf.proofToHash(pi);
    try std.testing.expectEqualSlices(
        u8,
        "\xa3\xad\x7b\x0e\xf7\x3d\x8f\xc6\x65\x50\x53\xea\x22\xf9\xbe\xde\x8c\x74\x3f\x08\xbb\xed\x3d\x38\x82\x1f\x0e\x16\x47\x4b\x50\x5e",
        &beta,
    );

    const verified = try xy.public_key.verify(alpha, pi, null);
    try std.testing.expectEqualSlices(
        u8,
        &beta,
        &verified,
    );

    // negative test
    try std.testing.expectError(error.Invalid, xy.public_key.verify("sAmple", pi, null));
}

test "key generation" {
    const vrf = EcvrfP256Sha256Tai;
    const kp = try vrf.KeyPair.generate();
    const alpha = "test";

    const pi = try kp.prove(alpha, null);
    const beta = try vrf.proofToHash(pi);
    const verified = try kp.public_key.verify(alpha, pi, null);
    try std.testing.expectEqualSlices(
        u8,
        &beta,
        &verified,
    );
}
