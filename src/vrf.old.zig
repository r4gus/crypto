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
const std = @import("std");
const crypto = std.crypto;

const IdentityElementError = crypto.errors.IdentityElementError;
const NonCanonicalError = crypto.errors.NonCanonicalError;

pub const EcvrfP256Sha256Tai = ECVRF(
    "\x01",
    crypto.ecc.P256,
    crypto.hash.sha2.Sha256,
    .TryAndIncrement,
);

pub const EncodeToCurveMode = enum {
    TryAndIncrement,
    H2cSuite,
};

pub fn ECVRF(
    comptime suite_string: []const u8,
    comptime Curve: type,
    comptime Hash: type,
    comptime encode_to_curve_mode: EncodeToCurveMode,
) type {
    return struct {
        /// The length of the prime order of the group in octets.
        const qLen = Curve.scalar.encoded_length;
        /// Length, in octets, of a challenge value used by the VRF.
        const cLen = qLen / 2;

        const HMAC_K = std.crypto.auth.hmac.Hmac(Hash);

        pub const ptLen = switch (Curve) {
            crypto.ecc.P256 => 1 + Curve.Fe.encoded_length,
            else => @compileError("unsupported curve"),
        };

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
        };

        /// An ECVRF public key.
        pub const PublicKey = struct {
            /// Length (in bytes) of a compressed sec1-encoded key.
            pub const compressed_sec1_encoded_length = 1 + Curve.Fe.encoded_length;
            /// Length (in bytes) of a compressed sec1-encoded key.
            pub const uncompressed_sec1_encoded_length = 1 + 2 * Curve.Fe.encoded_length;

            p: Curve,

            /// Create a public key from a SEC-1 representation.
            pub fn fromSec1(sec1: []const u8) !PublicKey {
                return PublicKey{ .p = try Curve.fromSec1(sec1) };
            }

            /// Encode the public key using the compressed SEC-1 format.
            pub fn toCompressedSec1(pk: PublicKey) [compressed_sec1_encoded_length]u8 {
                return pk.p.toCompressedSec1();
            }

            /// Encoding the public key using the uncompressed SEC-1 format.
            pub fn toUncompressedSec1(pk: PublicKey) [uncompressed_sec1_encoded_length]u8 {
                return pk.p.toUncompressedSec1();
            }
        };

        pub const Pi = [ptLen + cLen + qLen]u8;

        /// An ECDSA key pair.
        pub const KeyPair = struct {
            /// Public part.
            public_key: PublicKey,
            /// Secret scalar.
            secret_key: SecretKey,

            /// Create a new random key pair. `crypto.random.bytes` must be supported for the target.
            pub fn generate() IdentityElementError!KeyPair {
                switch (Curve) {
                    crypto.ecc.P256 => {
                        // Elliptic Curve Key Pair Generation Primitive (3.2.1.)
                        // https://www.secg.org/sec1-v2.pdf
                        const d = Curve.scalar.random(.big);
                        return fromSecretKey(SecretKey{ .bytes = d.bytes });
                    },
                    else => @compileError("unsupported curve"),
                }
            }

            /// Return the public key corresponding to the secret key.
            pub fn fromSecretKey(secret_key: SecretKey) IdentityElementError!KeyPair {
                const public_key = try Curve.basePoint.mul(secret_key.bytes, .big);
                return KeyPair{ .secret_key = secret_key, .public_key = PublicKey{ .p = public_key } };
            }

            //pub fn prove(key_pair: KeyPair, alpha: []const u8, salt: ?[]const u8) !Pi {
            //    _ = salt;
            //    const encode_to_curve_salt = key_pair.public_key.pointToString();
            //    const H = try encodeToCurveTryAndIncrement(encode_to_curve_salt, alpha);
            //    const H_ = PublicKey{ .p = H };
            //    const h_string = H_.pointToString();
            //    const Gamma = H.mul(key_pair.secret_key, .big);
            //}
        };

        pub fn pointToString(p: Curve) [ptLen]u8 {
            return switch (Curve) {
                crypto.ecc.P256 => p.toCompressedSec1(),
                else => @compileError("unsupported curve"),
            };
        }

        pub fn stringToPoint(s: [ptLen]u8) !Curve {
            return switch (Curve) {
                crypto.ecc.P256 => try Curve.fromSec1(&s),
                else => @compileError("unsupported curve"),
            };
        }

        pub fn encodeToCurve(salt: []const u8, alpha: []const u8) !Curve {
            return switch (encode_to_curve_mode) {
                .TryAndIncrement => encodeToCurveTryAndIncrement(salt, alpha),
                .H2cSuite => @compileError("H2cSuite not yet implemented"),
            };
        }

        /// This function takes a public salt and a VRF input alpha an converts it to H,
        /// an EC point on G.
        pub fn encodeToCurveTryAndIncrement(salt: []const u8, alpha: []const u8) !Curve {
            var ctr: u8 = 0;
            const encode_to_curve_domain_separator_front = "\x01";
            const encode_to_curve_domain_separator_back = "\x00";
            // loop is expected to stop after roughly two iterations!
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
                switch (Curve) {
                    crypto.ecc.P256 => {
                        H[0] = 0x02;
                        h.final(H[1..]);
                        const pk = stringToPoint(H) catch continue;
                        return pk;
                    },
                    else => @compileError("unsupported curve"),
                }
            }

            return error.NoCurve;
        }

        pub fn nonceGenerationFromRfc6979(sk: SecretKey, h_string: []const u8) void {
            const h1: [Hash.digest_length]u8 = undefined;
            Hash.hash(h_string, &h1, .{});
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

            while (true) {}
        }
    };
}

test "ECVRF-P256-SHA256-TAI try_and_increment should succeed on ctr = 1" {
    const vrf = EcvrfP256Sha256Tai;
    const x = try vrf.SecretKey.fromBytes("\xc9\xaf\xa9\xd8\x45\xba\x75\x16\x6b\x5c\x21\x57\x67\xb1\xd6\x93\x4e\x50\xc3\xdb\x36\xe8\x9b\x12\x7b\x8a\x62\x2b\x12\x0f\x67\x21".*);
    const xy = try vrf.KeyPair.fromSecretKey(x);

    try std.testing.expectEqualSlices(
        u8,
        "\x03\x60\xfe\xd4\xba\x25\x5a\x9d\x31\xc9\x61\xeb\x74\xc6\x35\x6d\x68\xc0\x49\xb8\x92\x3b\x61\xfa\x6c\xe6\x69\x62\x2e\x60\xf2\x9f\xb6",
        vrf.pointToString(xy.public_key.p)[0..],
    );

    const alpha = "sample";

    const H = try vrf.encodeToCurveTryAndIncrement(&vrf.pointToString(xy.public_key.p), alpha);
    try std.testing.expectEqualSlices(
        u8,
        "\x02\x72\xa8\x77\x53\x2e\x9a\xc1\x93\xaf\xf4\x40\x12\x34\x26\x6f\x59\x90\x0a\x4a\x9e\x3f\xc3\xcf\xc6\xa4\xb7\xe4\x67\xa1\x5d\x06\xd4",
        vrf.pointToString(H)[0..],
    );

    const H2 = try vrf.encodeToCurve(&vrf.pointToString(xy.public_key.p), alpha);
    try std.testing.expectEqualSlices(
        u8,
        "\x02\x72\xa8\x77\x53\x2e\x9a\xc1\x93\xaf\xf4\x40\x12\x34\x26\x6f\x59\x90\x0a\x4a\x9e\x3f\xc3\xcf\xc6\xa4\xb7\xe4\x67\xa1\x5d\x06\xd4",
        vrf.pointToString(H2)[0..],
    );
}
