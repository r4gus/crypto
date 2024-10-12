//! [XDRBG](https://tosc.iacr.org/index.php/ToSC/article/view/11399) is a Deterministic
//! Random Bit Generator (DRBG) based on any XOF (eXtended Output Function).

const std = @import("std");
const crypto = std.crypto;

/// XDRBG using SHAKE128
pub const Xdrbg128 = Xdrbg(crypto.hash.sha3.Shake128, 32);

/// XDRBG using SHAKE256
pub const Xdrbg256 = Xdrbg(crypto.hash.sha3.Shake256, 64);

pub fn Xdrbg(comptime Hash: type, comptime keysize: usize) type {
    return struct {
        pub const max_chunk = Hash.block_length * 2 - keysize;

        pub fn init() State {
            return State{};
        }

        /// The XDRBG state
        pub const State = struct {
            status: ?Status = null,
            v: [keysize]u8 = .{0} ** keysize,

            fn isInitiallySeeded(state: *const State) bool {
                return state.status != null and state.status.? == .InitiallySeeded;
            }

            /// Seed the DRNG with `seed_string` and optionally `alpha`.
            ///
            /// To omit additional data, pass the empty string `""` to `alpha`.
            pub fn seed(state: *State, seed_string: []const u8, alpha: []const u8) void {
                const seeded = state.isInitiallySeeded();
                var h = Hash.init(.{});

                // During reseeding, insert V' into the XOF state. During the
                // initial seeding V' does not exist yet, i.e., it's not considered:
                if (seeded) {
                    h.update(state.v[0..]);
                } else {
                    state.status = .InitiallySeeded;
                }

                // Insert the seed into the xof
                h.update(seed_string);

                // Insert alpha into the XOF state together with its encoding.
                encode(&h, if (seeded) 85 else 0, alpha);

                h.final(state.v[0..]);
            }

            /// Generate `8 * out.len` random bits and write them to `out`.
            ///
            /// This function will fail with `error.NotSeeded` if the DRNG context state
            /// hasn't been seeded using `seed()` previously.
            ///
            /// To omit additional data, pass the empty string `""` to `alpha`.
            pub fn generate(state: *State, out: []u8, alpha: []const u8) error{NotSeeded}!void {
                var left: usize = out.len;
                var offset: usize = 0;

                if (!state.isInitiallySeeded())
                    return error.NotSeeded;

                while (left > 0) {
                    const todo = @min(left, max_chunk);

                    // Fast-key-erasure initialization of the XOF context.
                    var h = Hash.init(.{});
                    h.update(state.v[0..]);
                    encode(&h, 2 * 85, alpha);
                    h.squeeze(state.v[0..]);

                    h.final(out[offset .. offset + todo]);

                    offset += todo;
                    left -= todo;
                }
            }

            pub fn zero(state: *State) void {
                if (!state.isInitiallySeeded())
                    return;
                state.status = null;
                @memset(state.v[0..], 0);
            }

            fn encode(hash_ctx: *Hash, n: u8, alpha: []const u8) void {
                var e: [1]u8 = .{0};
                var alpha_len: usize = alpha.len;

                // Only consider up to 84 left-most bytes of alpha. According to
                // the XDRBG specification appendix B
                if (alpha.len > 84)
                    alpha_len = 84;

                // encode the length
                e[0] = n + @as(u8, @intCast(alpha_len));

                // insert alpha and e into the context
                hash_ctx.update(alpha[0..alpha_len]);
                hash_ctx.update(&e);
            }
        };

        pub fn keySize() usize {
            return keysize;
        }

        pub const Status = enum(u8) {
            InitiallySeeded,
        };
    };
}

test "Xdrbg256 test #1" {
    const seed = &.{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const exp1: []const u8 = &.{ 0x1a, 0xd2, 0xcb, 0x76, 0x3c, 0x71, 0x6d, 0xf0, 0x79, 0x2c, 0xc0, 0x69, 0x7d, 0x56, 0x6a, 0x65, 0xb8, 0x36, 0xbe, 0x7d, 0x09, 0x12, 0x7c, 0x65, 0x47, 0xfc, 0x30, 0x58, 0xaa, 0x24, 0x39, 0x52, 0x29, 0xea, 0xce, 0x43, 0xdf, 0x16, 0x2c, 0x4f, 0x1a, 0xed, 0xbd, 0x3f, 0xf5, 0x8e, 0xe6, 0x4d, 0x93, 0x07, 0x3d, 0x7f, 0x3d, 0xd2, 0x50, 0x3c, 0xae, 0x04, 0x4a, 0x87, 0x2c, 0x90, 0x30, 0xd4, 0x8e, 0xef, 0x5d, 0x53, 0x0f, 0xb2, 0xdb, 0xec, 0x16, 0x39, 0x5a, 0xb5, 0x9a, 0xdc, 0x9d, 0x01, 0x7e, 0xe2, 0xac, 0x7c, 0xe4, 0x3d, 0xfd, 0x93, 0xa6, 0x6c, 0xc1, 0x22, 0x26, 0x64, 0xa0, 0x43, 0x52, 0x51, 0xf9, 0xb5, 0xa4, 0x91, 0x54, 0x08, 0xf8, 0x8f, 0x16, 0x85, 0x54, 0xc0, 0x9d, 0xce, 0xc9, 0xd5, 0xd7, 0xa9, 0x51, 0xc0, 0x06, 0x0c, 0x04, 0x95, 0xcf, 0x7d, 0x27, 0x00, 0x7e, 0x48, 0x6d, 0x2e, 0xbc, 0xf8, 0xa3, 0x71, 0x3d, 0xb0, 0x2b, 0x75, 0x2a, 0x48, 0x1a, 0xd3, 0xed, 0xc9, 0xa3, 0x80, 0x88, 0x03, 0xc0, 0x27, 0x75, 0xcc, 0xf5, 0xda, 0x56, 0x8d, 0x83, 0x36, 0xe6, 0x90, 0x9c, 0xd5, 0x82, 0xfa, 0x70, 0xe9, 0xbf, 0x61, 0xec, 0x97, 0xcc, 0xdd, 0xdc, 0x4e, 0xe1, 0x64, 0x9f, 0x1e, 0xb3, 0xfa, 0x97, 0xa7, 0x02, 0x0a, 0x28, 0x01, 0x19, 0xd0, 0x45, 0xe9, 0x21, 0x74, 0x52, 0x1a, 0xac, 0x5f, 0x58, 0x7c, 0x02, 0x47, 0x45, 0x06, 0x17, 0x71, 0xc5, 0x2b, 0x0f, 0xa9, 0x7f, 0x9c, 0x15, 0x9c, 0xde, 0x00, 0x25, 0xf9, 0xa3, 0x1b, 0x44, 0xfe, 0x4f, 0xc6, 0xf8, 0xbf, 0x6c, 0x9f, 0x12, 0xc7, 0x67, 0xb9, 0x3f, 0xd8, 0x92, 0xcf, 0xbb, 0x9d, 0x2c, 0x7e, 0x6a, 0x62, 0x8b, 0xa7, 0xe5, 0xfa, 0xab, 0x40, 0xc2 };
    const exp83 = &.{ 0x39, 0x2b, 0x18, 0x96, 0x45, 0x81, 0x86, 0x84, 0xcf };
    const exp84 = &.{ 0xf0, 0x85, 0xd6, 0xc8, 0xd1, 0x76, 0xd7, 0x12, 0x39 };
    var act1: [247]u8 = .{0} ** 247;
    var act2: [9]u8 = .{0} ** 9;

    var drbg = Xdrbg256.init();
    drbg.seed(seed, "");
    try drbg.generate(&act1, "");
    try std.testing.expectEqualSlices(u8, exp1, &act1);
    drbg.zero();

    // Verify the generate operation with additional information of 83 bytes.
    drbg.seed(seed, "");
    try drbg.generate(&act2, exp1[0..83]);
    try std.testing.expectEqualSlices(u8, exp83, &act2);
    drbg.zero();

    // Verify the generate operation with additional information of 84 bytes.
    drbg.seed(seed, "");
    try drbg.generate(&act2, exp1[0..84]);
    try std.testing.expectEqualSlices(u8, exp84, &act2);
    drbg.zero();

    // Verify the generate operation with additional information of 85
    // bytes to be identical to 84 bytes due to the truncation of the
    // additional data.
    drbg.seed(seed, "");
    try drbg.generate(&act2, exp1);
    try std.testing.expectEqualSlices(u8, exp84, &act2);
    drbg.zero();
}
