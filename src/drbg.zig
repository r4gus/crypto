//! A Deterministic Random Bit Generators (DRBG), also known as
//! Pseudo Random Number Generator (PRNG), uses some entropy
//! source as a seed and generates output bits on demand
//! that are indistinguishable from random.

pub const xdrbg = @import("drbg/xdrbg.zig");

test "drbg tests" {
    _ = xdrbg;
}
