const std = @import("std");

pub const vrf = @import("vrf.zig");
pub const drbg = @import("drbg.zig");

test "root tests" {
    _ = vrf;
    _ = drbg;
}
