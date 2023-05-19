const std = @import("std");
const math = std.math;

pub const Clefia128 = Clefia(.{
    .key_size = 16,
    .rounds = 18,
    .round_keys = 36,
});

pub const Clefia192 = Clefia(.{
    .key_size = 24,
    .rounds = 22,
    .round_keys = 44,
});

pub const Clefia256 = Clefia(.{
    .key_size = 32,
    .rounds = 26,
    .round_keys = 52,
});

const Params = struct {
    key_size: usize,
    rounds: usize,
    round_keys: usize,
};

fn Clefia(comptime p: Params) type {
    return struct {
        pub const block_size: usize = 16;
        wk: [p.key_size / 4]u32,
        rk: [p.round_keys]u32,

        const Self = @This();

        pub fn init(key: [p.key_size]u8) Self {
            var wk: [p.key_size / 4]u32 = undefined;
            var rk: [p.round_keys]u32 = undefined;
            var k: [p.key_size / 4]u32 = undefined;
            var i: usize = 0;

            while (i < p.key_size / 4) : (i += 1) {
                var idx: usize = i * 4;
                k[i] = std.mem.readIntBig(u32, key[idx..][0..4]);
            }

            switch (p.key_size) {
                16 => key_schedule_128(&k, &wk, &rk),
                24 => key_schedule_192(&k, &wk, &rk),
                32 => key_schedule_256(&k, &wk, &rk),
                else => unreachable,
            }

            return Self{
                .wk = wk,
                .rk = rk,
            };
        }

        pub fn encrypt(self: Self, plaintext: *const [block_size]u8, dst: *[block_size]u8) void {
            var en: [4]u32 = undefined;

            en[0] = std.mem.readIntBig(u32, plaintext[0..4]);
            en[1] = std.mem.readIntBig(u32, plaintext[4..8]);
            en[2] = std.mem.readIntBig(u32, plaintext[8..12]);
            en[3] = std.mem.readIntBig(u32, plaintext[12..16]);

            var t: [4]u32 = undefined;
            var c: [4]u32 = undefined;

            t[0] = en[0];
            t[1] = en[1] ^ self.wk[0];
            t[2] = en[2];
            t[3] = en[3] ^ self.wk[1];

            gfn4(p.rounds, &self.rk, &t, &t);

            c[0] = t[0];
            c[1] = t[1] ^ self.wk[2];
            c[2] = t[2];
            c[3] = t[3] ^ self.wk[3];

            std.mem.writeIntBig(u32, dst[0..4], c[0]);
            std.mem.writeIntBig(u32, dst[4..8], c[1]);
            std.mem.writeIntBig(u32, dst[8..12], c[2]);
            std.mem.writeIntBig(u32, dst[12..16], c[3]);
        }
        pub fn decrypt(self: Self, ciphertext: *const [block_size]u8, dst: *[block_size]u8) void {
            var en: [4]u32 = undefined;

            en[0] = std.mem.readIntBig(u32, ciphertext[0..4]);
            en[1] = std.mem.readIntBig(u32, ciphertext[4..8]);
            en[2] = std.mem.readIntBig(u32, ciphertext[8..12]);
            en[3] = std.mem.readIntBig(u32, ciphertext[12..16]);

            var t: [4]u32 = undefined;
            var c: [4]u32 = undefined;

            t[0] = en[0];
            t[1] = en[1] ^ self.wk[2];
            t[2] = en[2];
            t[3] = en[3] ^ self.wk[3];

            gfn_inv(p.rounds, &self.rk, &t, &t);

            c[0] = t[0];
            c[1] = t[1] ^ self.wk[0];
            c[2] = t[2];
            c[3] = t[3] ^ self.wk[1];

            std.mem.writeIntBig(u32, dst[0..4], c[0]);
            std.mem.writeIntBig(u32, dst[4..8], c[1]);
            std.mem.writeIntBig(u32, dst[8..12], c[2]);
            std.mem.writeIntBig(u32, dst[12..16], c[3]);
        }
    };
}

const s0 = [256]u8{ 0x57, 0x49, 0xd1, 0xc6, 0x2f, 0x33, 0x74, 0xfb, 0x95, 0x6d, 0x82, 0xea, 0x0e, 0xb0, 0xa8, 0x1c, 0x28, 0xd0, 0x4b, 0x92, 0x5c, 0xee, 0x85, 0xb1, 0xc4, 0x0a, 0x76, 0x3d, 0x63, 0xf9, 0x17, 0xaf, 0xbf, 0xa1, 0x19, 0x65, 0xf7, 0x7a, 0x32, 0x20, 0x06, 0xce, 0xe4, 0x83, 0x9d, 0x5b, 0x4c, 0xd8, 0x42, 0x5d, 0x2e, 0xe8, 0xd4, 0x9b, 0x0f, 0x13, 0x3c, 0x89, 0x67, 0xc0, 0x71, 0xaa, 0xb6, 0xf5, 0xa4, 0xbe, 0xfd, 0x8c, 0x12, 0x00, 0x97, 0xda, 0x78, 0xe1, 0xcf, 0x6b, 0x39, 0x43, 0x55, 0x26, 0x30, 0x98, 0xcc, 0xdd, 0xeb, 0x54, 0xb3, 0x8f, 0x4e, 0x16, 0xfa, 0x22, 0xa5, 0x77, 0x09, 0x61, 0xd6, 0x2a, 0x53, 0x37, 0x45, 0xc1, 0x6c, 0xae, 0xef, 0x70, 0x08, 0x99, 0x8b, 0x1d, 0xf2, 0xb4, 0xe9, 0xc7, 0x9f, 0x4a, 0x31, 0x25, 0xfe, 0x7c, 0xd3, 0xa2, 0xbd, 0x56, 0x14, 0x88, 0x60, 0x0b, 0xcd, 0xe2, 0x34, 0x50, 0x9e, 0xdc, 0x11, 0x05, 0x2b, 0xb7, 0xa9, 0x48, 0xff, 0x66, 0x8a, 0x73, 0x03, 0x75, 0x86, 0xf1, 0x6a, 0xa7, 0x40, 0xc2, 0xb9, 0x2c, 0xdb, 0x1f, 0x58, 0x94, 0x3e, 0xed, 0xfc, 0x1b, 0xa0, 0x04, 0xb8, 0x8d, 0xe6, 0x59, 0x62, 0x93, 0x35, 0x7e, 0xca, 0x21, 0xdf, 0x47, 0x15, 0xf3, 0xba, 0x7f, 0xa6, 0x69, 0xc8, 0x4d, 0x87, 0x3b, 0x9c, 0x01, 0xe0, 0xde, 0x24, 0x52, 0x7b, 0x0c, 0x68, 0x1e, 0x80, 0xb2, 0x5a, 0xe7, 0xad, 0xd5, 0x23, 0xf4, 0x46, 0x3f, 0x91, 0xc9, 0x6e, 0x84, 0x72, 0xbb, 0x0d, 0x18, 0xd9, 0x96, 0xf0, 0x5f, 0x41, 0xac, 0x27, 0xc5, 0xe3, 0x3a, 0x81, 0x6f, 0x07, 0xa3, 0x79, 0xf6, 0x2d, 0x38, 0x1a, 0x44, 0x5e, 0xb5, 0xd2, 0xec, 0xcb, 0x90, 0x9a, 0x36, 0xe5, 0x29, 0xc3, 0x4f, 0xab, 0x64, 0x51, 0xf8, 0x10, 0xd7, 0xbc, 0x02, 0x7d, 0x8e };
const s1 = [256]u8{ 0x6c, 0xda, 0xc3, 0xe9, 0x4e, 0x9d, 0x0a, 0x3d, 0xb8, 0x36, 0xb4, 0x38, 0x13, 0x34, 0x0c, 0xd9, 0xbf, 0x74, 0x94, 0x8f, 0xb7, 0x9c, 0xe5, 0xdc, 0x9e, 0x07, 0x49, 0x4f, 0x98, 0x2c, 0xb0, 0x93, 0x12, 0xeb, 0xcd, 0xb3, 0x92, 0xe7, 0x41, 0x60, 0xe3, 0x21, 0x27, 0x3b, 0xe6, 0x19, 0xd2, 0x0e, 0x91, 0x11, 0xc7, 0x3f, 0x2a, 0x8e, 0xa1, 0xbc, 0x2b, 0xc8, 0xc5, 0x0f, 0x5b, 0xf3, 0x87, 0x8b, 0xfb, 0xf5, 0xde, 0x20, 0xc6, 0xa7, 0x84, 0xce, 0xd8, 0x65, 0x51, 0xc9, 0xa4, 0xef, 0x43, 0x53, 0x25, 0x5d, 0x9b, 0x31, 0xe8, 0x3e, 0x0d, 0xd7, 0x80, 0xff, 0x69, 0x8a, 0xba, 0x0b, 0x73, 0x5c, 0x6e, 0x54, 0x15, 0x62, 0xf6, 0x35, 0x30, 0x52, 0xa3, 0x16, 0xd3, 0x28, 0x32, 0xfa, 0xaa, 0x5e, 0xcf, 0xea, 0xed, 0x78, 0x33, 0x58, 0x09, 0x7b, 0x63, 0xc0, 0xc1, 0x46, 0x1e, 0xdf, 0xa9, 0x99, 0x55, 0x04, 0xc4, 0x86, 0x39, 0x77, 0x82, 0xec, 0x40, 0x18, 0x90, 0x97, 0x59, 0xdd, 0x83, 0x1f, 0x9a, 0x37, 0x06, 0x24, 0x64, 0x7c, 0xa5, 0x56, 0x48, 0x08, 0x85, 0xd0, 0x61, 0x26, 0xca, 0x6f, 0x7e, 0x6a, 0xb6, 0x71, 0xa0, 0x70, 0x05, 0xd1, 0x45, 0x8c, 0x23, 0x1c, 0xf0, 0xee, 0x89, 0xad, 0x7a, 0x4b, 0xc2, 0x2f, 0xdb, 0x5a, 0x4d, 0x76, 0x67, 0x17, 0x2d, 0xf4, 0xcb, 0xb1, 0x4a, 0xa8, 0xb5, 0x22, 0x47, 0x3a, 0xd5, 0x10, 0x4c, 0x72, 0xcc, 0x00, 0xf9, 0xe0, 0xfd, 0xe2, 0xfe, 0xae, 0xf8, 0x5f, 0xab, 0xf1, 0x1b, 0x42, 0x81, 0xd6, 0xbe, 0x44, 0x29, 0xa6, 0x57, 0xb9, 0xaf, 0xf2, 0xd4, 0x75, 0x66, 0xbb, 0x68, 0x9f, 0x50, 0x02, 0x01, 0x3c, 0x7f, 0x8d, 0x1a, 0x88, 0xbd, 0xac, 0xf7, 0xe4, 0x79, 0x96, 0xa2, 0xfc, 0x6d, 0xb2, 0x6b, 0x03, 0xe1, 0x2e, 0x7d, 0x14, 0x95, 0x1d };

const con128: [60]u32 = [60]u32{ 0xf56b7aeb, 0x994a8a42, 0x96a4bd75, 0xfa854521, 0x735b768a, 0x1f7abac4, 0xd5bc3b45, 0xb99d5d62, 0x52d73592, 0x3ef636e5, 0xc57a1ac9, 0xa95b9b72, 0x5ab42554, 0x369555ed, 0x1553ba9a, 0x7972b2a2, 0xe6b85d4d, 0x8a995951, 0x4b550696, 0x2774b4fc, 0xc9bb034b, 0xa59a5a7e, 0x88cc81a5, 0xe4ed2d3f, 0x7c6f68e2, 0x104e8ecb, 0xd2263471, 0xbe07c765, 0x511a3208, 0x3d3bfbe6, 0x1084b134, 0x7ca565a7, 0x304bf0aa, 0x5c6aaa87, 0xf4347855, 0x9815d543, 0x4213141a, 0x2e32f2f5, 0xcd180a0d, 0xa139f97a, 0x5e852d36, 0x32a464e9, 0xc353169b, 0xaf72b274, 0x8db88b4d, 0xe199593a, 0x7ed56d96, 0x12f434c9, 0xd37b36cb, 0xbf5a9a64, 0x85ac9b65, 0xe98d4d32, 0x7adf6582, 0x16fe3ecd, 0xd17e32c1, 0xbd5f9f66, 0x50b63150, 0x3c9757e7, 0x1052b098, 0x7c73b3a7 };
const con192: [84]u32 = [84]u32{ 0xc6d61d91, 0xaaf73771, 0x5b6226f8, 0x374383ec, 0x15b8bb4c, 0x799959a2, 0x32d5f596, 0x5ef43485, 0xf57b7acb, 0x995a9a42, 0x96acbd65, 0xfa8d4d21, 0x735f7682, 0x1f7ebec4, 0xd5be3b41, 0xb99f5f62, 0x52d63590, 0x3ef737e5, 0x1162b2f8, 0x7d4383a6, 0x30b8f14c, 0x5c995987, 0x2055d096, 0x4c74b497, 0xfc3b684b, 0x901ada4b, 0x920cb425, 0xfe2ded25, 0x710f7222, 0x1d2eeec6, 0xd4963911, 0xb8b77763, 0x524234b8, 0x3e63a3e5, 0x1128b26c, 0x7d09c9a6, 0x309df106, 0x5cbc7c87, 0xf45f7883, 0x987ebe43, 0x963ebc41, 0xfa1fdf21, 0x73167610, 0x1f37f7c4, 0x01829338, 0x6da363b6, 0x38c8e1ac, 0x54e9298f, 0x246dd8e6, 0x484c8c93, 0xfe276c73, 0x9206c649, 0x9302b639, 0xff23e324, 0x7188732c, 0x1da969c6, 0x00cd91a6, 0x6cec2cb7, 0xec7748d3, 0x8056965b, 0x9a2aa469, 0xf60bcb2d, 0x751c7a04, 0x193dfdc2, 0x02879532, 0x6ea666b5, 0xed524a99, 0x8173b35a, 0x4ea00d7c, 0x228141f9, 0x1f59ae8e, 0x7378b8a8, 0xe3bd5747, 0x8f9c5c54, 0x9dcfaba3, 0xf1ee2e2a, 0xa2f6d5d1, 0xced71715, 0x697242d8, 0x055393de, 0x0cb0895c, 0x609151bb, 0x3e51ec9e, 0x5270b089 };
const con256: [92]u32 = [92]u32{ 0x0221947e, 0x6e00c0b5, 0xed014a3f, 0x8120e05a, 0x9a91a51f, 0xf6b0702d, 0xa159d28f, 0xcd78b816, 0xbcbde947, 0xd09c5c0b, 0xb24ff4a3, 0xde6eae05, 0xb536fa51, 0xd917d702, 0x62925518, 0x0eb373d5, 0x094082bc, 0x6561a1be, 0x3ca9e96e, 0x5088488b, 0xf24574b7, 0x9e64a445, 0x9533ba5b, 0xf912d222, 0xa688dd2d, 0xcaa96911, 0x6b4d46a6, 0x076cacdc, 0xd9b72353, 0xb596566e, 0x80ca91a9, 0xeceb2b37, 0x786c60e4, 0x144d8dcf, 0x043f9842, 0x681edeb3, 0xee0e4c21, 0x822fef59, 0x4f0e0e20, 0x232feff8, 0x1f8eaf20, 0x73af6fa8, 0x37ceffa0, 0x5bef2f80, 0x23eed7e0, 0x4fcf0f94, 0x29fec3c0, 0x45df1f9e, 0x2cf6c9d0, 0x40d7179b, 0x2e72ccd8, 0x42539399, 0x2f30ce5c, 0x4311d198, 0x2f91cf1e, 0x43b07098, 0xfbd9678f, 0x97f8384c, 0x91fdb3c7, 0xfddc1c26, 0xa4efd9e3, 0xc8ce0e13, 0xbe66ecf1, 0xd2478709, 0x673a5e48, 0x0b1bdbd0, 0x0b948714, 0x67b575bc, 0x3dc3ebba, 0x51e2228a, 0xf2f075dd, 0x9ed11145, 0x417112de, 0x2d5090f6, 0xcca9096f, 0xa088487b, 0x8a4584b7, 0xe664a43d, 0xa933c25b, 0xc512d21e, 0xb888e12d, 0xd4a9690f, 0x644d58a6, 0x086cacd3, 0xde372c53, 0xb216d669, 0x830a9629, 0xef2beb34, 0x798c6324, 0x15ad6dce, 0x04cf99a2, 0x68ee2eb3 };

// x^8 + x^4 + x^3 + x^2 + 1
// https://jhafranco.com/2012/02/03/clefia-implementation-in-python-improved-version/
fn mult(comptime a: u8, b: u8) u8 {
    var x: u16 = @as(u16, b);
    var z: u16 = @as(u16, a);
    var p: u16 = 0;
    while (x != 0) {
        if ((x & 0b1) != 0) {
            p ^= z;
        }

        z <<= 1;
        if ((z & 0x100) != 0) {
            z ^= 0b11101;
        }
        x >>= 1;
    }
    return @intCast(u8, p & 0xff);
}

fn x2(x: u8) u8 {
    return mult(2, x);
}
fn x4(x: u8) u8 {
    return mult(4, x);
}
fn x6(x: u8) u8 {
    return mult(6, x);
}
fn x8(x: u8) u8 {
    return mult(8, x);
}
fn x10(x: u8) u8 {
    return mult(10, x);
}

fn transformMatrix0(t: []u8, y: []u8) void {
    y[0] = t[0] ^ x2(t[1]) ^ x4(t[2]) ^ x6(t[3]);
    y[1] = x2(t[0]) ^ t[1] ^ x6(t[2]) ^ x4(t[3]);
    y[2] = x4(t[0]) ^ x6(t[1]) ^ t[2] ^ x2(t[3]);
    y[3] = x6(t[0]) ^ x4(t[1]) ^ x2(t[2]) ^ t[3];
}

fn transformMatrix1(t: []u8, y: []u8) void {
    y[0] = t[0] ^ x8(t[1]) ^ x2(t[2]) ^ x10(t[3]);
    y[1] = x8(t[0]) ^ t[1] ^ x10(t[2]) ^ x2(t[3]);
    y[2] = x2(t[0]) ^ x10(t[1]) ^ t[2] ^ x8(t[3]);
    y[3] = x10(t[0]) ^ x2(t[1]) ^ x8(t[2]) ^ t[3];
}

fn f0(rk: u32, x: u32) u32 {
    var t: [4]u8 = undefined;
    var y: [4]u8 = undefined;

    std.mem.writeIntBig(u32, &t, rk ^ x);
    //   T0 <- S1(T0),
    //   T1 <- S0(T1),
    //   T2 <- S1(T2),
    //   T3 <- S0(T3)
    t[0] = s0[t[0]];
    t[1] = s1[t[1]];
    t[2] = s0[t[2]];
    t[3] = s1[t[3]];
    // y = M0 trans((T0, T1, T2, T3)):
    transformMatrix0(&t, &y);

    return std.mem.readIntBig(u32, y[0..4]);
}

fn f1(rk: u32, x: u32) u32 {
    var t: [4]u8 = undefined;
    var y: [4]u8 = undefined;

    std.mem.writeIntBig(u32, &t, rk ^ x);
    //   T0 <- S1(T0),
    //   T1 <- S0(T1),
    //   T2 <- S1(T2),
    //   T3 <- S0(T3)
    t[0] = s1[t[0]];
    t[1] = s0[t[1]];
    t[2] = s1[t[2]];
    t[3] = s0[t[3]];
    // y <- M1 trans((T0, T1, T2, T3))
    transformMatrix1(&t, &y);

    return std.mem.readIntBig(u32, y[0..4]);
}

fn gfn4(
    comptime r: usize,
    rk: *const [r * 2]u32,
    x: []u32,
    y: []u32,
) void {
    var t: [4]u32 = undefined;
    var tmp: u32 = 0;

    std.mem.copy(u32, t[0..], x[0..]);

    for (0..r) |i| {
        // 2.1
        t[1] ^= f0(rk[2 * i], t[0]);
        t[3] ^= f1(rk[2 * i + 1], t[2]);
        //2.2
        tmp = t[0];

        t[0] = t[1];
        t[1] = t[2];
        t[2] = t[3];
        t[3] = tmp;
    }

    y[0] = t[3];
    y[1] = t[0];
    y[2] = t[1];
    y[3] = t[2];
}

fn gfn_inv(
    comptime r: usize,
    rk: *const [r * 2]u32,
    x: []u32,
    y: []u32,
) void {
    var t: [4]u32 = undefined;
    var tmp: u32 = 0;
    var tmp1: u32 = 0;
    var tmp2: u32 = 0;
    var tmp3: u32 = 0;

    std.mem.copy(u32, t[0..], x[0..]);

    for (0..r) |i| {
        // 2.1
        t[1] ^= f0(rk[2 * (r - i) - 2], t[0]);
        t[3] ^= f1(rk[2 * (r - i) - 1], t[2]);
        //2.2
        tmp = t[0];
        tmp1 = t[1];
        tmp2 = t[2];
        tmp3 = t[3];

        t[0] = tmp3;
        t[1] = tmp;
        t[2] = tmp1;
        t[3] = tmp2;
    }

    y[0] = t[1];
    y[1] = t[2];
    y[2] = t[3];
    y[3] = t[0];
}

fn gfn8(
    comptime r: usize,
    rk: *const [r * 4]u32,
    x: []u32,
    y: []u32,
) void {
    var t: [8]u32 = undefined;
    var tmp: u32 = 0;

    std.mem.copy(u32, t[0..], x[0..]);

    for (0..r) |i| {
        // 2.1
        t[1] ^= f0(rk[4 * i], t[0]);
        t[3] ^= f1(rk[4 * i + 1], t[2]);
        t[5] ^= f0(rk[4 * i + 2], t[4]);
        t[7] ^= f1(rk[4 * i + 3], t[6]);
        //2.2
        tmp = t[0];

        t[0] = t[1];
        t[1] = t[2];
        t[2] = t[3];
        t[3] = t[4];
        t[4] = t[5];
        t[5] = t[6];
        t[6] = t[7];
        t[7] = tmp;
    }

    y[0] = t[7];
    y[1] = t[0];
    y[2] = t[1];
    y[3] = t[2];
    y[4] = t[3];
    y[5] = t[4];
    y[6] = t[5];
    y[7] = t[6];
}

fn doubleSwap(x: []u32, y: []u32) void {
    y[0] = (math.shl(u32, x[0], 7) & 0xffffff80) | math.shr(u32, x[1], 25);
    y[1] = (math.shl(u32, x[1], 7) & 0xffffff80) | (x[3] & 0x7f);
    y[2] = (x[0] & 0xfe000000) | math.shr(u32, x[2], 7);
    y[3] = (math.shl(u32, x[2], 25) & 0xfe000000) | math.shr(u32, x[3], 7);
}

fn sigma(b: []u32) void {
    var t: [4]u32 = undefined;
    doubleSwap(b, &t);

    std.mem.copy(u32, b[0..], t[0..]);
}

fn key_schedule_128(k: []u32, wk: []u32, rk: []u32) void {
    var l: [4]u32 = undefined;
    var t: [4]u32 = undefined;

    //  Step 1. L <- GFN_{4,12}(CON_128[0], ..., CON_128[23], K0, ..., K3)
    gfn4(12, con128[0..24], k, &l);

    // Step 2. WK0 | WK1 | WK2 | WK3 <- K
    std.mem.copy(u32, wk[0..], k[0..]);

    for (0..9) |i| {
        t[0] = l[0] ^ con128[24 + 4 * i];
        t[1] = l[1] ^ con128[24 + 4 * i + 1];
        t[2] = l[2] ^ con128[24 + 4 * i + 2];
        t[3] = l[3] ^ con128[24 + 4 * i + 3];

        sigma(&l);

        if ((i % 2) != 0) {
            t[0] ^= k[0];
            t[1] ^= k[1];
            t[2] ^= k[2];
            t[3] ^= k[3];
        }

        rk[4 * i] = t[0];
        rk[4 * i + 1] = t[1];
        rk[4 * i + 2] = t[2];
        rk[4 * i + 3] = t[3];
    }
}

fn key_schedule_192(k: []u32, wk: []u32, rk: []u32) void {
    var kl: [4]u32 = undefined;
    var kr: [4]u32 = undefined;
    var ll: [4]u32 = undefined;
    var lr: [4]u32 = undefined;
    var t: [4]u32 = undefined;
    var y: [8]u32 = undefined;

    // Step 2
    std.mem.copy(u32, kl[0..], k[0..4]);

    kr[0] = k[4];
    kr[1] = k[5];
    kr[2] = k[0] ^ 0xffffffff;
    kr[3] = k[1] ^ 0xffffffff;

    var c: [8]u32 = undefined;
    std.mem.copy(u32, c[0..4], kl[0..]);
    std.mem.copy(u32, c[4..], kr[0..]);

    gfn8(10, con192[0..40], &c, &y);

    std.mem.copy(u32, ll[0..], y[0..4]);
    std.mem.copy(u32, lr[0..], y[4..]);

    // std.debug.print("ll: {x}\n", .{ll});
    // std.debug.print("lr: {x}\n", .{lr});

    // WK0 | WK1 | WK2 | WK3 <- KL XOR KR
    wk[0] = kl[0] ^ kr[0];
    wk[1] = kl[1] ^ kr[1];
    wk[2] = kl[2] ^ kr[2];
    wk[3] = kl[3] ^ kr[3];

    var i: usize = 0;
    while (i <= 10) : (i += 1) {
        if ((i % 4) == 0 or (i % 4) == 1) {
            t[0] = ll[0] ^ con192[40 + 4 * i];
            t[1] = ll[1] ^ con192[40 + 4 * i + 1];
            t[2] = ll[2] ^ con192[40 + 4 * i + 2];
            t[3] = ll[3] ^ con192[40 + 4 * i + 3];

            // LL <- Sigma(LL)
            sigma(&ll);
            // T <- T XOR KR
            if ((i % 2) != 0) {
                t[0] ^= kr[0];
                t[1] ^= kr[1];
                t[2] ^= kr[2];
                t[3] ^= kr[3];
            }
        } else {
            t[0] = lr[0] ^ con192[40 + 4 * i];
            t[1] = lr[1] ^ con192[40 + 4 * i + 1];
            t[2] = lr[2] ^ con192[40 + 4 * i + 2];
            t[3] = lr[3] ^ con192[40 + 4 * i + 3];

            // LR <- Sigma(LR)
            sigma(&lr);
            // T <- T XOR KL
            if ((i % 2) != 0) {
                t[0] ^= kl[0];
                t[1] ^= kl[1];
                t[2] ^= kl[2];
                t[3] ^= kl[3];
            }
        }

        rk[4 * i] = t[0];
        rk[4 * i + 1] = t[1];
        rk[4 * i + 2] = t[2];
        rk[4 * i + 3] = t[3];
    }
}

fn key_schedule_256(k: []u32, wk: []u32, rk: []u32) void {
    var kl: [4]u32 = undefined;
    var kr: [4]u32 = undefined;
    var ll: [4]u32 = undefined;
    var lr: [4]u32 = undefined;
    var t: [4]u32 = undefined;
    var y: [8]u32 = undefined;

    // Step 2
    std.mem.copy(u32, kl[0..], k[0..4]);

    kr[0] = k[4];
    kr[1] = k[5];
    kr[2] = k[6];
    kr[3] = k[7];

    var c: [8]u32 = undefined;
    std.mem.copy(u32, c[0..4], kl[0..]);
    std.mem.copy(u32, c[4..], kr[0..]);

    gfn8(10, con256[0..40], &c, &y);

    std.mem.copy(u32, ll[0..], y[0..4]);
    std.mem.copy(u32, lr[0..], y[4..]);

    // std.debug.print("ll: {x}\n", .{ll});
    // std.debug.print("lr: {x}\n", .{lr});

    // WK0 | WK1 | WK2 | WK3 <- KL XOR KR
    wk[0] = kl[0] ^ kr[0];
    wk[1] = kl[1] ^ kr[1];
    wk[2] = kl[2] ^ kr[2];
    wk[3] = kl[3] ^ kr[3];

    var i: usize = 0;
    while (i <= 12) : (i += 1) {
        if ((i % 4) == 0 or (i % 4) == 1) {
            t[0] = ll[0] ^ con256[40 + 4 * i];
            t[1] = ll[1] ^ con256[40 + 4 * i + 1];
            t[2] = ll[2] ^ con256[40 + 4 * i + 2];
            t[3] = ll[3] ^ con256[40 + 4 * i + 3];

            // LL <- Sigma(LL)
            sigma(&ll);
            // T <- T XOR KR
            if ((i % 2) != 0) {
                t[0] ^= kr[0];
                t[1] ^= kr[1];
                t[2] ^= kr[2];
                t[3] ^= kr[3];
            }
        } else {
            t[0] = lr[0] ^ con256[40 + 4 * i];
            t[1] = lr[1] ^ con256[40 + 4 * i + 1];
            t[2] = lr[2] ^ con256[40 + 4 * i + 2];
            t[3] = lr[3] ^ con256[40 + 4 * i + 3];

            // LR <- Sigma(LR)
            sigma(&lr);
            // T <- T XOR KL
            if ((i % 2) != 0) {
                t[0] ^= kl[0];
                t[1] ^= kl[1];
                t[2] ^= kl[2];
                t[3] ^= kl[3];
            }
        }

        rk[4 * i] = t[0];
        rk[4 * i + 1] = t[1];
        rk[4 * i + 2] = t[2];
        rk[4 * i + 3] = t[3];
    }
}

test "clefia 256" {
    const key = [_]u8{
        0xff,
        0xee,
        0xdd,
        0xcc,
        0xbb,
        0xaa,
        0x99,
        0x88,
        0x77,
        0x66,
        0x55,
        0x44,
        0x33,
        0x22,
        0x11,
        0x00,
        0xf0,
        0xe0,
        0xd0,
        0xc0,
        0xb0,
        0xa0,
        0x90,
        0x80,
        0x70,
        0x60,
        0x50,
        0x40,
        0x30,
        0x20,
        0x10,
        0x00,
    };
    const plaintext = [_]u8{
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0a,
        0x0b,
        0x0c,
        0x0d,
        0x0e,
        0x0f,
    };
    const expected_ct = [_]u8{ 0xa1, 0x39, 0x78, 0x14, 0x28, 0x9d, 0xe8, 0x0c, 0x10, 0xda, 0x46, 0xd1, 0xfa, 0x48, 0xb3, 0x8a };
    var ciphertext: [16]u8 = undefined;
    var plain_copy: [16]u8 = undefined;
    const cipher = Clefia256.init(key);
    cipher.encrypt(plaintext[0..], ciphertext[0..]);

    try std.testing.expectEqualSlices(u8, &expected_ct, &ciphertext);

    cipher.decrypt(ciphertext[0..], plain_copy[0..]);

    try std.testing.expectEqualSlices(u8, &plaintext, &plain_copy);
}

test "clefia 192" {
    const key = [_]u8{ 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80 };
    const plaintext = [_]u8{
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0a,
        0x0b,
        0x0c,
        0x0d,
        0x0e,
        0x0f,
    };
    const expected_ct = [_]u8{ 0xe2, 0x48, 0x2f, 0x64, 0x9f, 0x02, 0x8d, 0xc4, 0x80, 0xdd, 0xa1, 0x84, 0xfd, 0xe1, 0x81, 0xad };
    var ciphertext: [16]u8 = undefined;
    var plain_copy: [16]u8 = undefined;
    const cipher = Clefia192.init(key);
    cipher.encrypt(plaintext[0..], ciphertext[0..]);

    try std.testing.expectEqualSlices(u8, &expected_ct, &ciphertext);

    cipher.decrypt(ciphertext[0..], plain_copy[0..]);

    try std.testing.expectEqualSlices(u8, &plaintext, &plain_copy);
}

test "clefia 128" {
    const key = [_]u8{ 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };
    const plaintext = [_]u8{
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0a,
        0x0b,
        0x0c,
        0x0d,
        0x0e,
        0x0f,
    };

    const expected_ct = [_]u8{ 0xde, 0x2b, 0xf2, 0xfd, 0x9b, 0x74, 0xaa, 0xcd, 0xf1, 0x29, 0x85, 0x55, 0x45, 0x94, 0x94, 0xfd };
    var ciphertext: [16]u8 = undefined;
    var plain_copy: [16]u8 = undefined;
    const cipher = Clefia128.init(key);

    cipher.encrypt(plaintext[0..], ciphertext[0..]);

    try std.testing.expectEqualSlices(u8, &expected_ct, &ciphertext);

    cipher.decrypt(ciphertext[0..], plain_copy[0..]);

    try std.testing.expectEqualSlices(u8, &plaintext, &plain_copy);
}
