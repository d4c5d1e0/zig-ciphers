pub const clefia = struct {
    pub const Clefia128 = @import("ciphers/clefia.zig").Clefia128;
    pub const Clefia192 = @import("ciphers/clefia.zig").Clefia192;
    pub const Clefia256 = @import("ciphers/clefia.zig").Clefia256;
};
