const std = @import("std");

pub fn addModule(obj: *std.build.LibExeObjStep) void {
    obj.addAnonymousModule("zig-ciphers", .{
        .source_file = .{
            .path = comptime thisDir() ++ "/src/ciphers.zig",
        },
    });
}

fn thisDir() []const u8 {
    return std.fs.path.dirname(@src().file) orelse ".";
}
