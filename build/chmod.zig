//! Usage: chmod [file-path...]
//! Accepts a list of file paths as input and changes their permission bits to `0o755`.
//! POSIX only.

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var args = init.minimal.args.iterate();
    _ = args.skip();
    while (args.next()) |path| {
        const file = std.Io.Dir.cwd().openFile(
            io,
            path,
            .{ .mode = .read_write },
        ) catch |err|
            fatal("unable to open file '{s}': {t}", .{ path, err });
        defer file.close(io);
        file.setPermissions(io, @enumFromInt(0o755)) catch |err|
            fatal("unable to set permissions on file '{s}': {t}", .{ path, err });
    }
}

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(1);
}

const std = @import("std");
