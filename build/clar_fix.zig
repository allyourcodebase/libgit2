//! Usage: clar_fix <src-file> <fixtures-dir>
//! Replaces *reads* of the CLAR_FIXTURE_PATH macro definition in `src-file` with
//! the absolute path of `fixtures-dir`. `#ifdef`s are not affected.

const std = @import("std");

const fixture_var_name = "CLAR_FIXTURE_PATH";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arena = init.arena.allocator();

    var args = try init.minimal.args.iterateAllocator(arena);
    _ = args.skip();

    const clar_fixture_h = args.next() orelse fatal("expected path to 'clar/fixtures.h' file", .{});
    const fixture_path: []const u8 = blk: {
        const path_arg = args.next() orelse fatal("expected path to test resources directory", .{});

        var cleaned_path: std.ArrayList(u8) = try .initCapacity(arena, std.fs.max_path_bytes + 2);
        cleaned_path.appendAssumeCapacity('"'); // add string quotes
        const rec_dir = try std.Io.Dir.cwd().openDir(io, path_arg, .{});
        defer rec_dir.close(io);

        const abs_path_len = try rec_dir.realPath(io, cleaned_path.unusedCapacitySlice());
        cleaned_path.items.len += abs_path_len;
        cleaned_path.appendAssumeCapacity('"');

        // clar expects the fixture path to only have posix seperators or else some tests will break
        for (cleaned_path.items) |*c| {
            if (c.* == '\\') c.* = '/';
        }
        break :blk cleaned_path.items;
    };

    const file = try std.Io.Dir.cwd().openFile(
        io,
        clar_fixture_h,
        .{ .mode = .read_write },
    );
    defer file.close(io);

    var buf: [1024]u8 = undefined;
    var src: std.ArrayList(u8) = src: {
        var file_reader = file.reader(io, &buf);

        const file_size = try file_reader.getSize();
        const to_add = fixture_path.len -| fixture_var_name.len;
        var src: std.Io.Writer.Allocating = try .initCapacity(arena, file_size + to_add);

        _ = try file_reader.interface.streamRemaining(&src.writer);
        break :src src.toArrayList();
    };

    const i = std.mem.indexOf(
        u8,
        src.items,
        "return fixture_path(CLAR_FIXTURE_PATH, fixture_name);",
    ) orelse return;

    const start = i + "return fixture_path(".len;
    src.replaceRangeAssumeCapacity(start, fixture_var_name.len, fixture_path);

    var writer = file.writer(io, &buf); // buf is safe to reuse since file_reader is out of scope
    try writer.interface.writeAll(src.items);
    try writer.interface.flush();
}

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(1);
}
