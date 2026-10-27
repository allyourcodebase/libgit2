//! Usage: clar_fix <clar.c> <clar/fixture.h> <fixtures-dir>
//! Replaces *reads* of the `CLAR_FIXTURE_PATH` macro definition in `clar/fixture.h` with
//! the absolute path of `<fixtures-dir>`. `#ifdef`s are not affected.
//! Also applies a patch to `clar.c` fixing a bad `stat` definition on Windows.

const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arena = init.arena.allocator();

    var args = try init.minimal.args.iterateAllocator(arena);
    std.debug.assert(args.skip());

    const clar_c_path = args.next() orelse fatal("expected path to `clar.c` file", .{});
    const fixture_h_path = args.next() orelse fatal("expected path to `clar/fixture.h` file", .{});
    const fixture_dir_path = args.next() orelse fatal("expected path to test resources directory", .{});

    fix_fixture_path: {
        const fixture_var_name = "CLAR_FIXTURE_PATH";

        const clean_fixture_path: []const u8 = blk: {
            const rec_dir = try std.Io.Dir.cwd().openDir(io, fixture_dir_path, .{});
            defer rec_dir.close(io);

            var cleaned_path: std.ArrayList(u8) = try .initCapacity(arena, std.fs.max_path_bytes + 2);
            cleaned_path.appendAssumeCapacity('"'); // add string quotes
            const abs_path_len = try rec_dir.realPath(io, cleaned_path.unusedCapacitySlice());
            cleaned_path.items.len += abs_path_len;
            cleaned_path.appendAssumeCapacity('"');

            // clar expects the fixture path to only have posix seperators or else some tests will break
            for (cleaned_path.items) |*c| {
                if (c.* == '\\') c.* = '/';
            }
            break :blk cleaned_path.items;
        };

        const file = try std.Io.Dir.cwd().openFile(io, fixture_h_path, .{ .mode = .read_write });
        defer file.close(io);

        const to_add = clean_fixture_path.len -| fixture_var_name.len;
        var src = try readIntoArraylist(io, arena, file, to_add);

        const i = std.mem.indexOf(
            u8,
            src.items,
            "return fixture_path(CLAR_FIXTURE_PATH, fixture_name);",
        ) orelse break :fix_fixture_path; // @Todo disambiguate whether patch was already applied or doesn't apply

        const start = i + "return fixture_path(".len;
        src.replaceRangeAssumeCapacity(start, fixture_var_name.len, clean_fixture_path);

        var writer = file.writer(io, &.{});
        try writer.seekTo(0);
        try writer.interface.writeAll(src.items);
        try writer.end();
    }

    // Patch bad stat declaration in clar.c
    // (See https://github.com/clar-test/clar/commit/02104ca0f81ef4105cf0c4a558ad7d24c8fe97c4)
    patch_stat: {
        // This fix only applies to windows builds.
        if (@import("builtin").target.os.tag != .windows) break :patch_stat;

        const file = try std.Io.Dir.cwd().openFile(io, clar_c_path, .{ .mode = .read_write });
        defer file.close(io);
        var src = try readIntoArraylist(io, arena, file, 0);

        const to_remove =
            "#\tif defined(_MSC_VER) || defined(__MINGW32__)\n" ++
            "\ttypedef struct stat STAT_T;\n" ++
            "#\telse\n" ++
            "\ttypedef struct _stat STAT_T;\n" ++
            "#\tendif\n";

        const to_add =
            "\t\ttypedef struct _stat STAT_T;\n" ++
            "#\telse\n" ++
            "\t\ttypedef struct stat STAT_T;\n";

        comptime std.debug.assert(to_remove.len >= to_add.len);

        {
            const i = std.mem.indexOf(u8, src.items, to_remove) orelse break :patch_stat; // @Todo disambiguate whether patch was already applied or doesn't apply
            src.replaceRangeAssumeCapacity(i, to_remove.len, "");
        }
        {
            const match =
                "#\tifndef stat\n" ++
                "#\t\tdefine stat(path, st) _stat(path, st)\n" ++
                "#\tendif\n";
            const i = std.mem.indexOf(u8, src.items, match) orelse break :patch_stat; // @Todo disambiguate whether patch was already applied or doesn't apply

            const start = i + ("#\tifndef stat\n" ++
                "#\t\tdefine stat(path, st) _stat(path, st)\n").len;

            src.insertSliceAssumeCapacity(start, to_add);
        }

        var writer = file.writer(io, &.{});
        try writer.seekTo(0);
        try writer.interface.writeAll(src.items);
        try writer.end();
    }
}

fn readIntoArraylist(
    io: std.Io,
    gpa: std.mem.Allocator,
    file: std.Io.File,
    additional_capacity: usize,
) !std.ArrayList(u8) {
    var file_reader = file.reader(io, &.{});
    const file_size: usize = @intCast(try file_reader.getSize());
    var buf: std.Io.Writer.Allocating = try .initCapacity(gpa, file_size + additional_capacity);
    errdefer buf.deinit();

    _ = try file_reader.interface.streamRemaining(&buf.writer);
    return buf.toArrayList();
}

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(1);
}
