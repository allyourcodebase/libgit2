const std = @import("std");
const testing = std.testing;

const c = @cImport({
    @cInclude("git2.h");
    @cInclude("hash.h");
});

const fixture = @import("fixture");

fn calcHashFile(
    allocator: std.mem.Allocator,
    filename: []const u8,
    comptime algorithm: c.git_hash_algorithm_t,
) ![]u8 {
    const file = try std.fs.openFileAbsolute(
        filename,
        .{},
    );
    defer file.close();

    const size: usize = switch (algorithm) {
        c.GIT_HASH_ALGORITHM_SHA1 => c.GIT_HASH_SHA1_SIZE,
        c.GIT_HASH_ALGORITHM_SHA256 => c.GIT_HASH_SHA256_SIZE,
        else => unreachable,
    };
    const actual = try allocator.alloc(u8, size);

    errdefer {
        std.log.err("{s}", .{c.git_error_last().*.message});
    }

    if (c.git_libgit2_init() < 0) return error.Unexpected;
    defer _ = c.git_libgit2_shutdown();

    var ctx: c.git_hash_ctx = undefined;
    if (c.git_hash_ctx_init(&ctx, algorithm) != 0)
        return error.Unexpected;
    defer c.git_hash_ctx_cleanup(&ctx);

    const reader = file.reader();
    while (true) {
        var buf: [2048]u8 = undefined;
        const len = try reader.read(&buf);
        if (len == 0) break;
        if (c.git_hash_update(&ctx, &buf, len) != 0)
            return error.Unexpected;
    }

    if (c.git_hash_final(actual.ptr, &ctx) != 0)
        return error.Unexpected;

    return actual;
}

test "sha1" {
    const expect = [c.GIT_HASH_SHA1_SIZE]u8{
        0x4e, 0x72, 0x67, 0x9e, 0x3e, 0xa4, 0xd0, 0x4e,
        0x0c, 0x64, 0x2f, 0x02, 0x9e, 0x61, 0xeb, 0x80,
        0x56, 0xc7, 0xed, 0x94,
    };
    const actual = try calcHashFile(
        testing.allocator,
        fixture.resources ++ "/sha1/hello_c",
        c.GIT_HASH_ALGORITHM_SHA1,
    );
    defer testing.allocator.free(actual);

    try testing.expectEqualSlices(u8, &expect, actual);
}

test "sha256 empty" {
    const expect = [c.GIT_HASH_SHA256_SIZE]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    const actual = try calcHashFile(
        testing.allocator,
        fixture.resources ++ "/sha1/empty",
        c.GIT_HASH_ALGORITHM_SHA256,
    );
    defer testing.allocator.free(actual);

    try testing.expectEqualSlices(u8, &expect, actual);
}

test "sha256 hello" {
    const expect = [c.GIT_HASH_SHA256_SIZE]u8{
        0xaa, 0x32, 0x7f, 0xae, 0x5c, 0x91, 0x58, 0x3a,
        0x4f, 0xb6, 0x54, 0xcc, 0xb6, 0xc2, 0xb1, 0x0c,
        0x77, 0xd7, 0x49, 0xc9, 0x91, 0x2a, 0x8d, 0x6b,
        0x47, 0x26, 0x13, 0xc0, 0xa0, 0x4b, 0x4d, 0xad,
    };
    const actual = try calcHashFile(
        testing.allocator,
        fixture.resources ++ "/sha1/hello_c",
        c.GIT_HASH_ALGORITHM_SHA256,
    );
    defer testing.allocator.free(actual);

    try testing.expectEqualSlices(u8, &expect, actual);
}

test "sha256 pdf" {
    const expect = [c.GIT_HASH_SHA256_SIZE]u8{
        0x2b, 0xb7, 0x87, 0xa7, 0x3e, 0x37, 0x35, 0x2f,
        0x92, 0x38, 0x3a, 0xbe, 0x7e, 0x29, 0x02, 0x93,
        0x6d, 0x10, 0x59, 0xad, 0x9f, 0x1b, 0xa6, 0xda,
        0xaa, 0x9c, 0x1e, 0x58, 0xee, 0x69, 0x70, 0xd0,
    };
    const actual = try calcHashFile(
        testing.allocator,
        fixture.resources ++ "/sha1/shattered-1.pdf",
        c.GIT_HASH_ALGORITHM_SHA256,
    );
    defer testing.allocator.free(actual);

    try testing.expectEqualSlices(u8, &expect, actual);
}
