//! Runs a Clar test and lightly parses it's [TAP](https://testanything.org/) stream,
//! reporting progress/errors to the build system.
// @Todo report progress/errors to the build system

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = (try init.minimal.args.toSlice(arena))[1..];

    if (args.len < 1) {
        std.log.err("expected at least one argument", .{});
        return error.InvalidArgs;
    }

    var argv_list: std.ArrayList([]const u8) = try .initCapacity(arena, args.len + 1);
    argv_list.appendAssumeCapacity(args[0]); // test runner executable
    argv_list.appendAssumeCapacity("-t"); // force TAP output
    argv_list.appendSliceAssumeCapacity(args[1..]); // test runner args

    var runner = try std.process.spawn(io, .{
        .argv = argv_list.items,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .inherit,
    });

    var reader_buf: [1024]u8 = undefined;
    var file_reader = runner.stdout.?.readerStreaming(io, &reader_buf);
    const r = &file_reader.interface;

    var parser: TapParser = .default;
    var errors: std.ArrayList([]const u8) = .empty;

    var suite: ?[]const u8 = null;
    var error_found: bool = false;
    while (r.takeDelimiter('\n')) |line| {
        switch (try parser.parseLine(arena, line orelse break)) {
            .start_suite => |s| {
                // @Todo integrate with build progress nodes instead
                if (suite) |last_suite| {
                    if (try check_errors(io, errors.items, last_suite)) {
                        error_found = true;
                    }
                    arena.free(last_suite);
                    errors.clearRetainingCapacity();
                }
                suite = s;
            },
            .ok => {},
            .failure => |fail| {
                try errors.append(arena, fail.description.items);
                try errors.appendSlice(arena, fail.reasons.items);
                try errors.append(arena, "\n");
                parser.reset();
            },
            .feed_line => {},
        }
    } else |err| switch (err) {
        error.ReadFailed => return file_reader.err.?,
        error.StreamTooLong => return error.TapLineTooLong, // if you get this error then the reader buffer is too short!
    }

    _ = try runner.wait(io); // @Todo report term?
    if (try check_errors(io, errors.items, suite)) {
        error_found = true;
    }

    return @intFromBool(error_found);
}

pub fn check_errors(io: std.Io, errors: []const []const u8, suite: ?[]const u8) !bool {
    if (errors.len > 0) {
        const stderr = std.Io.File.stderr();
        var stderr_buf: [1024]u8 = undefined;
        var stderr_writer = stderr.writerStreaming(io, &stderr_buf);

        try stderr_writer.interface.print("errors in suite: {?s}\n", .{suite});
        for (errors) |err| {
            try stderr_writer.interface.writeAll(err);
            try stderr_writer.interface.writeByte('\n');
        }
        try stderr_writer.flush();
        return true;
    }
    return false;
}

const TapParser = struct {
    state: State,
    wip_failure: Result.Failure,

    const Result = union(enum) {
        start_suite: []const u8,
        ok,
        failure: Failure,
        feed_line,

        const Failure = struct {
            description: std.ArrayList(u8),
            reasons: std.ArrayList([]const u8),
        };
    };

    const keyword = struct {
        const suite_start = "# start of suite ";
        const ok = "ok ";
        const not_ok = "not ok ";
        const spacer1 = " - ";
        const spacer2 = ": ";
        const yaml_blk = " ---";
        const pre_reason = "reason: |";
        const at = "at:";
        const file = "file: ";
        const line = "line: ";
    };

    const State = enum {
        start,
        desc,
        yaml_start,
        pre_reason,
        reason,
        file,
        line,
    };

    /// caller owns any memory allocated in Result (start_suite and failure)
    fn parseLine(p: *TapParser, arena: Allocator, line: []const u8) Allocator.Error!Result {
        loop: switch (p.state) {
            .start => {
                if (mem.startsWith(u8, line, keyword.suite_start)) {
                    const suite_start = skip(line, keyword.spacer2, keyword.suite_start.len) orelse @panic("expected suite number");
                    return .{ .start_suite = try arena.dupe(u8, line[suite_start..]) };
                } else if (mem.startsWith(u8, line, keyword.ok)) {
                    return .ok;
                } else if (mem.startsWith(u8, line, keyword.not_ok)) {
                    p.state = .desc;
                    continue :loop p.state;
                }
            },

            // Failure parsing
            .desc => {
                const name_start = skip(line, keyword.spacer1, keyword.not_ok.len) orelse @panic("expected spacer");
                const name = mem.trim(u8, line[name_start..], &std.ascii.whitespace);
                try p.wip_failure.description.appendSlice(arena, name);
                try p.wip_failure.description.appendSlice(arena, ": ");
                p.state = .yaml_start;
            },
            .yaml_start => {
                _ = mem.indexOf(u8, line, keyword.yaml_blk) orelse @panic("expected yaml_blk");
                p.state = .pre_reason;
            },
            .pre_reason => {
                _ = mem.indexOf(u8, line, keyword.pre_reason) orelse @panic("expected pre_reason");
                p.state = .reason;
            },
            .reason => {
                if (mem.indexOf(u8, line, keyword.at) != null) {
                    p.state = .file;
                } else {
                    const ln = mem.trim(u8, line, &std.ascii.whitespace);
                    try p.wip_failure.reasons.append(arena, try arena.dupe(u8, ln));
                }
            },
            .file => {
                const file_start = skip(line, keyword.file, 0) orelse @panic("expected file");
                const file = mem.trim(u8, line[file_start..], std.ascii.whitespace ++ "'");
                try p.wip_failure.description.appendSlice(arena, file);
                try p.wip_failure.description.append(arena, ':');
                p.state = .line;
            },
            .line => {
                const line_start = skip(line, keyword.line, 0) orelse @panic("expected line");
                const fail_line = mem.trim(u8, line[line_start..], &std.ascii.whitespace);
                try p.wip_failure.description.appendSlice(arena, fail_line);
                p.state = .start;
                return .{ .failure = p.wip_failure };
            },
        }

        return .feed_line;
    }

    fn skip(line: []const u8, to_skip: []const u8, start: usize) ?usize {
        const index = mem.indexOfPos(u8, line, start, to_skip) orelse return null;
        return to_skip.len + index;
    }

    const default: TapParser = .{
        .state = .start,
        .wip_failure = .{
            .description = .empty,
            .reasons = .empty,
        },
    };

    fn reset(p: *TapParser) void {
        p.* = default;
    }
};
