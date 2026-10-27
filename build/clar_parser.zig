//! Runs a Clar test and lightly parses it's [TAP](https://testanything.org/) stream,
//! reporting progress/errors to the build system.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = (try init.minimal.args.toSlice(arena))[1..];

    if (args.len < 2) {
        std.log.err("expected at least 2 arguments, got: {d}", .{args.len});
        return error.InvalidArgs;
    }

    const parent_progress_node = std.Progress.start(io, .{ .root_name = args[0] });
    defer parent_progress_node.end();

    var argv_list: std.ArrayList([]const u8) = try .initCapacity(arena, args.len + 1);
    argv_list.appendAssumeCapacity(args[1]); // test runner executable
    argv_list.appendAssumeCapacity("-t"); // force TAP output
    argv_list.appendSliceAssumeCapacity(args[2..]); // test runner args

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
    var errors: std.ArrayList(TapParser.Result.Failure) = .empty;

    // not all tests belong to a suite, so start_suite isn't guaranteed to
    // occur before tests start running.
    var suite: ?[]const u8 = null;
    var node: ?std.Progress.Node = null;
    defer if (node) |n| n.end();

    // @Todo track number of tests passed/failed/skipped?
    var error_found: bool = false;
    while (r.takeDelimiter('\n')) |line| {
        switch (try parser.parseLine(arena, line orelse break)) {
            .start_suite => |s| {
                if (node) |n| n.end();
                node = parent_progress_node.start(s, 0);

                try report_errors(io, errors.items, suite);
                errors.clearRetainingCapacity();
                if (suite) |last_suite| {
                    // in the common case there are many suite names and few errors,
                    // so suite will likely be the most recent allocation.
                    arena.free(last_suite);
                }
                suite = s;
            },
            .ok => {
                if (node) |n| n.completeOne();
            },
            .failure => |fail| {
                error_found = true;
                std.Progress.setStatus(.failure_working);
                if (node) |n| n.completeOne();
                try errors.append(arena, fail);
                parser.reset();
            },
            .feed_line => {},
        }
    } else |err| switch (err) {
        error.ReadFailed => return file_reader.err.?,
        error.StreamTooLong => return error.TapLineTooLong, // if you get this error then the reader buffer is too short!
    }

    _ = try runner.wait(io); // @Todo report term?
    try report_errors(io, errors.items, suite);
    return @intFromBool(error_found);
}

fn report_errors(
    io: std.Io,
    failures: []const TapParser.Result.Failure,
    suite: ?[]const u8,
) !void {
    if (failures.len > 0) {
        var stderr_buf: [256]u8 = undefined;
        const term = (try io.lockStderr(&stderr_buf, null)).terminal();
        defer io.unlockStderr(); // flushes stderr

        try term.setColor(.red);
        try term.writer.writeAll("errors");
        try term.setColor(.reset);
        try term.writer.print(" in suite: {?s}\n\n", .{suite});
        for (failures) |fail| {
            try term.setColor(.red);
            try term.writer.writeAll("test failure: ");
            try term.setColor(.reset);
            try term.writer.writeAll(fail.description.test_name);
            try term.writer.writeAll(": ");
            try term.setColor(.dim);
            try term.writer.writeAll(fail.description.file_path_and_line.items);
            try term.setColor(.reset);
            try term.writer.writeByte('\n');

            print_line: {
                const sep_idx = std.mem.findScalar(u8, fail.description.file_path_and_line.items, ':').?;
                const path = fail.description.file_path_and_line.items[0..sep_idx];
                const line = std.fmt.parseUnsigned(
                    usize,
                    fail.description.file_path_and_line.items[sep_idx + 1 ..],
                    0,
                ) catch {
                    @branchHint(.unlikely);
                    break :print_line;
                };

                // print the offending line
                if (std.Io.Dir.cwd().openFile(io, path, .{})) |file| {
                    defer file.close(io);
                    var buf: [256]u8 = undefined;
                    var freader = file.reader(io, &buf);

                    for (0..line -| 1) |_| {
                        _ = freader.interface.discardDelimiterInclusive('\n') catch break;
                    }
                    _ = try freader.interface.streamDelimiterEnding(term.writer, '\n');
                    try term.writer.writeByte('\n');
                } else |_| {
                    @branchHint(.unlikely);
                    break :print_line;
                }
            }

            for (fail.reasons.items) |reason| {
                try term.setColor(.bright_cyan);
                try term.writer.writeAll("reason: ");
                try term.setColor(.reset);
                try term.writer.writeAll(reason);
                try term.writer.writeByte('\n');
            }
            try term.writer.writeByte('\n');
        }
    }
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
            description: struct {
                test_name: []const u8,
                file_path_and_line: std.ArrayList(u8),
            },
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
                p.wip_failure.description.test_name = try arena.dupe(u8, name);
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
                try p.wip_failure.description.file_path_and_line.appendSlice(arena, file);
                p.state = .line;
            },
            .line => {
                const line_start = skip(line, keyword.line, 0) orelse @panic("expected line");
                const fail_line = mem.trim(u8, line[line_start..], &std.ascii.whitespace);
                try p.wip_failure.description.file_path_and_line.append(arena, ':');
                try p.wip_failure.description.file_path_and_line.appendSlice(arena, fail_line);
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
            .description = .{
                .test_name = &.{},
                .file_path_and_line = .empty,
            },
            .reasons = .empty,
        },
    };

    fn reset(p: *TapParser) void {
        p.* = default;
    }
};
