//! Runs a Clar test and lightly parses it's [TAP](https://testanything.org/) stream,
//! reporting progress/errors to the build system.
// Based on Step.Run

step: Step,
runner: *Step.Compile,
args: std.ArrayListUnmanaged([]const u8),

const ClarTestStep = @This();

pub fn create(owner: *std.Build, name: []const u8, runner: *Step.Compile) *ClarTestStep {
    const clar = owner.allocator.create(ClarTestStep) catch @panic("OOM");
    clar.* = .{
        .step = Step.init(.{
            .id = .custom,
            .name = name,
            .owner = owner,
            .makeFn = make,
        }),
        .runner = runner,
        .args = .{},
    };
    runner.getEmittedBin().addStepDependencies(&clar.step);
    return clar;
}

pub fn addArg(clar: *ClarTestStep, arg: []const u8) void {
    const b = clar.step.owner;
    clar.args.append(b.allocator, b.dupe(arg)) catch @panic("OOM");
}

pub fn addArgs(clar: *ClarTestStep, args: []const []const u8) void {
    for (args) |arg| clar.addArg(arg);
}

fn make(step: *Step, options: std.Build.Step.MakeOptions) !void {
    const clar: *ClarTestStep = @fieldParentPtr("step", step);
    const b = step.owner;
    const arena = b.allocator;

    var man = b.graph.cache.obtain();
    defer man.deinit();

    var argv_list = std.ArrayList([]const u8).init(arena);
    {
        const file_path = clar.runner.installed_path orelse clar.runner.generated_bin.?.path.?;
        try argv_list.append(file_path);
        _ = try man.addFile(file_path, null);
    }
    try argv_list.append("-t"); // force TAP output
    for (clar.args.items) |arg| {
        try argv_list.append(arg);
        man.hash.addBytes(arg);
    }

    if (try step.cacheHitAndWatch(&man)) {
        // cache hit, skip running command
        step.result_cached = true;
        return;
    }

    {
        var child = std.process.Child.init(argv_list.items, arena);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;

        try child.spawn();

        var poller = std.io.poll(
            b.allocator,
            enum { stdout },
            .{ .stdout = child.stdout.? },
        );
        defer poller.deinit();

        const fifo = poller.fifo(.stdout);
        const r = fifo.reader();

        var buf: std.BoundedArray(u8, 1024) = .{};
        const w = buf.writer();

        var parser: TapParser = .default;
        var node: ?std.Progress.Node = null;
        defer if (node) |n| n.end();

        while (true) {
            r.streamUntilDelimiter(w, '\n', null) catch |err| switch (err) {
                error.EndOfStream => if (try poller.poll()) continue else break,
                else => return err,
            };

            const line = buf.constSlice();
            defer buf.resize(0) catch unreachable;

            switch (try parser.parseLine(arena, line)) {
                .start_suite => |suite| {
                    if (node) |n| n.end();
                    node = options.progress_node.start(suite, 0);
                },
                .ok => {
                    if (node) |n| n.completeOne();
                },
                .failure => |fail| {
                    // @Cleanup print failures in a nicer way. Avoid redundant "error:" prefixes on newlines with minimal allocations.
                    try step.result_error_msgs.append(arena, fail.description.items);
                    try step.result_error_msgs.appendSlice(arena, fail.reasons.items);
                    try step.result_error_msgs.append(arena, "\n");
                    if (node) |n| n.completeOne();
                    parser.reset();
                },
                .feed_line => {},
            }
        }

        const term = try child.wait();
        try step.handleChildProcessTerm(term, null, argv_list.items);
    }

    try step.writeManifestAndWatch(&man);
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
            description: std.ArrayListUnmanaged(u8),
            reasons: std.ArrayListUnmanaged([]const u8),
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

    fn parseLine(p: *TapParser, step_arena: Allocator, line: []const u8) Allocator.Error!Result {
        loop: switch (p.state) {
            .start => {
                if (std.mem.startsWith(u8, line, keyword.suite_start)) {
                    const suite_start = skip(line, keyword.spacer2, keyword.suite_start.len) orelse @panic("expected suite number");
                    return .{ .start_suite = line[suite_start..] };
                } else if (std.mem.startsWith(u8, line, keyword.ok)) {
                    return .ok;
                } else if (std.mem.startsWith(u8, line, keyword.not_ok)) {
                    p.state = .desc;
                    continue :loop p.state;
                }
            },

            // Failure parsing
            .desc => {
                const name_start = skip(line, keyword.spacer1, keyword.not_ok.len) orelse @panic("expected spacer");
                try p.wip_failure.description.appendSlice(step_arena, line[name_start..]);
                try p.wip_failure.description.appendSlice(step_arena, ": ");
                p.state = .yaml_start;
            },
            .yaml_start => {
                _ = std.mem.indexOf(u8, line, keyword.yaml_blk) orelse @panic("expected yaml_blk");
                p.state = .pre_reason;
            },
            .pre_reason => {
                _ = std.mem.indexOf(u8, line, keyword.pre_reason) orelse @panic("expected pre_reason");
                p.state = .reason;
            },
            .reason => {
                if (std.mem.indexOf(u8, line, keyword.at) != null) {
                    p.state = .file;
                } else {
                    const ln = std.mem.trim(u8, line, &std.ascii.whitespace);
                    try p.wip_failure.reasons.append(step_arena, try step_arena.dupe(u8, ln));
                }
            },
            .file => {
                const file_start = skip(line, keyword.file, 0) orelse @panic("expected file");
                const file = std.mem.trim(u8, line[file_start..], &.{'\''});
                try p.wip_failure.description.appendSlice(step_arena, file);
                try p.wip_failure.description.append(step_arena, ':');
                p.state = .line;
            },
            .line => {
                const line_start = skip(line, keyword.line, 0) orelse @panic("expected line");
                try p.wip_failure.description.appendSlice(step_arena, line[line_start..]);
                p.state = .start;
                return .{ .failure = p.wip_failure };
            },
        }

        return .feed_line;
    }

    fn skip(line: []const u8, to_skip: []const u8, start: usize) ?usize {
        const index = std.mem.indexOfPos(u8, line, start, to_skip) orelse return null;
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

const std = @import("std");
const Step = std.Build.Step;
const Allocator = std.mem.Allocator;
