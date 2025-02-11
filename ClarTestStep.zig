//! Runs a Clar test and parses it's [TAP](https://testanything.org/) stream,
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

        var buf: [1024]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        const w = fbs.writer();

        var parser: FailureParser = .default;
        while (true) {
            r.streamUntilDelimiter(w, '\n', null) catch |err| switch (err) {
                error.EndOfStream => if (try poller.poll()) continue else break,
                else => return err,
            };

            const line = fbs.getWritten();
            defer fbs.reset();

            options.progress_node.completeOne();

            if (try parser.parseLine(arena, line)) |err| {
                try step.addError("{s}: {s}:{s}", .{ err.desc, err.file, err.line });
                try step.result_error_msgs.appendSlice(arena, b.dupeStrings(err.reasons.items));
                try step.result_error_msgs.append(arena, "\n");
                parser.reset(arena);
            }
        }

        const term = try child.wait();
        try step.handleChildProcessTerm(term, null, argv_list.items);
    }

    try step.writeManifestAndWatch(&man);
}

const FailureParser = struct {
    state: State,
    fail: Failure,

    const Failure = struct {
        desc: []const u8,
        reasons: std.ArrayListUnmanaged([]const u8),
        file: []const u8,
        line: []const u8,
    };

    const not_ok = "not ok ";
    const spacer = " - ";
    const yaml_blk = " ---";
    const pre_reason = "reason: |";
    const at = "at:";
    const file = "file: ";
    const _line = "line: ";

    const State = enum {
        start,
        desc,
        yaml_start,
        pre_reason,
        reason,
        file,
        line,
    };

    fn parseLine(p: *FailureParser, allocator: Allocator, line: []const u8) Allocator.Error!?Failure {
        loop: switch (p.state) {
            .start => {
                if (std.mem.startsWith(u8, line, not_ok)) {
                    @branchHint(.unlikely);
                    p.state = .desc;
                    continue :loop p.state;
                }
            },
            .desc => {
                const name_start = spacer.len + (std.mem.indexOfPos(u8, line, not_ok.len, spacer) orelse @panic("expected spacer"));
                p.fail.desc = try allocator.dupe(u8, line[name_start..]);
                p.state = .yaml_start;
            },
            .yaml_start => {
                _ = std.mem.indexOf(u8, line, yaml_blk) orelse @panic("expected yaml_blk");
                p.state = .pre_reason;
            },
            .pre_reason => {
                _ = std.mem.indexOf(u8, line, pre_reason) orelse @panic("expected pre_reason");
                p.state = .reason;
            },
            .reason => {
                if (std.mem.indexOf(u8, line, at) != null) {
                    p.state = .file;
                } else {
                    const ln = std.mem.trim(u8, line, &std.ascii.whitespace);
                    try p.fail.reasons.append(allocator, try allocator.dupe(u8, ln));
                }
            },
            .file => {
                const file_start = file.len + (std.mem.indexOf(u8, line, file) orelse @panic("expected file"));
                p.fail.file = try allocator.dupe(u8, std.mem.trim(u8, line[file_start..], &.{'\''}));
                p.state = .line;
            },
            .line => {
                const line_start = _line.len + (std.mem.indexOf(u8, line, _line) orelse @panic("expected line"));
                p.fail.line = try allocator.dupe(u8, line[line_start..]);
                p.state = .start;
                return p.fail;
            },
        }

        return null;
    }

    const default: FailureParser = .{
        .state = .start,
        .fail = .{
            .desc = undefined,
            .reasons = .{},
            .file = undefined,
            .line = undefined,
        },
    };

    fn reset(p: *FailureParser, allocator: Allocator) void {
        for (p.fail.reasons.items) |reason| allocator.free(reason);
        p.fail.reasons.deinit(allocator);
        allocator.free(p.fail.desc);
        allocator.free(p.fail.file);
        allocator.free(p.fail.line);
        p.* = default;
    }
};

const std = @import("std");
const Step = std.Build.Step;
const Allocator = std.mem.Allocator;
