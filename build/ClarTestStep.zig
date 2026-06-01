//! Runs a Clar test and lightly parses it's [TAP](https://testanything.org/) stream,
//! reporting progress/errors to the build system.
// Based on Step.Run

step: *Step,
run: *Step.Run,
parse: *Step.Run,

const ClarTestStep = @This();

pub fn create(owner: *std.Build, name: []const u8, runner: *Step.Compile) *ClarTestStep {
    const clar = owner.allocator.create(ClarTestStep) catch @panic("OOM");
    const run = owner.addRunArtifact(runner);
    run.setName(owner.fmt("run-{s}", .{name}));
    run.addArg("-t");

    const parse = owner.addRunArtifact(owner.addExecutable(.{
        .name = "clar-parser",
        .root_module = owner.createModule(.{
            .root_source_file = owner.path("build/ClarParser.zig"),
            .target = owner.graph.host,
            .optimize = .ReleaseSafe,
        }),
    }));
    parse.setName(owner.fmt("parse-{s}", .{name}));
    parse.addFileArg(run.captureStdOut(.{}));

    clar.* = .{
        .step = &parse.step,
        .run = run,
        .parse = parse,
    };
    return clar;
}

pub fn addArg(clar: *ClarTestStep, arg: []const u8) void {
    clar.run.addArg(arg);
}

pub fn addArgs(clar: *ClarTestStep, args: []const []const u8) void {
    for (args) |arg| clar.addArg(arg);
}

const std = @import("std");
const mem = std.mem;
const Step = std.Build.Step;
const Allocator = mem.Allocator;
