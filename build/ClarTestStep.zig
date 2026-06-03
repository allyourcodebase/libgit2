//! See clar_parser.zig

step: *Step,
test_and_parse: *Step.Run,

const ClarTestStep = @This();

pub fn create(owner: *std.Build, name: []const u8, runner: *Step.Compile) *ClarTestStep {
    const clar = owner.allocator.create(ClarTestStep) catch @panic("OOM");

    const run = owner.addRunArtifact(owner.addExecutable(.{
        .name = "clar-parser",
        .root_module = owner.createModule(.{
            .root_source_file = owner.path("build/clar_parser.zig"),
            .target = owner.graph.host,
            .optimize = .Debug,
        }),
    }));
    run.setName(owner.fmt("test-{s}", .{name}));
    run.addArtifactArg(runner);

    clar.* = .{
        .step = &run.step,
        .test_and_parse = run,
    };
    return clar;
}

pub fn addArg(clar: *ClarTestStep, arg: []const u8) void {
    clar.test_and_parse.addArg(arg);
}

pub fn addArgs(clar: *ClarTestStep, args: []const []const u8) void {
    for (args) |arg| clar.addArg(arg);
}

const std = @import("std");
const mem = std.mem;
const Step = std.Build.Step;
const Allocator = mem.Allocator;
