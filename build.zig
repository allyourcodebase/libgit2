const std = @import("std");
const sources = @import("build/sources.zon");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const libgit_src = b.dependency("libgit2", .{});

    const mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const lib = b.addLibrary(.{
        .name = "git2",
        .linkage = .static,
        .root_module = mod,
    });

    const features = b.addConfigHeader(
        .{ .style = .{ .cmake = libgit_src.path("src/util/git2_features.h.in") } },
        .{
            .GIT_THREADS = 1,
            .GIT_USE_NSEC = 1,
        },
    );

    // @Cleanup: all these platform and TLS variants are starting to become unweildly. Compress these codepaths to avoid edgecases.

    // @Todo: are there more subtleties for other platforms?
    // @Todo: do we need iconv on other platforms? original cmake enabled it by
    // default on APPLE targets
    switch (target.result.os.tag) {
        .macos => {
            mod.linkSystemLibrary("iconv", .{});
            features.addValues(.{
                .GIT_USE_ICONV = 1,
                .GIT_USE_STAT_MTIMESPEC = 1,
                .GIT_REGEX_REGCOMP_L = 1,
                .GIT_QSORT_BSD = 1,
            });
        },
        .windows => {
            features.addValues(.{
                .GIT_QSORT_MSC = 1,
            });
        },
        else => {
            features.addValues(.{
                .GIT_USE_STAT_MTIM = 1,
                .GIT_RAND_GETENTROPY = 1,
                .GIT_RAND_GETLOADAVG = 1,
            });
        },
    }

    const flags = [_][]const u8{
        // @Todo: for some reason on linux, trying to use c90 as specified in the cmake
        // files causes compile errors relating to pthreads. Using gnu90 or the
        // default compiles, so I guess this is fine?
        // "-std=c90",
        "-DHAVE_CONFIG_H",
        if (target.result.os.tag != .windows)
            "-DGIT_DEFAULT_CERT_LOCATION=\"/etc/ssl/certs/\""
        else
            "",
        "-fno-sanitize=undefined",
    };

    // The TLS backend logic is only run for non windows builds.
    var tls_dep: ?*std.Build.Dependency = null;
    const tls_backend: TlsBackend = b.option(
        TlsBackend,
        "tls-backend",
        "Choose Unix TLS/SSL backend (default is mbedtls)",
    ) orelse if (target.result.os.tag == .macos) .securetransport else .mbedtls;

    if (target.result.os.tag == .windows) {
        mod.linkSystemLibrary("winhttp", .{});
        mod.linkSystemLibrary("rpcrt4", .{});
        mod.linkSystemLibrary("crypt32", .{});
        mod.linkSystemLibrary("ole32", .{});
        mod.linkSystemLibrary("ws2_32", .{});
        mod.linkSystemLibrary("secur32", .{});

        features.addValues(.{
            .GIT_HTTPS = 1,
            .GIT_WINHTTP = 1,

            .GIT_SHA1_COLLISIONDETECT = 1,
            .GIT_SHA256_WIN32 = 1,

            .GIT_IO_WSAPOLL = 1,
        });

        mod.addWin32ResourceFile(.{ .file = libgit_src.path("src/libgit2/git2.rc") });
        mod.addCSourceFiles(.{
            .root = libgit_src.path("src/util"),
            .files = &sources.util_win32,
            .flags = &flags,
        });
    } else {
        switch (tls_backend) {
            .securetransport => {
                mod.linkFramework("Security", .{});
                mod.linkFramework("CoreFoundation", .{});
                features.addValues(.{
                    .GIT_HTTPS = 1,
                    .GIT_SECURE_TRANSPORT = 1,

                    .GIT_SHA1_COLLISIONDETECT = 1,
                    .GIT_SHA256_COMMON_CRYPTO = 1,

                    .GIT_USE_FUTIMENS = 1,
                    .GIT_IO_POLL = 1,
                    .GIT_IO_SELECT = 1,
                });
            },
            .openssl => {
                tls_dep = try b.dependencyLazy("openssl", .{
                    .target = target,
                    .optimize = optimize,
                });
                if (tls_dep) |tls| mod.linkLibrary(tls.artifact("openssl"));
                features.addValues(.{
                    .GIT_HTTPS = 1,
                    .GIT_OPENSSL = 1,

                    .GIT_SHA1_COLLISIONDETECT = 1,
                    .GIT_SHA256_OPENSSL = 1,

                    .GIT_USE_FUTIMENS = 1,
                    .GIT_IO_POLL = 1,
                    .GIT_IO_SELECT = 1,
                });
            },
            .mbedtls => {
                tls_dep = try b.dependencyLazy("mbedtls", .{
                    .target = target,
                    .optimize = optimize,
                });
                if (tls_dep) |tls| mod.linkLibrary(tls.artifact("mbedtls"));
                features.addValues(.{
                    .GIT_HTTPS = 1,
                    .GIT_MBEDTLS = 1,

                    .GIT_SHA1_COLLISIONDETECT = 1,
                    .GIT_SHA256_MBEDTLS = 1,

                    .GIT_USE_FUTIMENS = 1,
                    .GIT_IO_POLL = 1,
                    .GIT_IO_SELECT = 1,
                });
            },
        }

        // ntlmclient
        {
            const ntlm = b.createModule(.{
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            });
            ntlm.addIncludePath(libgit_src.path("deps/ntlmclient"));
            maybeAddTlsIncludes(ntlm, tls_dep, tls_backend);

            const ntlm_cflags = .{
                "-Wno-implicit-fallthrough",
                "-DNTLM_STATIC=1",
                "-DUNICODE_BUILTIN=1",
                switch (tls_backend) {
                    .openssl => "-DCRYPT_OPENSSL",
                    .mbedtls => "-DCRYPT_MBEDTLS",
                    .securetransport => "-DCRYPT_COMMONCRYPTO",
                },
            };
            ntlm.addCSourceFiles(.{
                .root = libgit_src.path("deps/ntlmclient"),
                .files = switch (tls_backend) {
                    .openssl => &.{"crypt_openssl.c"},
                    .mbedtls => &.{ "crypt_mbedtls.c", "crypt_builtin_md4.c" },
                    .securetransport => &.{"crypt_commoncrypto.c"},
                },
                .flags = &ntlm_cflags,
            });
            ntlm.addCSourceFiles(.{
                .root = libgit_src.path("deps/ntlmclient"),
                .files = &sources.ntlm,
                .flags = &(ntlm_cflags ++ .{"-Wno-deprecated"}),
            });

            mod.linkLibrary(b.addLibrary(.{
                .name = "ntlmclient",
                .linkage = .static,
                .root_module = ntlm,
            }));
            mod.addAfterIncludePath(libgit_src.path("deps/ntlmclient")); // avoid aliasing ntlmclient/util.h and src/util/util.h
            features.addValues(.{ .GIT_NTLM = 1 });
        }

        mod.addCSourceFiles(.{
            .root = libgit_src.path("src/util"),
            .files = &sources.util_unix,
            .flags = &flags,
        });
        mod.addCSourceFiles(.{
            .root = libgit_src.path("src/util"),
            .files = switch (tls_backend) {
                .openssl => &.{"hash/openssl.c"},
                .mbedtls => &.{"hash/mbedtls.c"},
                .securetransport => &.{"hash/common_crypto.c"},
            },
            .flags = &flags,
        });
    }

    // SHA1 collisiondetect
    mod.addCSourceFiles(.{
        .root = libgit_src.path("src/util"),
        .files = &sources.util_sha1dc,
        .flags = &(flags ++ .{
            "-DSHA1DC_NO_STANDARD_INCLUDES",
            "-DSHA1DC_CUSTOM_INCLUDE_SHA1_C=\"git2_util.h\"",
            "-DSHA1DC_CUSTOM_INCLUDE_UBC_CHECK_C=\"git2_util.h\"",
        }),
    });

    if (b.option(bool, "enable-ssh", "Enable SSH support") orelse false) {
        mod.linkSystemLibrary("ssh2", .{});
        features.addValues(.{
            .GIT_SSH = 1,
            .GIT_SSH_LIBSSH2 = 1,
            .GIT_SSH_LIBSSH2_MEMORY_CREDENTIALS = 1, // @Todo: check for `libssh2_userauth_publickey_frommemory`?
        });
    }

    // Bundled dependencies
    {
        const llhttp = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        llhttp.addIncludePath(libgit_src.path("deps/llhttp"));
        llhttp.addCSourceFiles(.{
            .root = libgit_src.path("deps/llhttp"),
            .files = &sources.llhttp,
            .flags = &.{ "-Wno-unused-parameter", "-Wno-missing-declarations" },
        });

        mod.addIncludePath(libgit_src.path("deps/llhttp"));
        mod.linkLibrary(b.addLibrary(.{
            .name = "llhttp",
            .linkage = .static,
            .root_module = llhttp,
        }));
        features.addValues(.{ .GIT_HTTPPARSER_BUILTIN = 1 });
    }
    if (target.result.os.tag != .macos) {
        const pcre = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        pcre.addConfigHeader(b.addConfigHeader(
            .{ .style = .{ .cmake = libgit_src.path("deps/pcre/config.h.in") } },
            .{
                .SUPPORT_PCRE8 = 1,
                .PCRE_LINK_SIZE = 2,
                .PCRE_PARENS_NEST_LIMIT = 250,
                .PCRE_MATCH_LIMIT = 10000000,
                .PCRE_MATCH_LIMIT_RECURSION = "MATCH_LIMIT",
                .NEWLINE = '\n',
                .NO_RECURSE = 1,
                .PCRE_POSIX_MALLOC_THRESHOLD = 10,
                .BSR_ANYCRLF = 0,
                .PCREGREP_BUFSIZE = null,
            },
        ));
        pcre.addIncludePath(libgit_src.path("deps/pcre"));
        pcre.addCSourceFiles(.{
            .root = libgit_src.path("deps/pcre"),
            .files = &sources.pcre,
            .flags = &.{
                "-Wno-unused-function",
                "-Wno-implicit-fallthrough",
                "-DHAVE_CONFIG_H",
            },
        });

        mod.addIncludePath(libgit_src.path("deps/pcre"));
        mod.linkLibrary(b.addLibrary(.{
            .name = "pcre",
            .linkage = .static,
            .root_module = pcre,
        }));
        features.addValues(.{ .GIT_REGEX_BUILTIN = 1 });
    }
    {
        // @Todo: support using system zlib?
        const zlib = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        zlib.addIncludePath(libgit_src.path("deps/zlib"));
        zlib.addCSourceFiles(.{
            .root = libgit_src.path("deps/zlib"),
            .files = &sources.zlib,
            .flags = &.{
                "-Wno-implicit-fallthrough",
                "-DNO_VIZ",
                "-DSTDC",
                "-DNO_GZIP",
                "-DHAVE_SYS_TYPES_H",
                "-DHAVE_STDINT_H",
                "-DHAVE_STDDEF_H",
            },
        });

        mod.addIncludePath(libgit_src.path("deps/zlib"));
        mod.linkLibrary(b.addLibrary(.{
            .name = "z",
            .linkage = .static,
            .root_module = zlib,
        }));
        features.addValues(.{ .GIT_COMPRESSION_ZLIB = 1 });
    }
    // xdiff
    {
        // Bundled xdiff dependency relies on libgit2 headers & utils, so we
        // just add the source files directly instead of making a static lib step.
        mod.addCSourceFiles(.{
            .root = libgit_src.path("deps/xdiff"),
            .files = &sources.xdiff,
            .flags = &.{ "-Wno-sign-compare", "-Wno-unused-parameter" },
        });
        mod.addIncludePath(libgit_src.path("deps/xdiff"));
    }

    switch (target.result.ptrBitWidth()) {
        32 => features.addValues(.{ .GIT_ARCH_32 = 1 }),
        64 => features.addValues(.{ .GIT_ARCH_64 = 1 }),
        else => |size| std.debug.panic("Unsupported architecture ({d}bit)", .{size}),
    }

    mod.addConfigHeader(features);

    mod.addIncludePath(libgit_src.path("src/libgit2"));
    mod.addIncludePath(libgit_src.path("src/util"));
    mod.addIncludePath(libgit_src.path("include"));

    mod.addCSourceFiles(.{
        .root = libgit_src.path("src/libgit2"),
        .files = &sources.libgit2,
        .flags = &flags,
    });
    mod.addCSourceFiles(.{
        .root = libgit_src.path("src/util"),
        .files = &sources.util,
        .flags = &flags,
    });

    lib.installHeadersDirectory(libgit_src.path("include"), "", .{});
    b.installArtifact(lib);

    const translate_c = b.addTranslateC(.{
        .root_source_file = b.path("build/include.h"),
        .target = target,
        .optimize = optimize,
    });

    translate_c.addIncludePath(libgit_src.path("include"));

    const git2_module = translate_c.addModule("git2");
    git2_module.linkLibrary(lib);

    const cli_step = b.step("run-cli", "Build and run the command-line interface");
    {
        const cli = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });

        cli.addConfigHeader(features);
        cli.addIncludePath(libgit_src.path("src/util"));
        cli.addIncludePath(libgit_src.path("src/cli"));
        maybeAddTlsIncludes(cli, tls_dep, tls_backend);

        cli.linkLibrary(lib);
        cli.addCSourceFiles(.{
            .root = libgit_src.path("src/cli"),
            .files = &sources.cli,
            // @Todo: see above
            // .flags = &.{"-std=c90"},
        });
        cli.addCSourceFiles(.{
            .root = libgit_src.path("src/cli"),
            .files = if (target.result.os.tag == .windows)
                &.{"win32/sighandler.c"}
            else
                &.{"unix/sighandler.c"},
        });

        // independent install step so you can easily access the binary
        const cli_exe = b.addExecutable(.{
            .name = "git2_cli",
            .root_module = cli,
        });
        const cli_install = b.addInstallArtifact(cli_exe, .{});
        const cli_run = b.addRunArtifact(cli_exe);

        passthroughArgs(b, cli_run);
        cli_run.step.dependOn(&cli_install.step);
        cli_step.dependOn(&cli_run.step);
    }

    const examples_step = b.step("run-example", "Build and run library usage example app");
    {
        const lg2 = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        const lg2_exe = b.addExecutable(.{
            .name = "lg2",
            .root_module = lg2,
        });

        lg2.addIncludePath(libgit_src.path("examples"));
        lg2.addCSourceFiles(.{
            .root = libgit_src.path("examples"),
            .files = &sources.examples,
            .flags = &.{
                // "-std=c90",
                "-DGIT_DEPRECATE_HARD",
            },
        });

        maybeAddTlsIncludes(lg2, tls_dep, tls_backend);
        lg2.linkLibrary(lib);

        // independent install step so you can easily access the binary
        const examples_install = b.addInstallArtifact(lg2_exe, .{});
        const example_run = b.addRunArtifact(lg2_exe);
        passthroughArgs(b, example_run);
        example_run.step.dependOn(&examples_install.step);
        examples_step.dependOn(&example_run.step);
    }

    const test_step = b.step("test", "Run core unit tests (requires python3)");
    {
        const gen_cmd = b.addSystemCommand(&.{"python3"});
        gen_cmd.addFileArg(libgit_src.path("tests/clar/generate.py"));
        const clar_suite = gen_cmd.addPrefixedOutputDirectoryArg("-o", "clar_suite");
        gen_cmd.addArgs(&.{ "-f", "-xonline", "-xstress", "-xperf" });
        gen_cmd.addDirectoryArg(libgit_src.path("tests/libgit2"));

        // Copy the clar source so it can be modified below.
        const clar_src = b.addWriteFiles().addCopyDirectory(
            libgit_src.path("tests/clar"),
            "clar_src",
            .{},
        );

        const runner = b.createModule(.{
            .target = target,
            .optimize = .Debug,
            .link_libc = true,
        });
        const runner_exe = b.addExecutable(.{
            .name = "libgit2_tests",
            .root_module = runner,
        });
        runner.addIncludePath(clar_suite);
        runner.addIncludePath(clar_src);
        runner.addIncludePath(libgit_src.path("tests/libgit2"));

        runner.addConfigHeader(features);
        runner.addIncludePath(libgit_src.path("src/util"));
        runner.addIncludePath(libgit_src.path("src/libgit2"));

        runner.addIncludePath(libgit_src.path("deps/zlib"));
        runner.addIncludePath(libgit_src.path("deps/xdiff"));
        runner.addIncludePath(libgit_src.path("deps/pcre"));
        maybeAddTlsIncludes(runner, tls_dep, tls_backend);

        runner.linkLibrary(lib);

        const runner_flags = &.{
            "-DCLAR_FIXTURE_PATH", // See clar_fix step below
            "-DCLAR_TMPDIR=\"libgit2_tests\"",
            "-DCLAR_WIN32_LONGPATHS",
            "-DGIT_DEPRECATE_HARD",
        };
        runner.addCSourceFiles(.{
            .root = libgit_src.path("tests/libgit2"),
            .files = &sources.libgit2_test,
            .flags = runner_flags,
        });
        runner.addCSourceFiles(.{
            .root = clar_src,
            .files = &sources.clar,
            .flags = runner_flags,
        });

        const resources_dir = switch (@import("builtin").os.tag) {
            .windows => libgit_src.path("tests/resources"),
            else => dir: {
                // Fix the test fixture file permissions. This is necessary because Zig does
                // not respect the execute permission on arbitrary files it extracts from dependencies.
                // Since we need those files to have the execute permission set for tests to
                // run successfully, we need to patch them before we bake them into the
                // test executable.
                const resources_dir = b.addWriteFiles().addCopyDirectory(
                    libgit_src.path("tests/resources/"),
                    "test_resources",
                    .{},
                );
                const chmod = b.addExecutable(.{
                    .name = "chmod",
                    .root_module = b.createModule(.{
                        .root_source_file = b.path("build/chmod.zig"),
                        .target = b.graph.host,
                    }),
                });
                const run_chmod = b.addRunArtifact(chmod);
                run_chmod.addFileArg(resources_dir.path(b, "filemodes/exec_on"));
                run_chmod.addFileArg(resources_dir.path(b, "filemodes/exec_off2on_staged"));
                run_chmod.addFileArg(resources_dir.path(b, "filemodes/exec_off2on_workdir"));
                run_chmod.addFileArg(resources_dir.path(b, "filemodes/exec_on_untracked"));
                runner_exe.step.dependOn(&run_chmod.step);

                break :dir resources_dir;
            },
        };
        {
            // Clar hardcodes the path to resources_dir via the `-DCLAR_FIXTURE_PATH="..."` flag.
            // This path isn't known at configure-time, so we have to create a dedicated build step.
            // This step replaces *reads* of the `CLAR_FIXTURE_PATH` macro in a local-cache copy of the source code
            // (see clar_src). Thankfully the macro is only read by `tests/clar/clar/fixture.h` once.
            //
            // Additionally fixes a bug in tests/clar/clar.c where the stat type macros can be
            // mismatched when targeting windows (specifically mingw-w64), causing compile errors on zig 0.17.0.
            // @Todo remove this patch when updating upstream to 1.9.1 or later
            const clar_fix = b.addExecutable(.{
                .name = "clar_fix",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("build/clar_fix.zig"),
                    .target = b.graph.host,
                }),
            });

            const run_fix = b.addRunArtifact(clar_fix);
            run_fix.addFileArg(clar_src.path(b, "clar.c"));
            run_fix.addFileArg(clar_src.path(b, "clar/fixtures.h"));
            run_fix.addDirectoryArg(resources_dir);
            runner_exe.step.dependOn(&run_fix.step);
        }

        const TestHelper = struct {
            b: *std.Build,
            top_level_step: *Step,
            runner: *Step.Compile,
            clar_parser: *Step.Compile,
            const Step = std.Build.Step;

            fn addTest(
                self: @This(),
                name: []const u8,
                args: []const []const u8,
            ) void {
                const clar = self.createClarTestStep(name);
                clar.addArgs(args);
            }

            fn addTestFiltered(
                self: @This(),
                name: []const u8,
                /// Comma seperated list of tests
                tests: []const u8,
            ) void {
                const clar = self.createClarTestStep(name);
                var iter = std.mem.tokenizeScalar(u8, tests, ',');
                while (iter.next()) |filter| {
                    clar.addArg(self.b.fmt("-s{s}", .{filter}));
                }
            }

            fn createClarTestStep(self: @This(), name: []const u8) *Step.Run {
                const clar = self.b.addRunArtifact(self.clar_parser);
                self.top_level_step.dependOn(&clar.step);
                clar.setName(self.b.fmt("test-{s}", .{name}));
                clar.addArtifactArg(self.runner);
                return clar;
            }
        };

        const helper: TestHelper = .{
            .b = b,
            .top_level_step = test_step,
            .runner = runner_exe,
            .clar_parser = b.addExecutable(.{
                .name = "clar-parser",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("build/clar_parser.zig"),
                    .target = b.graph.host,
                    .optimize = .debug,
                }),
            }),
        };

        if (b.option([]const u8, "test-filter", "Comma seperated list of specific tests to run")) |tests| {
            helper.addTestFiltered("filtered", tests);
        } else if (b.option(bool, "test-offline", "Only run offline tests") orelse false) {
            helper.addTest("offline", &.{"-xonline"});
        } else {
            helper.addTest("offline", &.{
                "-xonline",
                // clone::nonetwork::bad_urls wastes a ton of time waiting for a connection to bogus URLs to timeout.
                // This can be easily fixed by manually setting the timeout to something reasonable using `git_libgit2_opts(GIT_OPT_SET_SERVER_CONNECT_TIMEOUT, ms);`
                // Because connect uses an exponential backoff, the test runner is usually sleeping for literal minutes! WTF!
                // On my machine, setting the timout to 1 second drops the test time from 2 minutes 14 seconds to *1.6 seconds*.
                // For everyone's sake, disable this test until the timeout is patched.
                "-xclone::nonetwork::bad_urls",
            });

            const only_offline = b.option(bool, "test-offline", "Only run offline tests") orelse false;
            if (!only_offline) {
                helper.addTest("auth_clone", &.{
                    "-sonline::clone::cred",
                    "-xonline::clone::credentials_via_custom_headers", // See comment below
                });
                helper.addTest("auth_clone_and_push", &.{ "-sonline::clone::push", "-sonline::push" });
                helper.addTest("gitdaemon", &.{"-sonline::push"});
                helper.addTest("gitdaemon_namespace", &.{"-sonline::clone::namespace"});
                helper.addTest("gitdaemon_sha256", &.{"-sonline::clone::sha256"});
                helper.addTest("invasive", &.{ "-sfilter::stream::bigfile", "-sodb::largefiles", "-siterator::workdir::filesystem_gunk", "-srepo::init", "-srepo::init::at_filesystem_root", "-sonline::clone::connect_timeout_default" });
                helper.addTest("online", &.{
                    "-sonline",
                    "-xonline::customcert",
                    // These tests are disabled because they try to connect to an outdated bitbucket repository.
                    // See https://github.com/libgit2/libgit2/pull/7326
                    "-xonline::clone::credentials_via_custom_headers",
                    "-xonline::clone::bitbucket_style",
                    "-xonline::clone::bitbucket_uses_creds_in_url",
                });
                helper.addTest("online_customcert", &.{"-sonline::customcert"});
                helper.addTest("proxy", &.{"-sonline::clone::proxy"});
                helper.addTest("ssh", &.{ "-sonline::push", "-sonline::clone::ssh_cert", "-sonline::clone::ssh_with_paths", "-sonline::clone::path_whitespace_ssh", "-sonline::clone::ssh_auth_methods" });
            }
        }
    }
}

// zig 0.17.0 and 0.16.0 compatible args passthrough function
inline fn passthroughArgs(b: *std.Build, run: *std.Build.Step.Run) void {
    if (comptime @import("builtin").zig_version.order(std.SemanticVersion.parse("0.16.0") catch unreachable) == .gt) {
        run.addPassthruArgs();
    } else {
        if (b.args) |args| {
            for (args) |arg| run.addArg(arg);
        }
    }
}

pub const TlsBackend = enum { openssl, mbedtls, securetransport };

fn maybeAddTlsIncludes(
    compile: *std.Build.Module,
    dep: ?*std.Build.Dependency,
    backend: TlsBackend,
) void {
    if (dep) |tls| {
        const name = switch (backend) {
            .securetransport => unreachable,
            .openssl => "openssl",
            .mbedtls => "mbedtls",
        };
        compile.addIncludePath(tls.artifact(name).getEmittedIncludeTree());
    }
}
