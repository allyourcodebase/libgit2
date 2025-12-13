const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const libgit_src = b.dependency("libgit2", .{});
    const libgit_root = libgit_src.path(".");

    const lib = b.addLibrary(.{
        .name = "git2",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
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
            lib.linkSystemLibrary("iconv");
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
        lib.linkSystemLibrary("winhttp");
        lib.linkSystemLibrary("rpcrt4");
        lib.linkSystemLibrary("crypt32");
        lib.linkSystemLibrary("ole32");
        lib.linkSystemLibrary("ws2_32");
        lib.linkSystemLibrary("secur32");

        features.addValues(.{
            .GIT_HTTPS = 1,
            .GIT_WINHTTP = 1,

            .GIT_SHA1_COLLISIONDETECT = 1,
            .GIT_SHA256_WIN32 = 1,

            .GIT_IO_WSAPOLL = 1,
        });

        lib.addWin32ResourceFile(.{ .file = libgit_src.path("src/libgit2/git2.rc") });
        lib.addCSourceFiles(.{ .root = libgit_root, .files = &util_win32_sources, .flags = &flags });
    } else {
        switch (tls_backend) {
            .securetransport => {
                lib.linkFramework("Security");
                lib.linkFramework("CoreFoundation");
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
                tls_dep = b.lazyDependency("openssl", .{
                    .target = target,
                    .optimize = optimize,
                });
                if (tls_dep) |tls| lib.linkLibrary(tls.artifact("openssl"));
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
                tls_dep = b.lazyDependency("mbedtls", .{
                    .target = target,
                    .optimize = optimize,
                });
                if (tls_dep) |tls| lib.linkLibrary(tls.artifact("mbedtls"));
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
            const ntlm = b.addLibrary(.{
                .name = "ntlmclient",
                .linkage = .static,
                .root_module = b.createModule(.{
                    .target = target,
                    .optimize = optimize,
                    .link_libc = true,
                }),
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
                .root = libgit_root,
                .files = switch (tls_backend) {
                    .openssl => &.{"deps/ntlmclient/crypt_openssl.c"},
                    .mbedtls => &.{"deps/ntlmclient/crypt_mbedtls.c"},
                    .securetransport => &.{"deps/ntlmclient/crypt_commoncrypto.c"},
                },
                .flags = &ntlm_cflags,
            });
            ntlm.addCSourceFiles(.{
                .root = libgit_root,
                .files = &ntlm_sources,
                .flags = &(ntlm_cflags ++ .{"-Wno-deprecated"}),
            });

            lib.linkLibrary(ntlm);
            lib.addAfterIncludePath(libgit_src.path("deps/ntlmclient")); // avoid aliasing ntlmclient/util.h and src/util/util.h
            features.addValues(.{ .GIT_NTLM = 1 });
        }

        lib.addCSourceFiles(.{
            .root = libgit_root,
            .files = &util_unix_sources,
            .flags = &flags,
        });
        lib.addCSourceFiles(.{
            .root = libgit_root,
            .files = switch (tls_backend) {
                .openssl => &.{"src/util/hash/openssl.c"},
                .mbedtls => &.{"src/util/hash/mbedtls.c"},
                .securetransport => &.{"src/util/hash/common_crypto.c"},
            },
            .flags = &flags,
        });
    }

    // SHA1 collisiondetect
    lib.addCSourceFiles(.{
        .root = libgit_root,
        .files = &util_sha1dc_sources,
        .flags = &(flags ++ .{
            "-DSHA1DC_NO_STANDARD_INCLUDES",
            "-DSHA1DC_CUSTOM_INCLUDE_SHA1_C=\"git2_util.h\"",
            "-DSHA1DC_CUSTOM_INCLUDE_UBC_CHECK_C=\"git2_util.h\"",
        }),
    });

    if (b.option(bool, "enable-ssh", "Enable SSH support") orelse false) {
        lib.linkSystemLibrary("ssh2");
        features.addValues(.{
            .GIT_SSH = 1,
            .GIT_SSH_LIBSSH2 = 1,
            .GIT_SSH_LIBSSH2_MEMORY_CREDENTIALS = 1, // @Todo: check for `libssh2_userauth_publickey_frommemory`?
        });
    }

    // Bundled dependencies
    {
        const llhttp = b.addLibrary(.{
            .name = "llhttp",
            .linkage = .static,
            .root_module = b.createModule(.{
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            }),
        });
        llhttp.addIncludePath(libgit_src.path("deps/llhttp"));
        llhttp.addCSourceFiles(.{
            .root = libgit_root,
            .files = &llhttp_sources,
            .flags = &.{ "-Wno-unused-parameter", "-Wno-missing-declarations" },
        });

        lib.addIncludePath(libgit_src.path("deps/llhttp"));
        lib.linkLibrary(llhttp);
        features.addValues(.{ .GIT_HTTPPARSER_BUILTIN = 1 });
    }
    if (target.result.os.tag != .macos) {
        const pcre = b.addLibrary(.{
            .name = "pcre",
            .linkage = .static,
            .root_module = b.createModule(.{
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            }),
        });
        pcre.root_module.addConfigHeader(b.addConfigHeader(
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
            .root = libgit_root,
            .files = &pcre_sources,
            .flags = &.{
                "-Wno-unused-function",
                "-Wno-implicit-fallthrough",
                "-DHAVE_CONFIG_H",
            },
        });

        lib.addIncludePath(libgit_src.path("deps/pcre"));
        lib.linkLibrary(pcre);
        features.addValues(.{ .GIT_REGEX_BUILTIN = 1 });
    }
    {
        // @Todo: support using system zlib?
        const zlib = b.addLibrary(.{
            .name = "z",
            .linkage = .static,
            .root_module = b.createModule(.{
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            }),
        });
        zlib.addIncludePath(libgit_src.path("deps/zlib"));
        zlib.addCSourceFiles(.{
            .root = libgit_root,
            .files = &zlib_sources,
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

        lib.addIncludePath(libgit_src.path("deps/zlib"));
        lib.linkLibrary(zlib);
        features.addValues(.{ .GIT_COMPRESSION_ZLIB = 1 });
    }
    // xdiff
    {
        // Bundled xdiff dependency relies on libgit2 headers & utils, so we
        // just add the source files directly instead of making a static lib step.
        lib.addCSourceFiles(.{
            .root = libgit_root,
            .files = &xdiff_sources,
            .flags = &.{ "-Wno-sign-compare", "-Wno-unused-parameter" },
        });
        lib.addIncludePath(libgit_src.path("deps/xdiff"));
    }

    switch (target.result.ptrBitWidth()) {
        32 => features.addValues(.{ .GIT_ARCH_32 = 1 }),
        64 => features.addValues(.{ .GIT_ARCH_64 = 1 }),
        else => |size| std.debug.panic("Unsupported architecture ({d}bit)", .{size}),
    }

    lib.addConfigHeader(features);

    lib.addIncludePath(libgit_src.path("src/libgit2"));
    lib.addIncludePath(libgit_src.path("src/util"));
    lib.addIncludePath(libgit_src.path("include"));

    lib.addCSourceFiles(.{ .root = libgit_root, .files = &libgit_sources, .flags = &flags });
    lib.addCSourceFiles(.{ .root = libgit_root, .files = &util_sources, .flags = &flags });

    lib.installHeadersDirectory(libgit_src.path("include"), "", .{});
    b.installArtifact(lib);

    const cli_step = b.step("run-cli", "Build and run the command-line interface");
    {
        const cli = b.addExecutable(.{
            .name = "git2_cli",
            .root_module = b.createModule(.{
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            }),
        });

        cli.addConfigHeader(features);
        cli.addIncludePath(libgit_src.path("src/util"));
        cli.addIncludePath(libgit_src.path("src/cli"));
        maybeAddTlsIncludes(cli, tls_dep, tls_backend);

        cli.linkLibrary(lib);
        cli.addCSourceFiles(.{
            .root = libgit_root,
            .files = &cli_sources,
            // @Todo: see above
            // .flags = &.{"-std=c90"},
        });
        cli.addCSourceFiles(.{
            .root = libgit_root,
            .files = if (target.result.os.tag == .windows)
                &.{"src/cli/win32/sighandler.c"}
            else
                &.{"src/cli/unix/sighandler.c"},
        });

        // independent install step so you can easily access the binary
        const cli_install = b.addInstallArtifact(cli, .{});
        const cli_run = b.addRunArtifact(cli);
        if (b.args) |args| {
            for (args) |arg| cli_run.addArg(arg);
        }
        cli_run.step.dependOn(&cli_install.step);
        cli_step.dependOn(&cli_run.step);
    }

    const examples_step = b.step("run-example", "Build and run library usage example app");
    {
        const exe = b.addExecutable(.{
            .name = "lg2",
            .root_module = b.createModule(.{
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            }),
        });

        exe.addIncludePath(libgit_src.path("examples"));
        exe.addCSourceFiles(.{
            .root = libgit_root,
            .files = &example_sources,
            .flags = &.{
                // "-std=c90",
                "-DGIT_DEPRECATE_HARD",
            },
        });

        maybeAddTlsIncludes(exe, tls_dep, tls_backend);
        exe.linkLibrary(lib);

        // independent install step so you can easily access the binary
        const examples_install = b.addInstallArtifact(exe, .{});
        const example_run = b.addRunArtifact(exe);
        if (b.args) |args| {
            for (args) |arg| example_run.addArg(arg);
        }
        example_run.step.dependOn(&examples_install.step);
        examples_step.dependOn(&example_run.step);
    }

    const test_step = b.step("test", "Run core unit tests (requires python)");
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

        const runner = b.addExecutable(.{
            .name = "libgit2_tests",
            .root_module = b.createModule(.{
                .target = target,
                .optimize = .Debug,
                .link_libc = true,
            }),
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
            .root = libgit_src.path("tests/libgit2/"),
            .files = &libgit2_test_sources,
            .flags = runner_flags,
        });
        runner.addCSourceFiles(.{
            .root = clar_src,
            .files = &clar_sources,
            .flags = runner_flags,
        });

        const resources_dir = switch (@import("builtin").os.tag) {
            .windows => libgit_src.path("tests/resources/"),
            else => dir: {
                // Fix the test fixture file permissions. This is necessary because Zig does
                // not respect the execute permission on arbitrary files it extracts from dependencies.
                // Since we need those files to have the execute permission set for tests to
                // run successfully, we need to patch them before we bake them into the
                // test executable.
                const resources_dir = b.addWriteFiles().addCopyDirectory(
                    libgit_root.path(b, "tests/resources/"),
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
                runner.step.dependOn(&run_chmod.step);

                break :dir resources_dir;
            },
        };
        {
            // Clar hardcodes the path to resources_dir via the `-DCLAR_FIXTURE_PATH="..."` flag.
            // This path isn't known at configure-time, so we have to create a dedicated build step.
            // This step replaces *reads* of the `CLAR_FIXTURE_PATH` macro in a local-cache copy of the source code
            // (see clar_src). Thankfully the macro is only read by `tests/clar/clar/fixture.h` once.
            const clar_fix = b.addExecutable(.{
                .name = "clar_fix",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("build/clar_fix.zig"),
                    .target = b.graph.host,
                }),
            });

            const run_fix = b.addRunArtifact(clar_fix);
            // run_fix.has_side_effects = true; // @Todo is this necessary? What are the rules for cache invalidation with Run steps?
            run_fix.addFileArg(clar_src.path(b, "clar/fixtures.h"));
            run_fix.addDirectoryArg(resources_dir);
            runner.step.dependOn(&run_fix.step);
        }

        const TestHelper = struct {
            b: *std.Build,
            top_level_step: *std.Build.Step,
            runner: *std.Build.Step.Compile,

            const ClarStep = @import("build/ClarTestStep.zig");

            fn addTest(
                self: @This(),
                name: []const u8,
                args: []const []const u8,
            ) void {
                const clar = ClarStep.create(self.b, name, self.runner);
                self.top_level_step.dependOn(&clar.step);
                clar.addArgs(args);
            }

            fn addTestFiltered(
                self: @This(),
                name: []const u8,
                /// Comma seperated list of tests
                tests: []const u8,
            ) void {
                const clar = ClarStep.create(self.b, name, self.runner);
                self.top_level_step.dependOn(&clar.step);
                var iter = std.mem.tokenizeScalar(u8, tests, ',');
                while (iter.next()) |filter| {
                    clar.addArg(self.b.fmt("-s{s}", .{filter}));
                }
            }
        };

        const helper: TestHelper = .{
            .b = b,
            .top_level_step = test_step,
            .runner = runner,
        };

        if (b.option([]const u8, "test-filter", "Comma seperated list of specific tests to run")) |tests| {
            helper.addTestFiltered("filtered", tests);
        } else {
            helper.addTest("auth_clone", &.{"-sonline::clone::cred"});
            helper.addTest("auth_clone_and_push", &.{ "-sonline::clone::push", "-sonline::push" });
            helper.addTest("gitdaemon", &.{"-sonline::push"});
            helper.addTest("gitdaemon_namespace", &.{"-sonline::clone::namespace"});
            helper.addTest("gitdaemon_sha256", &.{"-sonline::clone::sha256"});
            helper.addTest("invasive", &.{ "-sfilter::stream::bigfile", "-sodb::largefiles", "-siterator::workdir::filesystem_gunk", "-srepo::init", "-srepo::init::at_filesystem_root", "-sonline::clone::connect_timeout_default" });
            helper.addTest("offline", &.{"-xonline"});
            helper.addTest("online", &.{ "-sonline", "-xonline::customcert" });
            helper.addTest("online_customcert", &.{"-sonline::customcert"});
            helper.addTest("proxy", &.{"-sonline::clone::proxy"});
            helper.addTest("ssh", &.{ "-sonline::push", "-sonline::clone::ssh_cert", "-sonline::clone::ssh_with_paths", "-sonline::clone::path_whitespace_ssh", "-sonline::clone::ssh_auth_methods" });
        }
    }
}

pub const TlsBackend = enum { openssl, mbedtls, securetransport };

fn maybeAddTlsIncludes(
    compile: *std.Build.Step.Compile,
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

const libgit_sources = [_][]const u8{
    "src/libgit2/annotated_commit.c",
    "src/libgit2/apply.c",
    "src/libgit2/attr.c",
    "src/libgit2/attr_file.c",
    "src/libgit2/attrcache.c",
    "src/libgit2/blame.c",
    "src/libgit2/blame_git.c",
    "src/libgit2/blob.c",
    "src/libgit2/branch.c",
    "src/libgit2/buf.c",
    "src/libgit2/cache.c",
    "src/libgit2/checkout.c",
    "src/libgit2/cherrypick.c",
    "src/libgit2/clone.c",
    "src/libgit2/commit.c",
    "src/libgit2/commit_graph.c",
    "src/libgit2/commit_list.c",
    "src/libgit2/config.c",
    "src/libgit2/config_cache.c",
    "src/libgit2/config_file.c",
    "src/libgit2/config_list.c",
    "src/libgit2/config_mem.c",
    "src/libgit2/config_parse.c",
    "src/libgit2/config_snapshot.c",
    "src/libgit2/crlf.c",
    "src/libgit2/delta.c",
    "src/libgit2/describe.c",
    "src/libgit2/diff.c",
    "src/libgit2/diff_driver.c",
    "src/libgit2/diff_file.c",
    "src/libgit2/diff_generate.c",
    "src/libgit2/diff_parse.c",
    "src/libgit2/diff_print.c",
    "src/libgit2/diff_stats.c",
    "src/libgit2/diff_tform.c",
    "src/libgit2/diff_xdiff.c",
    "src/libgit2/email.c",
    "src/libgit2/fetch.c",
    "src/libgit2/fetchhead.c",
    "src/libgit2/filter.c",
    "src/libgit2/grafts.c",
    "src/libgit2/graph.c",
    "src/libgit2/hashsig.c",
    "src/libgit2/ident.c",
    "src/libgit2/ignore.c",
    "src/libgit2/index.c",
    "src/libgit2/index_map.c",
    "src/libgit2/indexer.c",
    "src/libgit2/iterator.c",
    "src/libgit2/libgit2.c",
    "src/libgit2/mailmap.c",
    "src/libgit2/merge.c",
    "src/libgit2/merge_driver.c",
    "src/libgit2/merge_file.c",
    "src/libgit2/message.c",
    "src/libgit2/midx.c",
    "src/libgit2/mwindow.c",
    "src/libgit2/notes.c",
    "src/libgit2/object.c",
    "src/libgit2/object_api.c",
    "src/libgit2/odb.c",
    "src/libgit2/odb_loose.c",
    "src/libgit2/odb_mempack.c",
    "src/libgit2/odb_pack.c",
    "src/libgit2/oid.c",
    "src/libgit2/oidarray.c",
    "src/libgit2/pack-objects.c",
    "src/libgit2/pack.c",
    "src/libgit2/parse.c",
    "src/libgit2/patch.c",
    "src/libgit2/patch_generate.c",
    "src/libgit2/patch_parse.c",
    "src/libgit2/path.c",
    "src/libgit2/pathspec.c",
    "src/libgit2/proxy.c",
    "src/libgit2/push.c",
    "src/libgit2/reader.c",
    "src/libgit2/rebase.c",
    "src/libgit2/refdb.c",
    "src/libgit2/refdb_fs.c",
    "src/libgit2/reflog.c",
    "src/libgit2/refs.c",
    "src/libgit2/refspec.c",
    "src/libgit2/remote.c",
    "src/libgit2/repository.c",
    "src/libgit2/reset.c",
    "src/libgit2/revert.c",
    "src/libgit2/revparse.c",
    "src/libgit2/revwalk.c",
    "src/libgit2/settings.c",
    "src/libgit2/signature.c",
    "src/libgit2/stash.c",
    "src/libgit2/status.c",
    "src/libgit2/strarray.c",
    "src/libgit2/streams/mbedtls.c",
    "src/libgit2/streams/openssl.c",
    "src/libgit2/streams/openssl_dynamic.c",
    "src/libgit2/streams/openssl_legacy.c",
    "src/libgit2/streams/registry.c",
    "src/libgit2/streams/schannel.c",
    "src/libgit2/streams/socket.c",
    "src/libgit2/streams/stransport.c",
    "src/libgit2/streams/tls.c",
    "src/libgit2/submodule.c",
    "src/libgit2/sysdir.c",
    "src/libgit2/tag.c",
    "src/libgit2/trace.c",
    "src/libgit2/trailer.c",
    "src/libgit2/transaction.c",
    "src/libgit2/transport.c",
    "src/libgit2/transports/auth.c",
    "src/libgit2/transports/auth_gssapi.c",
    "src/libgit2/transports/auth_ntlmclient.c",
    "src/libgit2/transports/auth_sspi.c",
    "src/libgit2/transports/credential.c",
    "src/libgit2/transports/credential_helpers.c",
    "src/libgit2/transports/git.c",
    "src/libgit2/transports/http.c",
    "src/libgit2/transports/httpclient.c",
    "src/libgit2/transports/httpparser.c",
    "src/libgit2/transports/local.c",
    "src/libgit2/transports/smart.c",
    "src/libgit2/transports/smart_pkt.c",
    "src/libgit2/transports/smart_protocol.c",
    "src/libgit2/transports/ssh.c",
    "src/libgit2/transports/ssh_exec.c",
    "src/libgit2/transports/ssh_libssh2.c",
    "src/libgit2/transports/winhttp.c",
    "src/libgit2/tree-cache.c",
    "src/libgit2/tree.c",
    "src/libgit2/worktree.c",
};

const util_sources = [_][]const u8{
    "src/util/alloc.c",
    "src/util/allocators/debugalloc.c",
    "src/util/allocators/failalloc.c",
    "src/util/allocators/stdalloc.c",
    "src/util/allocators/win32_leakcheck.c",
    "src/util/date.c",
    "src/util/errors.c",
    "src/util/filebuf.c",
    "src/util/fs_path.c",
    "src/util/futils.c",
    "src/util/hash.c",
    "src/util/net.c",
    "src/util/pool.c",
    "src/util/posix.c",
    "src/util/pqueue.c",
    "src/util/rand.c",
    "src/util/regexp.c",
    "src/util/runtime.c",
    "src/util/sortedcache.c",
    "src/util/str.c",
    "src/util/strlist.c",
    "src/util/thread.c",
    "src/util/tsort.c",
    "src/util/utf8.c",
    "src/util/util.c",
    "src/util/varint.c",
    "src/util/vector.c",
    "src/util/wildmatch.c",
    "src/util/zstream.c",
};

const util_unix_sources = [_][]const u8{
    "src/util/unix/map.c",
    "src/util/unix/process.c",
    "src/util/unix/realpath.c",
};

const util_win32_sources = [_][]const u8{
    "src/util/win32/dir.c",
    "src/util/win32/error.c",
    "src/util/win32/map.c",
    "src/util/win32/path_w32.c",
    "src/util/win32/posix_w32.c",
    "src/util/win32/precompiled.c",
    "src/util/win32/process.c",
    "src/util/win32/thread.c",
    "src/util/win32/utf-conv.c",
    "src/util/win32/w32_buffer.c",
    "src/util/win32/w32_leakcheck.c",
    "src/util/win32/w32_util.c",

    "src/util/hash/win32.c",
};

const util_sha1dc_sources = [_][]const u8{
    "src/util/hash/collisiondetect.c",
    "src/util/hash/sha1dc/sha1.c",
    "src/util/hash/sha1dc/ubc_check.c",
};

const llhttp_sources = [_][]const u8{
    "deps/llhttp/api.c",
    "deps/llhttp/http.c",
    "deps/llhttp/llhttp.c",
};

const pcre_sources = [_][]const u8{
    "deps/pcre/pcre_byte_order.c",
    "deps/pcre/pcre_chartables.c",
    "deps/pcre/pcre_compile.c",
    "deps/pcre/pcre_config.c",
    "deps/pcre/pcre_dfa_exec.c",
    "deps/pcre/pcre_exec.c",
    "deps/pcre/pcre_fullinfo.c",
    "deps/pcre/pcre_get.c",
    "deps/pcre/pcre_globals.c",
    "deps/pcre/pcre_jit_compile.c",
    "deps/pcre/pcre_maketables.c",
    "deps/pcre/pcre_newline.c",
    "deps/pcre/pcre_ord2utf8.c",
    "deps/pcre/pcre_printint.c",
    "deps/pcre/pcre_refcount.c",
    "deps/pcre/pcre_string_utils.c",
    "deps/pcre/pcre_study.c",
    "deps/pcre/pcre_tables.c",
    "deps/pcre/pcre_ucd.c",
    "deps/pcre/pcre_valid_utf8.c",
    "deps/pcre/pcre_version.c",
    "deps/pcre/pcre_xclass.c",
    "deps/pcre/pcreposix.c",
};

const zlib_sources = [_][]const u8{
    "deps/zlib/adler32.c",
    "deps/zlib/crc32.c",
    "deps/zlib/deflate.c",
    "deps/zlib/infback.c",
    "deps/zlib/inffast.c",
    "deps/zlib/inflate.c",
    "deps/zlib/inftrees.c",
    "deps/zlib/trees.c",
    "deps/zlib/zutil.c",
};

const xdiff_sources = [_][]const u8{
    "deps/xdiff/xdiffi.c",
    "deps/xdiff/xemit.c",
    "deps/xdiff/xhistogram.c",
    "deps/xdiff/xmerge.c",
    "deps/xdiff/xpatience.c",
    "deps/xdiff/xprepare.c",
    "deps/xdiff/xutils.c",
};

const ntlm_sources = [_][]const u8{
    "deps/ntlmclient/crypt_builtin_md4.c",
    "deps/ntlmclient/ntlm.c",
    "deps/ntlmclient/unicode_builtin.c",
    "deps/ntlmclient/util.c",
};

const cli_sources = [_][]const u8{
    "src/cli/cmd.c",
    "src/cli/cmd_blame.c",
    "src/cli/cmd_cat_file.c",
    "src/cli/cmd_clone.c",
    "src/cli/cmd_config.c",
    "src/cli/cmd_hash_object.c",
    "src/cli/cmd_help.c",
    "src/cli/cmd_index_pack.c",
    "src/cli/cmd_init.c",
    "src/cli/common.c",
    "src/cli/main.c",
    "src/cli/opt.c",
    "src/cli/opt_usage.c",
    "src/cli/progress.c",
};

const example_sources = [_][]const u8{
    "examples/add.c",
    "examples/args.c",
    "examples/blame.c",
    "examples/cat-file.c",
    "examples/checkout.c",
    "examples/clone.c",
    "examples/commit.c",
    "examples/common.c",
    "examples/config.c",
    "examples/describe.c",
    "examples/diff.c",
    "examples/fetch.c",
    "examples/for-each-ref.c",
    "examples/general.c",
    "examples/index-pack.c",
    "examples/init.c",
    "examples/lg2.c",
    "examples/log.c",
    "examples/ls-files.c",
    "examples/ls-remote.c",
    "examples/merge.c",
    "examples/push.c",
    "examples/remote.c",
    "examples/rev-list.c",
    "examples/rev-parse.c",
    "examples/show-index.c",
    "examples/stash.c",
    "examples/status.c",
    "examples/tag.c",
};

const clar_sources = [_][]const u8{
    "clar.c",
    "clar_libgit2.c",
    "clar_libgit2_alloc.c",
    "clar_libgit2_timer.c",
    "clar_libgit2_trace.c",
    "main.c",
};

const libgit2_test_sources = [_][]const u8{
    "apply/apply_helpers.c",
    "apply/both.c",
    "apply/callbacks.c",
    "apply/check.c",
    "apply/fromdiff.c",
    "apply/fromfile.c",
    "apply/index.c",
    "apply/partial.c",
    "apply/tree.c",
    "apply/workdir.c",
    "attr/file.c",
    "attr/flags.c",
    "attr/lookup.c",
    "attr/macro.c",
    "attr/repo.c",
    "blame/blame_helpers.c",
    "blame/buffer.c",
    "blame/getters.c",
    "blame/harder.c",
    "blame/simple.c",
    "checkout/binaryunicode.c",
    "checkout/checkout_helpers.c",
    "checkout/conflict.c",
    "checkout/crlf.c",
    "checkout/head.c",
    "checkout/icase.c",
    "checkout/index.c",
    "checkout/nasty.c",
    "checkout/tree.c",
    "checkout/typechange.c",
    "cherrypick/bare.c",
    "cherrypick/workdir.c",
    "clone/empty.c",
    "clone/local.c",
    "clone/nonetwork.c",
    "clone/transport.c",
    "commit/commit.c",
    "commit/create.c",
    "commit/parent.c",
    "commit/parse.c",
    "commit/signature.c",
    "commit/write.c",
    "config/add.c",
    "config/backend.c",
    "config/conditionals.c",
    "config/config_helpers.c",
    "config/configlevel.c",
    "config/find.c",
    "config/global.c",
    "config/include.c",
    "config/memory.c",
    "config/multivar.c",
    "config/new.c",
    "config/read.c",
    "config/readonly.c",
    "config/rename.c",
    "config/snapshot.c",
    "config/stress.c",
    "config/validkeyname.c",
    "config/write.c",
    "core/buf.c",
    "core/env.c",
    "core/features.c",
    "core/hashsig.c",
    "core/oid.c",
    "core/oidarray.c",
    "core/opts.c",
    "core/pool.c",
    "core/structinit.c",
    "core/useragent.c",
    "core/version.c",
    "date/date.c",
    "date/rfc2822.c",
    "delta/apply.c",
    "describe/describe.c",
    "describe/describe_helpers.c",
    "describe/t6120.c",
    "diff/binary.c",
    "diff/blob.c",
    "diff/diff_helpers.c",
    "diff/diffiter.c",
    "diff/drivers.c",
    "diff/externalmodifications.c",
    "diff/format_email.c",
    "diff/header.c",
    "diff/index.c",
    "diff/notify.c",
    "diff/parse.c",
    "diff/patch.c",
    "diff/patchid.c",
    "diff/pathspec.c",
    "diff/racediffiter.c",
    "diff/rename.c",
    "diff/stats.c",
    "diff/submodules.c",
    "diff/tree.c",
    "diff/userdiff.c",
    "diff/workdir.c",
    "email/create.c",
    "fetch/local.c",
    "fetchhead/nonetwork.c",
    "filter/bare.c",
    "filter/blob.c",
    "filter/crlf.c",
    "filter/custom.c",
    "filter/custom_helpers.c",
    "filter/file.c",
    "filter/ident.c",
    "filter/query.c",
    "filter/stream.c",
    "filter/systemattrs.c",
    "filter/wildcard.c",
    "grafts/basic.c",
    "grafts/parse.c",
    "grafts/shallow.c",
    "graph/ahead_behind.c",
    "graph/commitgraph.c",
    "graph/descendant_of.c",
    "graph/reachable_from_any.c",
    "ignore/path.c",
    "ignore/status.c",
    "index/add.c",
    "index/addall.c",
    "index/bypath.c",
    "index/cache.c",
    "index/collision.c",
    "index/conflicts.c",
    "index/crlf.c",
    "index/filemodes.c",
    "index/inmemory.c",
    "index/names.c",
    "index/nsec.c",
    "index/racy.c",
    "index/read_index.c",
    "index/read_tree.c",
    "index/rename.c",
    "index/reuc.c",
    "index/splitindex.c",
    "index/stage.c",
    "index/tests.c",
    "index/tests256.c",
    "index/version.c",
    "iterator/index.c",
    "iterator/iterator_helpers.c",
    "iterator/tree.c",
    "iterator/workdir.c",
    "mailmap/basic.c",
    "mailmap/blame.c",
    "mailmap/parsing.c",
    "merge/analysis.c",
    "merge/annotated_commit.c",
    "merge/driver.c",
    "merge/files.c",
    "merge/merge_helpers.c",
    "merge/trees/automerge.c",
    "merge/trees/commits.c",
    "merge/trees/modeconflict.c",
    "merge/trees/recursive.c",
    "merge/trees/renames.c",
    "merge/trees/treediff.c",
    "merge/trees/trivial.c",
    "merge/trees/whitespace.c",
    "merge/workdir/dirty.c",
    "merge/workdir/recursive.c",
    "merge/workdir/renames.c",
    "merge/workdir/setup.c",
    "merge/workdir/simple.c",
    "merge/workdir/submodules.c",
    "merge/workdir/trivial.c",
    "message/trailer.c",
    "network/cred.c",
    "network/fetchlocal.c",
    "network/refspecs.c",
    "network/remote/defaultbranch.c",
    "network/remote/delete.c",
    "network/remote/isvalidname.c",
    "network/remote/local.c",
    "network/remote/push.c",
    "network/remote/remotes.c",
    "network/remote/rename.c",
    "network/remote/tag.c",
    "notes/notes.c",
    "notes/notesref.c",
    "object/blob/filter.c",
    "object/blob/fromstream.c",
    "object/blob/write.c",
    "object/cache.c",
    "object/commit/commitstagedfile.c",
    "object/commit/parse.c",
    "object/lookup.c",
    "object/lookup256.c",
    "object/lookupbypath.c",
    "object/message.c",
    "object/peel.c",
    "object/raw/chars.c",
    "object/raw/compare.c",
    "object/raw/convert.c",
    "object/raw/fromstr.c",
    "object/raw/hash.c",
    "object/raw/short.c",
    "object/raw/size.c",
    "object/raw/type2string.c",
    "object/raw/write.c",
    "object/shortid.c",
    "object/tag/list.c",
    "object/tag/parse.c",
    "object/tag/peel.c",
    "object/tag/read.c",
    "object/tag/write.c",
    "object/tree/attributes.c",
    "object/tree/duplicateentries.c",
    "object/tree/frompath.c",
    "object/tree/parse.c",
    "object/tree/read.c",
    "object/tree/update.c",
    "object/tree/walk.c",
    "object/tree/write.c",
    "object/validate.c",
    "odb/alternates.c",
    "odb/backend/backend_helpers.c",
    "odb/backend/loose.c",
    "odb/backend/mempack.c",
    "odb/backend/multiple.c",
    "odb/backend/nobackend.c",
    "odb/backend/nonrefreshing.c",
    "odb/backend/refreshing.c",
    "odb/backend/simple.c",
    "odb/emptyobjects.c",
    "odb/foreach.c",
    "odb/freshen.c",
    "odb/largefiles.c",
    "odb/loose.c",
    "odb/mixed.c",
    "odb/open.c",
    "odb/packed.c",
    "odb/packed256.c",
    "odb/packedone.c",
    "odb/packedone256.c",
    "odb/sorting.c",
    "odb/streamwrite.c",
    "online/badssl.c",
    "online/clone.c",
    "online/customcert.c",
    "online/fetch.c",
    "online/fetchhead.c",
    "online/push.c",
    "online/push_util.c",
    "online/remotes.c",
    "online/shallow.c",
    "pack/filelimit.c",
    "pack/indexer.c",
    "pack/midx.c",
    "pack/packbuilder.c",
    "pack/sharing.c",
    "pack/threadsafety.c",
    "patch/parse.c",
    "patch/print.c",
    "path/validate.c",
    "perf/helper__perf__do_merge.c",
    "perf/helper__perf__timer.c",
    "perf/merge.c",
    "precompiled.c",
    "rebase/abort.c",
    "rebase/inmemory.c",
    "rebase/iterator.c",
    "rebase/merge.c",
    "rebase/setup.c",
    "rebase/sign.c",
    "rebase/submodule.c",
    "refs/basic.c",
    "refs/branches/checkedout.c",
    "refs/branches/create.c",
    "refs/branches/delete.c",
    "refs/branches/ishead.c",
    "refs/branches/iterator.c",
    "refs/branches/lookup.c",
    "refs/branches/move.c",
    "refs/branches/name.c",
    "refs/branches/remote.c",
    "refs/branches/upstream.c",
    "refs/branches/upstreamname.c",
    "refs/crashes.c",
    "refs/create.c",
    "refs/delete.c",
    "refs/dup.c",
    "refs/foreachglob.c",
    "refs/isvalidname.c",
    "refs/iterator.c",
    "refs/list.c",
    "refs/listall.c",
    "refs/lookup.c",
    "refs/namespaces.c",
    "refs/normalize.c",
    "refs/overwrite.c",
    "refs/pack.c",
    "refs/peel.c",
    "refs/races.c",
    "refs/read.c",
    "refs/ref_helpers.c",
    "refs/reflog/drop.c",
    "refs/reflog/messages.c",
    "refs/reflog/reflog.c",
    "refs/reflog/reflog_helpers.c",
    "refs/rename.c",
    "refs/revparse.c",
    "refs/setter.c",
    "refs/shorthand.c",
    "refs/tags/name.c",
    "refs/transactions.c",
    "refs/unicode.c",
    "refs/update.c",
    "remote/create.c",
    "remote/fetch.c",
    "remote/httpproxy.c",
    "remote/insteadof.c",
    "remote/list.c",
    "repo/config.c",
    "repo/discover.c",
    "repo/env.c",
    "repo/extensions.c",
    "repo/getters.c",
    "repo/hashfile.c",
    "repo/head.c",
    "repo/headtree.c",
    "repo/init.c",
    "repo/message.c",
    "repo/new.c",
    "repo/objectformat.c",
    "repo/open.c",
    "repo/pathspec.c",
    "repo/repo_helpers.c",
    "repo/reservedname.c",
    "repo/setters.c",
    "repo/shallow.c",
    "repo/state.c",
    "repo/template.c",
    "reset/default.c",
    "reset/hard.c",
    "reset/mixed.c",
    "reset/reset_helpers.c",
    "reset/soft.c",
    "revert/bare.c",
    "revert/rename.c",
    "revert/workdir.c",
    "revwalk/basic.c",
    "revwalk/hidecb.c",
    "revwalk/mergebase.c",
    "revwalk/signatureparsing.c",
    "revwalk/simplify.c",
    "stash/apply.c",
    "stash/drop.c",
    "stash/foreach.c",
    "stash/save.c",
    "stash/stash_helpers.c",
    "stash/submodules.c",
    "status/renames.c",
    "status/single.c",
    "status/status_helpers.c",
    "status/submodules.c",
    "status/worktree.c",
    "status/worktree_init.c",
    "stream/deprecated.c",
    "stream/registration.c",
    "stress/diff.c",
    "submodule/add.c",
    "submodule/escape.c",
    "submodule/init.c",
    "submodule/inject_option.c",
    "submodule/lookup.c",
    "submodule/modify.c",
    "submodule/nosubs.c",
    "submodule/open.c",
    "submodule/repository_init.c",
    "submodule/status.c",
    "submodule/submodule_helpers.c",
    "submodule/update.c",
    "threads/atomic.c",
    "threads/basic.c",
    "threads/diff.c",
    "threads/iterator.c",
    "threads/refdb.c",
    "threads/thread_helpers.c",
    "threads/tlsdata.c",
    "trace/trace.c",
    "trace/windows/stacktrace.c",
    "transport/register.c",
    "transport/ssh_exec.c",
    "transports/smart/packet.c",
    "win32/forbidden.c",
    "win32/longpath.c",
    "win32/systemdir.c",
    "worktree/bare.c",
    "worktree/config.c",
    "worktree/merge.c",
    "worktree/open.c",
    "worktree/reflog.c",
    "worktree/refs.c",
    "worktree/repository.c",
    "worktree/submodule.c",
    "worktree/worktree.c",
    "worktree/worktree_helpers.c",
};
