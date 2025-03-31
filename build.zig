const std = @import("std");
const builtin = @import("builtin");

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
        if (builtin.os.tag != .windows) {
            // Fix the test fixture file permissions. This is necessary because Zig does
            // not respect the execute permission on arbitrary files it extracts from dependencies.
            // Since we need those files to have the execute permission set for tests to
            // run successfully, we need to patch them before we bake them into the
            // test executable. While modifying the global cache is hacky, it wont break
            // hashes for the same reason above. -blurrycat 3/31/25
            for ([_]std.Build.LazyPath{
                libgit_root.path(b, "tests/resources/filemodes/exec_on"),
                libgit_root.path(b, "tests/resources/filemodes/exec_off2on_staged"),
                libgit_root.path(b, "tests/resources/filemodes/exec_off2on_workdir"),
                libgit_root.path(b, "tests/resources/filemodes/exec_on_untracked"),
            }) |lazy| {
                const path = lazy.getPath2(b, null);
                const file = try std.fs.cwd().openFile(path, .{
                    .mode = .read_write,
                });
                defer file.close();
                try file.setPermissions(.{ .inner = .{ .mode = 0o755 } });
            }
        }

        const gen_cmd = b.addSystemCommand(&.{"python3"});
        gen_cmd.addFileArg(libgit_src.path("tests/clar/generate.py"));
        const clar_suite = gen_cmd.addPrefixedOutputDirectoryArg("-o", "clar_suite");
        gen_cmd.addArgs(&.{ "-f", "-xonline", "-xstress", "-xperf" });
        gen_cmd.addDirectoryArg(libgit_src.path("tests/libgit2"));

        const runner = b.addExecutable(.{
            .name = "libgit2_tests",
            .root_module = b.createModule(.{
                .target = target,
                .optimize = .Debug,
                .link_libc = true,
            }),
        });
        runner.addIncludePath(clar_suite);
        runner.addIncludePath(libgit_src.path("tests/clar"));
        runner.addIncludePath(libgit_src.path("tests/libgit2"));

        runner.addConfigHeader(features);
        runner.addIncludePath(libgit_src.path("src/util"));
        runner.addIncludePath(libgit_src.path("src/libgit2"));

        runner.addIncludePath(libgit_src.path("deps/zlib"));
        runner.addIncludePath(libgit_src.path("deps/xdiff"));
        runner.addIncludePath(libgit_src.path("deps/pcre"));
        maybeAddTlsIncludes(runner, tls_dep, tls_backend);

        runner.linkLibrary(lib);

        runner.addCSourceFiles(.{
            .root = libgit_src.path("tests/"),
            .files = &(clar_sources ++ libgit2_test_sources),
            .flags = &.{
                b.fmt(
                    "-DCLAR_FIXTURE_PATH=\"{s}\"",
                    // clar expects the fixture path to only have posix seperators or else some tests will break on windows
                    .{try getNormalizedPath(libgit_src.path("tests/resources"), b, &runner.step)},
                ),
                "-DCLAR_TMPDIR=\"libgit2_tests\"",
                "-DCLAR_WIN32_LONGPATHS",
                "-D_FILE_OFFSET_BITS=64",
                "-DGIT_DEPRECATE_HARD",
            },
        });

        const TestHelper = struct {
            b: *std.Build,
            top_level_step: *std.Build.Step,
            runner: *std.Build.Step.Compile,

            const ClarStep = @import("ClarTestStep.zig");

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

/// Returns the absolute lazy path with posix seperators
fn getNormalizedPath(lp: std.Build.LazyPath, b: *std.Build, asking_step: *std.Build.Step) ![]const u8 {
    const p = lp.getPath3(b, asking_step);
    const result = b.pathResolve(&.{ p.root_dir.path orelse ".", p.sub_path });
    if (builtin.os.tag == .windows) {
        for (result) |*c| {
            if (c.* == '\\') c.* = '/';
        }
    }
    return result;
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
    "clar/clar.c",
    "clar/clar_libgit2.c",
    "clar/clar_libgit2_alloc.c",
    "clar/clar_libgit2_timer.c",
    "clar/clar_libgit2_trace.c",
    "clar/main.c",
};

const libgit2_test_sources = [_][]const u8{
    "libgit2/apply/apply_helpers.c",
    "libgit2/apply/both.c",
    "libgit2/apply/callbacks.c",
    "libgit2/apply/check.c",
    "libgit2/apply/fromdiff.c",
    "libgit2/apply/fromfile.c",
    "libgit2/apply/index.c",
    "libgit2/apply/partial.c",
    "libgit2/apply/tree.c",
    "libgit2/apply/workdir.c",
    "libgit2/attr/file.c",
    "libgit2/attr/flags.c",
    "libgit2/attr/lookup.c",
    "libgit2/attr/macro.c",
    "libgit2/attr/repo.c",
    "libgit2/blame/blame_helpers.c",
    "libgit2/blame/buffer.c",
    "libgit2/blame/getters.c",
    "libgit2/blame/harder.c",
    "libgit2/blame/simple.c",
    "libgit2/checkout/binaryunicode.c",
    "libgit2/checkout/checkout_helpers.c",
    "libgit2/checkout/conflict.c",
    "libgit2/checkout/crlf.c",
    "libgit2/checkout/head.c",
    "libgit2/checkout/icase.c",
    "libgit2/checkout/index.c",
    "libgit2/checkout/nasty.c",
    "libgit2/checkout/tree.c",
    "libgit2/checkout/typechange.c",
    "libgit2/cherrypick/bare.c",
    "libgit2/cherrypick/workdir.c",
    "libgit2/clone/empty.c",
    "libgit2/clone/local.c",
    "libgit2/clone/nonetwork.c",
    "libgit2/clone/transport.c",
    "libgit2/commit/commit.c",
    "libgit2/commit/create.c",
    "libgit2/commit/parent.c",
    "libgit2/commit/parse.c",
    "libgit2/commit/signature.c",
    "libgit2/commit/write.c",
    "libgit2/config/add.c",
    "libgit2/config/backend.c",
    "libgit2/config/conditionals.c",
    "libgit2/config/config_helpers.c",
    "libgit2/config/configlevel.c",
    "libgit2/config/find.c",
    "libgit2/config/global.c",
    "libgit2/config/include.c",
    "libgit2/config/memory.c",
    "libgit2/config/multivar.c",
    "libgit2/config/new.c",
    "libgit2/config/read.c",
    "libgit2/config/readonly.c",
    "libgit2/config/rename.c",
    "libgit2/config/snapshot.c",
    "libgit2/config/stress.c",
    "libgit2/config/validkeyname.c",
    "libgit2/config/write.c",
    "libgit2/core/buf.c",
    "libgit2/core/env.c",
    "libgit2/core/features.c",
    "libgit2/core/hashsig.c",
    "libgit2/core/oid.c",
    "libgit2/core/oidarray.c",
    "libgit2/core/opts.c",
    "libgit2/core/pool.c",
    "libgit2/core/structinit.c",
    "libgit2/core/useragent.c",
    "libgit2/core/version.c",
    "libgit2/date/date.c",
    "libgit2/date/rfc2822.c",
    "libgit2/delta/apply.c",
    "libgit2/describe/describe.c",
    "libgit2/describe/describe_helpers.c",
    "libgit2/describe/t6120.c",
    "libgit2/diff/binary.c",
    "libgit2/diff/blob.c",
    "libgit2/diff/diff_helpers.c",
    "libgit2/diff/diffiter.c",
    "libgit2/diff/drivers.c",
    "libgit2/diff/externalmodifications.c",
    "libgit2/diff/format_email.c",
    "libgit2/diff/header.c",
    "libgit2/diff/index.c",
    "libgit2/diff/notify.c",
    "libgit2/diff/parse.c",
    "libgit2/diff/patch.c",
    "libgit2/diff/patchid.c",
    "libgit2/diff/pathspec.c",
    "libgit2/diff/racediffiter.c",
    "libgit2/diff/rename.c",
    "libgit2/diff/stats.c",
    "libgit2/diff/submodules.c",
    "libgit2/diff/tree.c",
    "libgit2/diff/userdiff.c",
    "libgit2/diff/workdir.c",
    "libgit2/email/create.c",
    "libgit2/fetch/local.c",
    "libgit2/fetchhead/nonetwork.c",
    "libgit2/filter/bare.c",
    "libgit2/filter/blob.c",
    "libgit2/filter/crlf.c",
    "libgit2/filter/custom.c",
    "libgit2/filter/custom_helpers.c",
    "libgit2/filter/file.c",
    "libgit2/filter/ident.c",
    "libgit2/filter/query.c",
    "libgit2/filter/stream.c",
    "libgit2/filter/systemattrs.c",
    "libgit2/filter/wildcard.c",
    "libgit2/grafts/basic.c",
    "libgit2/grafts/parse.c",
    "libgit2/grafts/shallow.c",
    "libgit2/graph/ahead_behind.c",
    "libgit2/graph/commitgraph.c",
    "libgit2/graph/descendant_of.c",
    "libgit2/graph/reachable_from_any.c",
    "libgit2/ignore/path.c",
    "libgit2/ignore/status.c",
    "libgit2/index/add.c",
    "libgit2/index/addall.c",
    "libgit2/index/bypath.c",
    "libgit2/index/cache.c",
    "libgit2/index/collision.c",
    "libgit2/index/conflicts.c",
    "libgit2/index/crlf.c",
    "libgit2/index/filemodes.c",
    "libgit2/index/inmemory.c",
    "libgit2/index/names.c",
    "libgit2/index/nsec.c",
    "libgit2/index/racy.c",
    "libgit2/index/read_index.c",
    "libgit2/index/read_tree.c",
    "libgit2/index/rename.c",
    "libgit2/index/reuc.c",
    "libgit2/index/splitindex.c",
    "libgit2/index/stage.c",
    "libgit2/index/tests.c",
    "libgit2/index/tests256.c",
    "libgit2/index/version.c",
    "libgit2/iterator/index.c",
    "libgit2/iterator/iterator_helpers.c",
    "libgit2/iterator/tree.c",
    "libgit2/iterator/workdir.c",
    "libgit2/mailmap/basic.c",
    "libgit2/mailmap/blame.c",
    "libgit2/mailmap/parsing.c",
    "libgit2/merge/analysis.c",
    "libgit2/merge/annotated_commit.c",
    "libgit2/merge/driver.c",
    "libgit2/merge/files.c",
    "libgit2/merge/merge_helpers.c",
    "libgit2/merge/trees/automerge.c",
    "libgit2/merge/trees/commits.c",
    "libgit2/merge/trees/modeconflict.c",
    "libgit2/merge/trees/recursive.c",
    "libgit2/merge/trees/renames.c",
    "libgit2/merge/trees/treediff.c",
    "libgit2/merge/trees/trivial.c",
    "libgit2/merge/trees/whitespace.c",
    "libgit2/merge/workdir/dirty.c",
    "libgit2/merge/workdir/recursive.c",
    "libgit2/merge/workdir/renames.c",
    "libgit2/merge/workdir/setup.c",
    "libgit2/merge/workdir/simple.c",
    "libgit2/merge/workdir/submodules.c",
    "libgit2/merge/workdir/trivial.c",
    "libgit2/message/trailer.c",
    "libgit2/network/cred.c",
    "libgit2/network/fetchlocal.c",
    "libgit2/network/refspecs.c",
    "libgit2/network/remote/defaultbranch.c",
    "libgit2/network/remote/delete.c",
    "libgit2/network/remote/isvalidname.c",
    "libgit2/network/remote/local.c",
    "libgit2/network/remote/push.c",
    "libgit2/network/remote/remotes.c",
    "libgit2/network/remote/rename.c",
    "libgit2/network/remote/tag.c",
    "libgit2/notes/notes.c",
    "libgit2/notes/notesref.c",
    "libgit2/object/blob/filter.c",
    "libgit2/object/blob/fromstream.c",
    "libgit2/object/blob/write.c",
    "libgit2/object/cache.c",
    "libgit2/object/commit/commitstagedfile.c",
    "libgit2/object/commit/parse.c",
    "libgit2/object/lookup.c",
    "libgit2/object/lookup256.c",
    "libgit2/object/lookupbypath.c",
    "libgit2/object/message.c",
    "libgit2/object/peel.c",
    "libgit2/object/raw/chars.c",
    "libgit2/object/raw/compare.c",
    "libgit2/object/raw/convert.c",
    "libgit2/object/raw/fromstr.c",
    "libgit2/object/raw/hash.c",
    "libgit2/object/raw/short.c",
    "libgit2/object/raw/size.c",
    "libgit2/object/raw/type2string.c",
    "libgit2/object/raw/write.c",
    "libgit2/object/shortid.c",
    "libgit2/object/tag/list.c",
    "libgit2/object/tag/parse.c",
    "libgit2/object/tag/peel.c",
    "libgit2/object/tag/read.c",
    "libgit2/object/tag/write.c",
    "libgit2/object/tree/attributes.c",
    "libgit2/object/tree/duplicateentries.c",
    "libgit2/object/tree/frompath.c",
    "libgit2/object/tree/parse.c",
    "libgit2/object/tree/read.c",
    "libgit2/object/tree/update.c",
    "libgit2/object/tree/walk.c",
    "libgit2/object/tree/write.c",
    "libgit2/object/validate.c",
    "libgit2/odb/alternates.c",
    "libgit2/odb/backend/backend_helpers.c",
    "libgit2/odb/backend/loose.c",
    "libgit2/odb/backend/mempack.c",
    "libgit2/odb/backend/multiple.c",
    "libgit2/odb/backend/nobackend.c",
    "libgit2/odb/backend/nonrefreshing.c",
    "libgit2/odb/backend/refreshing.c",
    "libgit2/odb/backend/simple.c",
    "libgit2/odb/emptyobjects.c",
    "libgit2/odb/foreach.c",
    "libgit2/odb/freshen.c",
    "libgit2/odb/largefiles.c",
    "libgit2/odb/loose.c",
    "libgit2/odb/mixed.c",
    "libgit2/odb/open.c",
    "libgit2/odb/packed.c",
    "libgit2/odb/packed256.c",
    "libgit2/odb/packedone.c",
    "libgit2/odb/packedone256.c",
    "libgit2/odb/sorting.c",
    "libgit2/odb/streamwrite.c",
    "libgit2/online/badssl.c",
    "libgit2/online/clone.c",
    "libgit2/online/customcert.c",
    "libgit2/online/fetch.c",
    "libgit2/online/fetchhead.c",
    "libgit2/online/push.c",
    "libgit2/online/push_util.c",
    "libgit2/online/remotes.c",
    "libgit2/online/shallow.c",
    "libgit2/pack/filelimit.c",
    "libgit2/pack/indexer.c",
    "libgit2/pack/midx.c",
    "libgit2/pack/packbuilder.c",
    "libgit2/pack/sharing.c",
    "libgit2/pack/threadsafety.c",
    "libgit2/patch/parse.c",
    "libgit2/patch/print.c",
    "libgit2/path/validate.c",
    "libgit2/perf/helper__perf__do_merge.c",
    "libgit2/perf/helper__perf__timer.c",
    "libgit2/perf/merge.c",
    "libgit2/precompiled.c",
    "libgit2/rebase/abort.c",
    "libgit2/rebase/inmemory.c",
    "libgit2/rebase/iterator.c",
    "libgit2/rebase/merge.c",
    "libgit2/rebase/setup.c",
    "libgit2/rebase/sign.c",
    "libgit2/rebase/submodule.c",
    "libgit2/refs/basic.c",
    "libgit2/refs/branches/checkedout.c",
    "libgit2/refs/branches/create.c",
    "libgit2/refs/branches/delete.c",
    "libgit2/refs/branches/ishead.c",
    "libgit2/refs/branches/iterator.c",
    "libgit2/refs/branches/lookup.c",
    "libgit2/refs/branches/move.c",
    "libgit2/refs/branches/name.c",
    "libgit2/refs/branches/remote.c",
    "libgit2/refs/branches/upstream.c",
    "libgit2/refs/branches/upstreamname.c",
    "libgit2/refs/crashes.c",
    "libgit2/refs/create.c",
    "libgit2/refs/delete.c",
    "libgit2/refs/dup.c",
    "libgit2/refs/foreachglob.c",
    "libgit2/refs/isvalidname.c",
    "libgit2/refs/iterator.c",
    "libgit2/refs/list.c",
    "libgit2/refs/listall.c",
    "libgit2/refs/lookup.c",
    "libgit2/refs/namespaces.c",
    "libgit2/refs/normalize.c",
    "libgit2/refs/overwrite.c",
    "libgit2/refs/pack.c",
    "libgit2/refs/peel.c",
    "libgit2/refs/races.c",
    "libgit2/refs/read.c",
    "libgit2/refs/ref_helpers.c",
    "libgit2/refs/reflog/drop.c",
    "libgit2/refs/reflog/messages.c",
    "libgit2/refs/reflog/reflog.c",
    "libgit2/refs/reflog/reflog_helpers.c",
    "libgit2/refs/rename.c",
    "libgit2/refs/revparse.c",
    "libgit2/refs/setter.c",
    "libgit2/refs/shorthand.c",
    "libgit2/refs/tags/name.c",
    "libgit2/refs/transactions.c",
    "libgit2/refs/unicode.c",
    "libgit2/refs/update.c",
    "libgit2/remote/create.c",
    "libgit2/remote/fetch.c",
    "libgit2/remote/httpproxy.c",
    "libgit2/remote/insteadof.c",
    "libgit2/remote/list.c",
    "libgit2/repo/config.c",
    "libgit2/repo/discover.c",
    "libgit2/repo/env.c",
    "libgit2/repo/extensions.c",
    "libgit2/repo/getters.c",
    "libgit2/repo/hashfile.c",
    "libgit2/repo/head.c",
    "libgit2/repo/headtree.c",
    "libgit2/repo/init.c",
    "libgit2/repo/message.c",
    "libgit2/repo/new.c",
    "libgit2/repo/objectformat.c",
    "libgit2/repo/open.c",
    "libgit2/repo/pathspec.c",
    "libgit2/repo/repo_helpers.c",
    "libgit2/repo/reservedname.c",
    "libgit2/repo/setters.c",
    "libgit2/repo/shallow.c",
    "libgit2/repo/state.c",
    "libgit2/repo/template.c",
    "libgit2/reset/default.c",
    "libgit2/reset/hard.c",
    "libgit2/reset/mixed.c",
    "libgit2/reset/reset_helpers.c",
    "libgit2/reset/soft.c",
    "libgit2/revert/bare.c",
    "libgit2/revert/rename.c",
    "libgit2/revert/workdir.c",
    "libgit2/revwalk/basic.c",
    "libgit2/revwalk/hidecb.c",
    "libgit2/revwalk/mergebase.c",
    "libgit2/revwalk/signatureparsing.c",
    "libgit2/revwalk/simplify.c",
    "libgit2/stash/apply.c",
    "libgit2/stash/drop.c",
    "libgit2/stash/foreach.c",
    "libgit2/stash/save.c",
    "libgit2/stash/stash_helpers.c",
    "libgit2/stash/submodules.c",
    "libgit2/status/renames.c",
    "libgit2/status/single.c",
    "libgit2/status/status_helpers.c",
    "libgit2/status/submodules.c",
    "libgit2/status/worktree.c",
    "libgit2/status/worktree_init.c",
    "libgit2/stream/deprecated.c",
    "libgit2/stream/registration.c",
    "libgit2/stress/diff.c",
    "libgit2/submodule/add.c",
    "libgit2/submodule/escape.c",
    "libgit2/submodule/init.c",
    "libgit2/submodule/inject_option.c",
    "libgit2/submodule/lookup.c",
    "libgit2/submodule/modify.c",
    "libgit2/submodule/nosubs.c",
    "libgit2/submodule/open.c",
    "libgit2/submodule/repository_init.c",
    "libgit2/submodule/status.c",
    "libgit2/submodule/submodule_helpers.c",
    "libgit2/submodule/update.c",
    "libgit2/threads/atomic.c",
    "libgit2/threads/basic.c",
    "libgit2/threads/diff.c",
    "libgit2/threads/iterator.c",
    "libgit2/threads/refdb.c",
    "libgit2/threads/thread_helpers.c",
    "libgit2/threads/tlsdata.c",
    "libgit2/trace/trace.c",
    "libgit2/trace/windows/stacktrace.c",
    "libgit2/transport/register.c",
    "libgit2/transport/ssh_exec.c",
    "libgit2/transports/smart/packet.c",
    "libgit2/win32/forbidden.c",
    "libgit2/win32/longpath.c",
    "libgit2/win32/systemdir.c",
    "libgit2/worktree/bare.c",
    "libgit2/worktree/config.c",
    "libgit2/worktree/merge.c",
    "libgit2/worktree/open.c",
    "libgit2/worktree/reflog.c",
    "libgit2/worktree/refs.c",
    "libgit2/worktree/repository.c",
    "libgit2/worktree/submodule.c",
    "libgit2/worktree/worktree.c",
    "libgit2/worktree/worktree_helpers.c",
};
