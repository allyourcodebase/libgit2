# libgit2
This is [libgit2](https://libgit2.org/) packaged using Zig's build system.

While libgit2 supports many different options for system dependencies, I've opted to use [MbedTLS](https://www.trustedfirmware.org/projects/mbed-tls/) by default on Linux for TLS, crypto, and certificate support. You can replace MbedTLS with OpenSSL if you prefer. SSH support is optional, and is provided by [libssh2](https://libssh2.org/). 
All other dependencies are bundled in the source tree and compiled statically.

## Usage
Update your `build.zig.zon`:
```sh
zig fetch --save git+https://github.com/allyourcodebase/libgit2
# or if you want a tagged release
zig fetch --save https://github.com/allyourcodebase/libgit2/archive/refs/tags/${tag}.tar.gz
```

Then, in your `build.zig`, you can access the library as a dependency:
```zig
const exe = b.addExecutable(.{
    .name = "git2test",
    .root_module = b.createModule(.{
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ // Add git2 as an import
            .name = "git2",
            .module = dep.module("git2"),
        }},
    }),
});
```

Don't forget to import headers too:
```zig
const c = @import("git2");
```
