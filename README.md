# libgit2
This is [libgit2](https://libgit2.org/) packaged using Zig's build system.

While libgit2 supports many different options for system dependencies, I've opted to use [MbedTLS](https://www.trustedfirmware.org/projects/mbed-tls/) by default on Linux for TLS, crypto, and certificate support. You can replace MbedTLS with OpenSSL if you prefer. SSH support is optional, and is provided by [libssh2](https://libssh2.org/). 
All other dependencies are bundled in the source tree and compiled statically.

## Versioning
See `build.zig.zon` for the current Zig version, see releases for support for previous Zig/libgit2 versions.

The versions specified in `build.zig.zon` are split between the package version (before the plus)
and the libgit2 version (after the plus). For example, version `1.0.0+1.9.0` is package version 1.0.0
with support for libgit2 1.9.0.

## Usage
Update your `build.zig.zon`:
```sh
zig fetch --save git+https://github.com/allyourcodebase/libgit2
# or if you want a tagged release
zig fetch --save git+https://github.com/allyourcodebase/libgit2#${tag}
```

Then, in your `build.zig`, you can access the library as a dependency:
```zig
const libgit2_dep = b.dependency("libgit2", .{
    .target = target,
    .optimize = optimize,
    .@"enable-ssh" = true, // optional ssh support via libssh2
    .@"tls-backend" = .openssl, // use openssl instead of mbedtls
});
your_compile_step.root_module.addImport("git2", libgit_dep.module("git2"));
// or if you only need the artifact:
your_compile_step.linkLibrary(libgit_dep.artifact("git2"));
```
