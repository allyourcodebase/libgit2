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
const libgit2_dep = b.dependency("libgit2", .{
    .target = target,
    .optimize = optimize,
    .@"enable-ssh" = true, // optional ssh support via libssh2
    .@"tls-backend" = .openssl, // use openssl instead of mbedtls
});
your_compile_step.linkLibrary(libgit_dep.artifact("git2"));
```

Don't forget to import headers too:
```zig
const c = @cImport({
    @cInclude("git2.h");
});
```
