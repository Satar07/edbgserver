# edbgserver

A debugger server implemented using **eBPF**, designed to operate **without `ptrace`** system calls. It currently supports the **ARM64 (AArch64)** architecture and is compatible with both **Android** and **Linux** environments.

## Acknowledgments

Special thanks to [ShinoLeah](https://github.com/ShinoLeah) for the project [eDBG](https://github.com/ShinoLeah/eDBG). The core architecture and concepts of `edbgserver` are heavily inspired by his work.

## Features & Limitations

### Working Features

- **Process & Thread Management:** Basic lifecycle tracking and management.
- **Hardware Breakpoints:** Utilize ARM64 hardware registers for debugging.
- **Memory I/O:** Reading from and writing to process memory.

### Current Limitations (eBPF Constraints)

Due to current eBPF subsystem limitations, the following behaviors are not yet supported:

- **Register Modification:** Modifying CPU register values is currently not possible.
- **Cross-Thread Register Access:** Reading registers from threads other than the one currently triggered (potential for future resolution).
- **Thread Isolation:** Running/stepping a specific single thread independently.
- **APK-mmaped Breakpoints:** Adding `uprobe` breakpoints to `.so` files that are directly `mmap`\-ed from an APK (potential for future resolution).

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
2. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
3. zig: [download from ziglang.org](https://ziglang.org/download/)
4. rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
5. LLVM: (e.g.) `brew install llvm` (on macOS)
6. C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
7. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release
cargo zigbuild --release --target aarch64-unknown-linux-musl
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package edbgserver --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```

The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/edbgserver` can be
copied to a Linux server or VM and run there.

## License

With the exception of eBPF code, edbgserver is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
