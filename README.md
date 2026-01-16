# edbgserver

A debugger server implemented using **eBPF**, designed to operate **without `ptrace`** system calls. It currently supports the Arm64 and x86_64 architecture and is compatible with both **Android** and **Linux** environments.

## Acknowledgments

Special thanks to [ShinoLeah](https://github.com/ShinoLeah) for the project [eDBG](https://github.com/ShinoLeah/eDBG). The core architecture and concepts of `edbgserver` are heavily inspired by his work.

## Features & Limitations

### Working Features

- **Process & Thread Management:** Basic lifecycle tracking and management.
- **Hardware Breakpoints:** Utilize ARM64 hardware registers for debugging.
- **Memory I/O:** Reading from and writing to process memory.

### Current Limitations

The following behaviors are not yet supported:

- **Register Modification:** Modifying CPU register values is currently not possible.
- **Cross-Thread Register Access:** Reading registers from threads other than the one currently triggered (potential for future resolution).

## Usage

```sh
./edbgserver -p io.cyril.supervipplayer -t libsupervipplayer.so -b 0x1848

pwndbg
pwndbg> target remote :3333
pwndbg> breakrva 0x18A8 libsupervipplayer.so
```

or maybe:

```sh
./android_lib_pull.sh io.cyril.supervipplayer
pwndbg> set sysroot android_sysroot/
pwndbg> set breakpoint auto-hw on
```

## Prerequisites

1. install rustup: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
2. stable rust toolchains: `rustup toolchain install stable`
3. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
4. rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
5. LLVM:
    - MacOS: `brew install llvm` and add to PATH
    - Linux: `bash -c "$(wget -O - https://apt.llvm.org/llvm.sh)"`
6. musl C toolchain:
    - MacOS: `brew install filosottile/musl-cross/musl-cross` (https://github.com/FiloSottile/homebrew-musl-cross)
    - Linux: `curl -O https://musl.cc/aarch64-linux-musl-cross.tgz` and `curl -O https://musl.cc/x86_64-linux-musl-cross.tgz`
      and add to PATH
7. bpf-linker: `cargo install bpf-linker`

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```sh
cargo c --target aarch64-unknown-linux-musl
cargo run --release --target aarch64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling

[Config file](.cargo/config.toml) as decribe this action like this:

```sh
ARCH=aarch64
CC=${ARCH}-linux-musl-gcc cargo c \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```

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
