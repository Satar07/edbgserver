# edbgserver

[English](README.md) | [中文](README_zh.md)

一个基于 **eBPF** 实现的调试器服务端，旨在脱离 `ptrace` 系统调用以实现最小侵入特征，无视大部分调试限制。目前支持 **Android** 与 **Linux** 下的 Arm64 和 x86_64 架构。

## 致谢

特别感谢学长 [ShinoLeah](https://github.com/ShinoLeah) 的项目 [eDBG](https://github.com/ShinoLeah/eDBG)。本项目的名字还有原理均出于此，如果本项目帮到你的话也请给 [eDBG](https://github.com/ShinoLeah/eDBG) 一个星吧。

## 支持功能

- 硬件软件断点
- 单步步进步过（和gdb实现有关）
- 信号发送
- 读取修改任意地址内存
- 读取寄存器
- 读取修改文件
- 进程库信息获取（符号信息）
- 多线程调试支持（默认多线程当成单线程调试）

## 局限

- 由于ebpf的限制，目前无法修改 CPU 寄存器的值（但是可以用 patch 指令代替操作）
- 无法读取当前触发中断以外的其他线程的寄存器（todo）
- 无法 attach 进程，只能先下文件断点（todo）
- 由于 ebpf 程序运行在内核态，对 namespace 无感知，所以最好不要在 WSL 或者 docker 等隔离环境下运行，否则获取到的线程号信息会不准确，可能影响部分功能。Linux 虚拟机和安卓 adb shell 无影响
- x86_64 单步断点未充分测试，可能会有些 bug

## 使用方法

```sh
edbgserver [OPTIONS] --target <TARGET> --break <BREAK_POINT>

Options:
  -t, --target <TARGET>      Path to the target binary or library
  -p, --package <PACKAGE>    [Android only] The package name of target application
  -b, --break <BREAK_POINT>  The initial breakpoint address (virtual address). The server will set a UProbe at this location to intercept execution and wait for GDB. Supports hexadecimal (e.g., 0x400000) or decimal input
      --port <PORT>          The TCP port where the GDB server will listen for incoming connections [default: 3333]
  -u, --uds [<UDS>]          Use Unix Domain Socket instead of TCP. If the path starts with '@', it is treated as an Abstract Namespace Socket. If no value is provided, it defaults to the abstract socket "@edbg"
  -P, --pid <PID>            The Process ID (PID) of the target process to attach to. If omitted, the server will automatically attach to the first process that triggers the breakpoint in the specified binary
  -m, --multi-thread         Run the server in multi-threaded mode
      --no-filter            Disable filtering of memory maps when attaching to the target process. By default, the server filters out irrelevant memory maps to improve performance
      --use-uprobe           force using uprobe implementation for single-step (perf by default)
  -h, --help                 Print help (see more with '--help')
  -V, --version              Print version
```

- **target**：目标文件路径，需要 uprobe 能够找得到。如果是安卓 app 的 so 就写名字就行
- **package**：指定包名，如果目标是安卓 app 下的 so 文件则需要提供包名（或者不提供直接写好so的绝对路径也行）
- **break**：指定初始断点地址，注意是虚拟地址，ida直接打开来左边显示的那个，不是文件偏移别搞错了。
- **port**：指定端口号，默认3333。安卓记得 adb forward
- **uds**：指定使用 Unix Domain Socket，如果路径以 '@' 开头，则被视为抽象命名空间套接字。如果未提供值，则默认为抽象套接字 "@edbg"。可以稍稍提高性能，安卓记得 forward localabstract
- **pid**：初始断点过滤指定的进程 ID
- **multi-thread**：指定需要传送多线程信息给gdb，如果你只是在一个线程上跟踪程序那就最好不用开（开了也只能感叹，哇，好多线程啊）
- **no-filter**：禁用对 /proc/pid/maps 文件信息过滤，这会导致性能严重下降。如果 vmmap 看不到信息了可以考虑开一下或者提个白名单 issue
- **use-uprobe**：强制使用 uprobe 实现单步调试（默认使用perf和uprobe综合策略）

一些例子：

```sh
./edbgserver -u -p io.cyril.supervipplayer -t libsupervipplayer.so -b 0x1848
adb forward tcp:3333 localabstract:edbg
pwndbg
pwndbg> target remote :3333
pwndbg> breakrva 0x18A8 libsupervipplayer.so
```

在调试安卓的时候因为本机拿不到远程的库文件，所以需要每次都从远端拉下来，这会非常非常慢。这个时候可以用根目录下的 `android_lib_pull.sh` 脚本先把一些常用库还有目标apk下的库给打包一次性拉下来，然后gdb设置查找路径。设置完成后每次调试都能够秒开了

```sh
./android_lib_pull.sh io.cyril.supervipplayer
pwndbg
pwndbg> set sysroot android_sysroot/
pwndbg> set breakpoint auto-hw on
pwndbg> target remote :3333
```

_建议配合 pwndbg 食用_

## 安装

在 release 里面下载对应架构的二进制文件运行即可，本程序基于 musl 静态构建，无需额外安装依赖。

## 构建

编译环境安装：

1. 安装 rustup：`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
2. 安装 Stable Rust 工具链：`rustup toolchain install stable`
3. 安装 Nightly Rust 工具链：`rustup toolchain install nightly --component rust-src`
4. 添加 Rust 目标架构：`rustup target add ${ARCH}-unknown-linux-musl`
5. 安装 LLVM：
    - MacOS：`brew install llvm` 并添加到环境变量 PATH
    - Linux：`bash -c "$(wget -O - https://apt.llvm.org/llvm.sh)"`
6. 安装 musl C 工具链：
    - MacOS：`brew install filosottile/musl-cross/musl-cross`
    - Linux：下载并添加 `aarch64-linux-musl-cross.tgz` 或 `x86_64-linux-musl-cross.tgz` 到 PATH
7. 安装 bpf-linker：`cargo install bpf-linker`

之后 `cargo check`, `cargo build` 应该能够正常使用了

```sh
cargo check --target x86_64-unknown-linux-musl
cargo run --release --target aarch64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
```

项目使用构建脚本自动编译 eBPF 代码并将其链接至程序中，具体原理参考 aya。交叉编译部分可参考 `.cargo/config.toml` 文件

## 开源协议

除 eBPF 代码外，`edbgserver` 遵循 [MIT 协议] 或 [Apache 协议 (2.0版本)] 开源，您可以择其一使用。除非您另有明确说明，否则根据 Apache-2.0 协议定义，您有意提交并包含在本库中的任何贡献都将按照上述方式双重授权，且不附加任何额外条款或条件。

### eBPF

所有 eBPF 代码均遵循 [GNU 通用公共许可协议第 2 版 (GPLv2)] 或 [MIT 协议] 开源，您可以择其一使用。除非您另有明确说明，否则根据 GPL-2 协议定义，您有意提交并包含在本项目中的任何贡献都将按照上述方式双重授权，且不附加任何额外条款或条件。

[Apache 协议 (2.0版本)]: LICENSE-APACHE
[MIT 协议]: LICENSE-MIT
[GNU 通用公共许可协议第 2 版 (GPLv2)]: LICENSE-GPL2
